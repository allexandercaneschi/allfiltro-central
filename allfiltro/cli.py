"""Linha de comando da central (roda como o usuario allfiltro).

    python -m allfiltro.cli ciclo            baixa fontes vencidas e gera versao se algo mudou (timer, 1 min)
    python -m allfiltro.cli publicar         gera versao agora (com as travas)
    python -m allfiltro.cli ativar N         ativa a versao N (liberar travada / voltar versao)
    python -m allfiltro.cli semear           categorias, fonte UT1 e protegidos iniciais
    python -m allfiltro.cli criar-admin LOGIN "Nome"   pede a senha no terminal
    python -m allfiltro.cli gerar-chave      cria o par Ed25519 (se nao existir)
    python -m allfiltro.cli chave-publica    mostra a chave publica (vai no pacote)
    python -m allfiltro.cli status
"""
import argparse
import fcntl
import getpass
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .config import config
from .db import transacao


def _trava():
    cfg = config()
    (cfg.dados / "run").mkdir(parents=True, exist_ok=True)
    f = open(cfg.dados / "run" / "worker.lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return None
    return f


def ciclo(forcar_versao: bool = False, autor: str = "worker") -> int:
    from .fontes import atualizar
    from .models import Fonte, Versao
    from .montagem import estado_geral, gerar_versao

    trava = _trava()
    if trava is None:
        print("outro ciclo em andamento")
        return 0
    cfg = config()
    agora = datetime.now(timezone.utc)
    with transacao() as s:
        for f in s.scalars(select(Fonte).where(Fonte.ativa.is_(True)).order_by(Fonte.id)).all():
            vencida = f.ultimo_download is None or agora - f.ultimo_download > timedelta(hours=f.frequencia_h)
            com_erro = (f.ultimo_status or "").startswith("erro") and (
                f.ultimo_download is None or agora - f.ultimo_download > timedelta(minutes=30))
            if f.baixar_agora or vencida or com_erro:
                f.baixar_agora = False
                mudou, st = atualizar(f)
                print(f"fonte {f.nome}: {st}")
                s.commit()

    flag = cfg.flag_publicar
    pedido = flag.exists()
    autor_flag = flag.read_text().strip() if pedido else ""
    with transacao() as s:
        ultima = s.scalars(select(Versao).order_by(Versao.versao.desc())).first()
        estado = estado_geral(s)
        if forcar_versao or pedido or ultima is None or ultima.estado != estado:
            v = gerar_versao(s, autor=autor_flag or autor)
            print(f"versao {v.versao}: {v.status}" + (f" ({v.erro})" if v.erro else ""))
        else:
            print("nada mudou")
    if pedido:
        flag.unlink(missing_ok=True)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="allfiltro")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ciclo")
    sub.add_parser("publicar")
    a = sub.add_parser("ativar")
    a.add_argument("versao", type=int)
    sub.add_parser("semear")
    c = sub.add_parser("criar-admin")
    c.add_argument("login")
    c.add_argument("nome")
    c.add_argument("--papel", default="admin", choices=["admin", "tecnico"])
    c.add_argument("--temporaria", action="store_true",
                   help="aceita qualquer senha, mas obriga a trocar no primeiro login")
    sub.add_parser("gerar-chave")
    sub.add_parser("chave-publica")
    sub.add_parser("status")
    args = ap.parse_args(argv)

    if args.cmd == "ciclo":
        return ciclo()
    if args.cmd == "publicar":
        return ciclo(forcar_versao=True, autor="linha de comando")
    if args.cmd == "ativar":
        from .montagem import ativar
        with transacao() as s:
            v = ativar(s, args.versao)
            print(f"versao {v.versao} ativa")
        return 0
    if args.cmd == "semear":
        from .semente import semear
        with transacao() as s:
            feito = semear(s)
        print(f"{len(feito)} item(ns) criado(s)" if feito else "nada a criar")
        return 0
    if args.cmd == "criar-admin":
        from .models import Usuario
        from .web.auth import hash_senha, senha_fraca
        senha = getpass.getpass("Senha: ")
        if senha != getpass.getpass("Repita a senha: "):
            print("as senhas nao conferem")
            return 1
        erro = "" if args.temporaria else senha_fraca(senha)
        if erro:
            print(erro + " (ou use --temporaria: troca obrigatoria no primeiro login)")
            return 1
        if not senha:
            print("senha vazia")
            return 1
        with transacao() as s:
            u = s.scalars(select(Usuario).where(Usuario.login == args.login)).first()
            if u:
                u.senha_hash, u.ativo, u.papel, u.falhas, u.bloqueado_ate = hash_senha(senha), True, args.papel, 0, None
                u.trocar_senha = args.temporaria
                print(f"senha de {args.login} trocada" + (" (temporaria)" if args.temporaria else ""))
            else:
                s.add(Usuario(login=args.login, nome=args.nome, senha_hash=hash_senha(senha), papel=args.papel,
                              trocar_senha=args.temporaria))
                print(f"usuario {args.login} criado ({args.papel})"
                      + (": a senha e temporaria, o painel pede a troca no primeiro login" if args.temporaria else ""))
        return 0
    if args.cmd == "gerar-chave":
        from .assinatura import gerar
        cfg = config()
        if cfg.chave_privada.exists():
            print(f"ja existe: {cfg.chave_privada}")
        else:
            gerar(cfg.chave_privada)
            print(f"criada: {cfg.chave_privada} (guarde uma copia no RDM)")
        return 0
    if args.cmd == "chave-publica":
        from .assinatura import publica_pem
        print(publica_pem(), end="")
        return 0
    if args.cmd == "status":
        from .models import Fonte, Versao
        with transacao() as s:
            for v in s.scalars(select(Versao).order_by(Versao.versao.desc()).limit(5)).all():
                print(f"versao {v.versao} {v.status} {v.gerado_em:%d/%m %H:%M} {v.erro}")
            for f in s.scalars(select(Fonte)).all():
                print(f"fonte {f.nome}: {f.ultimo_status} ({f.ultimo_download})")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
