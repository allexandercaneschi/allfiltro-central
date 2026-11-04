"""Montagem das versoes de listas.

Categoria = fontes mapeadas - protegidos - retirados + incluidos a mao.
Tudo em disco e em fluxo: a memoria usada nao depende do tamanho das listas.

Dominios: cada dominio vira "rotulos invertidos separados por espaco"
("ge.globo.com" -> "com globo ge"). Ordenado (LC_ALL=C, o espaco vem antes de
qualquer caractere valido), o pai fica logo antes dos filhos e uma passada
remove os subdominios ja cobertos pelo pai: o pfSense recebe a menor lista que
bloqueia a mesma coisa.

Travas (a versao nao e ativada, fica "travada"):
  - categoria que cresce ou encolhe mais de 30% E mais de 500 itens por
    mudanca de fonte (entradas manuais nao passam por essa trava)
Os protegidos que vierem de fonte saem da lista e viram aviso.
"""
import hashlib
import ipaddress
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from .arquivos import contar_linhas, gz_deterministico, ordenar_unico, sha256
from .config import config
from .fontes import dir_retrato
from .models import Categoria, CategoriaCliente, Entrada, Fonte, Mapeamento, Protegido, Versao
from .normaliza import invertido

TRAVA_PCT = 0.30
TRAVA_ITENS = 500
VERSOES_GUARDADAS = 15
SEP = " "


def _inv(d: str) -> str:
    return SEP.join(reversed(d.split(".")))


def _desinv(l: str) -> str:
    return ".".join(reversed(l.split(SEP)))


def _prefixos_inv(l: str):
    """'com globo ge' -> 'com', 'com globo', 'com globo ge' (pais em forma invertida)."""
    p = l.split(SEP)
    return (SEP.join(p[:i]) for i in range(1, len(p) + 1))


# --------------------------------------------------------------------------
# Entradas de cada categoria (o que define a categoria, sem ler as listas)
# --------------------------------------------------------------------------
def coletar(s):
    """Tudo que a montagem usa, lido do banco de uma vez."""
    cats = s.scalars(select(Categoria).where(Categoria.ativa.is_(True)).order_by(Categoria.chave)).all()
    fontes = {f.id: f for f in s.scalars(select(Fonte)).all()}
    maps = {}
    for m in s.scalars(select(Mapeamento)).all():
        f = fontes.get(m.fonte_id)
        if f and f.ativa:
            maps.setdefault(m.categoria_id, []).append((f.id, m.categoria_origem or "_", f.retrato_sha256))
    ents = {}
    for e in s.scalars(select(Entrada).where(Entrada.ativa.is_(True))).all():
        ents.setdefault(e.categoria_id, []).append((e.operacao, e.tipo, e.valor))
    clientes = {}
    for cc in s.scalars(select(CategoriaCliente)).all():
        clientes.setdefault(cc.categoria_id, []).append(cc.cliente_id)
    prot = s.scalars(select(Protegido)).all()
    prot_dom = sorted({p.valor for p in prot if p.tipo == "dominio"})
    prot_ip = sorted({p.valor for p in prot if p.tipo == "ip"})
    return cats, maps, ents, clientes, prot_dom, prot_ip


def chave_entrada(cat, maps, ents, prot_dom, prot_ip) -> tuple[str, str]:
    """(hash de tudo que define a categoria, hash so da parte das fontes)."""
    fontes = sorted(maps.get(cat.id, []))
    h_fontes = hashlib.sha256(json.dumps([fontes, prot_dom, prot_ip]).encode()).hexdigest()
    manual = sorted(ents.get(cat.id, []))
    h = hashlib.sha256(json.dumps([h_fontes, manual]).encode()).hexdigest()
    return h, h_fontes


def estado_geral(s) -> str:
    cats, maps, ents, clientes, prot_dom, prot_ip = coletar(s)
    partes = []
    for c in cats:
        partes.append([c.chave, c.nome, c.descricao, c.tipo, sorted(clientes.get(c.id, [])),
                       chave_entrada(c, maps, ents, prot_dom, prot_ip)[0]])
    return hashlib.sha256(json.dumps(partes, ensure_ascii=False).encode()).hexdigest()


# --------------------------------------------------------------------------
# Montagem de uma categoria
# --------------------------------------------------------------------------
def _montar_dominios(fontes, incluir, retirar, prot_dom, saida: Path, tmp: Path, avisos: list):
    # protegido "*.x": x e todos os subdominios; "x": so o proprio dominio
    prot_sub = {_inv(p[2:]) for p in prot_dom if p.startswith("*.")}
    prot_exato = {_inv(p) for p in prot_dom if not p.startswith("*.")}
    ret = {_inv(r) for r in retirar}
    bruto = tmp / "dom.bruto"
    barrados = 0
    exemplos = []
    with open(bruto, "w") as out:
        for fid, origem, _ in fontes:
            arq = dir_retrato(fid) / f"{origem}.dom"
            if not arq.exists():
                continue
            with open(arq) as f:
                for l in f:
                    d = l.rstrip("\n")
                    if not d:
                        continue
                    inv = _inv(d)
                    pref = list(_prefixos_inv(inv))
                    if inv in prot_exato or (prot_sub and any(p in prot_sub for p in pref)):
                        barrados += 1
                        if len(exemplos) < 10:
                            exemplos.append(d)
                        continue
                    if ret and any(p in ret for p in pref):
                        continue
                    out.write(inv + "\n")
        for d in incluir:  # manual: nao passa por protegidos nem retirados
            out.write(_inv(d) + "\n")
    if barrados:
        avisos.append({"tipo": "protegido", "itens": barrados, "exemplos": exemplos})
    ordenado = tmp / "dom.ord"
    ordenar_unico(bruto, ordenado, tmp)
    n = 0
    ultimo = None
    with open(ordenado) as fi, open(saida.with_suffix(".rev"), "w") as frev, open(saida, "w") as ftxt:
        for l in fi:
            l = l.rstrip("\n")
            if ultimo is not None and l.startswith(ultimo + SEP):
                continue  # ja coberto pelo dominio pai
            ultimo = l
            frev.write(l + "\n")
            ftxt.write(_desinv(l) + "\n")
            n += 1
    return n


def _montar_ips(fontes, incluir, retirar, prot_ip, saida: Path, avisos: list):
    redes = []
    for fid, origem, _ in fontes:
        arq = dir_retrato(fid) / f"{origem}.ip"
        if arq.exists():
            with open(arq) as f:
                redes.extend(ipaddress.ip_network(l.strip(), strict=False) for l in f if l.strip())
    protegidas = [ipaddress.ip_network(p, strict=False) for p in prot_ip]
    retiradas = [ipaddress.ip_network(r, strict=False) for r in retirar]

    def tirar(lista, tirar_estas, conta=None):
        resultado = []
        for r in lista:
            pedacos = [r]
            for t in tirar_estas:
                if t.version != r.version:
                    continue
                novos = []
                for p in pedacos:
                    if p.subnet_of(t):
                        if conta is not None:
                            conta.append(str(p))
                        continue
                    if t.subnet_of(p):
                        if conta is not None:
                            conta.append(str(t))
                        novos.extend(p.address_exclude(t))
                    else:
                        novos.append(p)
                pedacos = novos
            resultado.extend(pedacos)
        return resultado

    barrados = []
    redes = tirar(redes, protegidas, barrados)
    redes = tirar(redes, retiradas)
    redes += [ipaddress.ip_network(i, strict=False) for i in incluir]
    if barrados:
        avisos.append({"tipo": "ip_protegido", "itens": len(barrados), "exemplos": barrados[:10]})
    v4 = sorted(ipaddress.collapse_addresses(r for r in redes if r.version == 4))
    v6 = sorted(ipaddress.collapse_addresses(r for r in redes if r.version == 6))
    with open(saida, "w") as f:
        for r in v4 + v6:
            f.write((str(r.network_address) if r.num_addresses == 1 else str(r)) + "\n")
    return len(v4) + len(v6)


def _arquivo(pasta: Path, nome: str, txt: Path, itens: int) -> dict:
    gz = pasta / f"{nome}.txt.gz"
    gz_deterministico(txt, gz)
    txt.unlink()
    return {"itens": itens, "sha256": sha256(gz), "bytes": gz.stat().st_size}


def montar_categoria(cat, maps, ents, prot_dom, prot_ip, pasta: Path, tmp: Path, anterior: dict | None,
                     dir_anterior: Path | None):
    """Monta a categoria em pasta. Reaproveita os arquivos da versao anterior
    quando nada que a define mudou."""
    chave, chave_fontes = chave_entrada(cat, maps, ents, prot_dom, prot_ip)
    pasta.mkdir(parents=True)
    if anterior and anterior.get("_entrada") == chave and dir_anterior is not None:
        origem = dir_anterior / "cat" / cat.chave
        arquivos = ["dominios.txt.gz", "ips.txt.gz", "dominios.rev"]
        if all((origem / a).exists() for a in arquivos):
            for a in arquivos:
                os.link(origem / a, pasta / a)
            info = {k: v for k, v in anterior.items()}
            info["_reaproveitada"] = True
            return info
    fontes = sorted(maps.get(cat.id, []))
    entradas = ents.get(cat.id, [])
    inc_d = [v for op, t, v in entradas if op == "incluir" and t == "dominio"]
    ret_d = [v for op, t, v in entradas if op == "retirar" and t == "dominio"]
    inc_i = [v for op, t, v in entradas if op == "incluir" and t == "ip"]
    ret_i = [v for op, t, v in entradas if op == "retirar" and t == "ip"]
    avisos = []
    n_dom = _montar_dominios(fontes, inc_d, ret_d, prot_dom, pasta / "dominios.txt", tmp, avisos)
    n_ip = _montar_ips(fontes, inc_i, ret_i, prot_ip, pasta / "ips.txt", avisos)
    return {
        "nome": cat.nome, "descricao": cat.descricao or "", "tipo": cat.tipo,
        "dominios": _arquivo(pasta, "dominios", pasta / "dominios.txt", n_dom),
        "ips": _arquivo(pasta, "ips", pasta / "ips.txt", n_ip),
        "_entrada": chave, "_fontes": chave_fontes, "_avisos": avisos,
    }


# --------------------------------------------------------------------------
# Versao
# --------------------------------------------------------------------------
def versao_ativa(s):
    return s.scalars(select(Versao).where(Versao.status == "ativa").order_by(Versao.versao.desc())).first()


def dir_versao(n: int) -> Path:
    return config().dir_versoes / str(n)


def _verificar_travas(cats_novas: dict, cats_ativas: dict) -> list:
    travas = []
    for chave, nova in cats_novas.items():
        velha = cats_ativas.get(chave)
        if not velha or nova.get("_fontes") == velha.get("_fontes"):
            continue  # categoria nova ou so entradas manuais mudaram
        for tipo in ("dominios", "ips"):
            a, b = velha[tipo]["itens"], nova[tipo]["itens"]
            if a == 0:
                continue  # primeira carga da categoria
            dif = abs(b - a)
            if dif > TRAVA_ITENS and dif > TRAVA_PCT * max(a, 1):
                travas.append({"categoria": chave, "tipo": tipo, "antes": a, "depois": b})
    return travas


def gerar_versao(s, autor: str = "worker", forcar: bool = False) -> Versao:
    """Monta uma versao nova. Ativa se passar nas travas (ou se forcar)."""
    cfg = config()
    cfg.dir_versoes.mkdir(parents=True, exist_ok=True)
    cfg.dir_tmp.mkdir(parents=True, exist_ok=True)
    cats, maps, ents, clientes, prot_dom, prot_ip = coletar(s)
    estado = estado_geral(s)
    ativa = versao_ativa(s)
    cats_ativas = (ativa.manifesto or {}).get("categorias", {}) if ativa else {}
    dir_ativa = dir_versao(ativa.versao) if ativa else None
    ultimo = s.scalars(select(Versao.versao).order_by(Versao.versao.desc())).first() or 0
    numero = ultimo + 1

    tmp = Path(tempfile.mkdtemp(dir=cfg.dir_tmp))
    destino_tmp = Path(tempfile.mkdtemp(dir=cfg.dir_versoes, prefix=".nova-"))
    try:
        novas = {}
        for c in cats:
            info = montar_categoria(c, maps, ents, prot_dom, prot_ip, destino_tmp / "cat" / c.chave, tmp,
                                    cats_ativas.get(c.chave), dir_ativa)
            info["nome"], info["descricao"], info["tipo"] = c.nome, c.descricao or "", c.tipo
            info["clientes"] = sorted(clientes.get(c.id, []))
            novas[c.chave] = info
        travas = [] if forcar else _verificar_travas(novas, cats_ativas)
        avisos = [dict(a, categoria=k) for k, v in novas.items() for a in v.get("_avisos", [])]
        manifesto = {"versao": numero, "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "categorias": novas}
        (destino_tmp / "manifesto-interno.json").write_text(json.dumps(manifesto, ensure_ascii=False, indent=1))
        destino = dir_versao(numero)
        if destino.exists():
            shutil.rmtree(destino)
        # mkdtemp cria com 700: o Apache (X-Sendfile) precisa ler a pasta da versao
        destino_tmp.chmod(0o755)
        destino_tmp.rename(destino)
    except Exception:
        shutil.rmtree(destino_tmp, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    v = Versao(versao=numero, manifesto=manifesto, estado=estado, avisos=avisos, gerado_por=autor,
               status="travada" if travas else "ativa",
               erro=("; ".join(f"{t['categoria']} ({t['tipo']}): {t['antes']} -> {t['depois']}" for t in travas)
                     if travas else ""))
    if not travas and ativa:
        ativa.status = "anterior"
    s.add(v)
    s.flush()
    limpar_versoes(s)
    return v


def ativar(s, numero: int) -> Versao:
    """Ativa uma versao travada ou anterior (liberacao manual / voltar versao)."""
    v = s.get(Versao, numero)
    if v is None or not dir_versao(numero).exists():
        raise ValueError("versao inexistente ou ja apagada do disco")
    for a in s.scalars(select(Versao).where(Versao.status == "ativa")).all():
        a.status = "anterior"
    v.status = "ativa"
    return v


def limpar_versoes(s):
    """Guarda no disco as ultimas versoes (e a ativa); o resto vira 'descartada'."""
    vs = s.scalars(select(Versao).order_by(Versao.versao.desc())).all()
    for v in vs[VERSOES_GUARDADAS:]:
        if v.status == "ativa":
            continue
        d = dir_versao(v.versao)
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        if v.status != "descartada":
            v.status = "descartada"


# --------------------------------------------------------------------------
# Manifesto publicado (o que o pfSense recebe)
# --------------------------------------------------------------------------
def manifesto_publico(v: Versao, cliente_id: str | None = None) -> dict:
    cats = {}
    for chave, info in (v.manifesto or {}).get("categorias", {}).items():
        if info.get("tipo") == "privada" and (not cliente_id or cliente_id not in info.get("clientes", [])):
            continue
        cats[chave] = {
            "nome": info["nome"], "descricao": info.get("descricao", ""), "tipo": info.get("tipo", "publica"),
            "dominios": dict(info["dominios"], url=f"/api/v1/cat/{chave}/dominios.txt.gz"),
            "ips": dict(info["ips"], url=f"/api/v1/cat/{chave}/ips.txt.gz"),
        }
    return {"formato": 1, "versao": v.versao, "gerado_em": v.manifesto.get("gerado_em"),
            "central": config().url_publica, "cliente": cliente_id, "categorias": cats}


# --------------------------------------------------------------------------
# Busca (tela Dominios e IPs)
# --------------------------------------------------------------------------
def onde_esta_dominio(v: Versao, dominio: str) -> list:
    """Categorias da versao que pegam o dominio (direto ou por um dominio pai)."""
    from .arquivos import contem
    res = []
    inv = _inv(dominio)
    for chave, info in (v.manifesto or {}).get("categorias", {}).items():
        rev = dir_versao(v.versao) / "cat" / chave / "dominios.rev"
        for p in _prefixos_inv(inv):
            if contem(rev, p):
                res.append({"categoria": chave, "nome": info["nome"], "por": _desinv(p)})
                break
    return res


def origens_dominio(s, dominio: str, categoria_id: int | None = None) -> list:
    """De onde o dominio (ou um pai) vem: quais fontes trazem."""
    from .arquivos import contem
    from .normaliza import pais
    res = []
    q = select(Mapeamento, Fonte, Categoria).join(Fonte, Fonte.id == Mapeamento.fonte_id).join(
        Categoria, Categoria.id == Mapeamento.categoria_id)
    if categoria_id:
        q = q.where(Mapeamento.categoria_id == categoria_id)
    for m, f, c in s.execute(q).all():
        arq = dir_retrato(f.id) / f"{m.categoria_origem or '_'}.dom"
        for p in pais(dominio)[:-1]:
            if contem(arq, p):
                res.append({"categoria": c.chave, "fonte": f.nome, "origem": m.categoria_origem, "por": p})
                break
    return res


def onde_esta_ip(v: Versao, valor: str) -> list:
    alvo = ipaddress.ip_network(valor, strict=False)
    res = []
    for chave, info in (v.manifesto or {}).get("categorias", {}).items():
        if not info["ips"]["itens"]:
            continue
        import gzip
        with gzip.open(dir_versao(v.versao) / "cat" / chave / "ips.txt.gz", "rt") as f:
            for l in f:
                r = ipaddress.ip_network(l.strip(), strict=False)
                if r.version == alvo.version and (alvo.subnet_of(r) or r.subnet_of(alvo)):
                    res.append({"categoria": chave, "nome": info["nome"], "por": str(r)})
                    break
    return res
