"""App web da central: landing (/), painel (/admin) e API dos pfSense (/api/v1)."""
import hashlib
import hmac
import json
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from .. import VERSAO
from ..assinatura import assinar_b64, publica_pem
from ..config import config
from ..db import transacao
from ..models import (Assinatura, Auditoria, Categoria, Entrada, Firewall, Fonte, Mapeamento, Protegido, Usuario,
                      Versao)
from ..montagem import dir_versao, manifesto_publico, onde_esta_dominio, onde_esta_ip, origens_dominio, versao_ativa
from ..normaliza import ValorInvalido, dominio as norm_dominio, ip as norm_ip, valor as norm_valor
from . import auth

AQUI = Path(__file__).parent
app = FastAPI(title="Central de Listas ALL Filtros", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=AQUI / "static"), name="static")
tpl = Jinja2Templates(directory=AQUI / "templates")
tpl.env.globals["versao_app"] = VERSAO
tpl.env.filters["num"] = lambda n: f"{int(n or 0):,}".replace(",", ".")
tpl.env.filters["data"] = lambda d: d.astimezone().strftime("%d/%m/%Y %H:%M") if d else "—"


@app.middleware("http")
async def cabecalhos(request: Request, call_next):
    r = await call_next(request)
    r.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.url.path.startswith("/admin") or request.url.path == "/":
        r.headers.setdefault("X-Frame-Options", "DENY")
        r.headers.setdefault("Referrer-Policy", "same-origin")
        r.headers.setdefault("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             "form-action 'self'; frame-ancestors 'none'")
        r.headers.setdefault("Cache-Control", "no-store")
    return r


# ==========================================================================
# Publico
# ==========================================================================
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return tpl.TemplateResponse(request, "landing.html", {})


@app.api_route("/saude", methods=["GET", "HEAD", "OPTIONS"], response_class=PlainTextResponse)
def saude():
    """Checagem de saude (o HAProxy do pfSense usa OPTIONS por padrao)."""
    with transacao() as s:
        v = versao_ativa(s)
    return f"ok versao={v.versao if v else 'nenhuma'}"


# ==========================================================================
# API dos pfSense
# ==========================================================================
def _cliente_da_chave(s, request: Request):
    """Chave do cliente (Authorization: Bearer ALLF-...). Opcional por enquanto."""
    aut = request.headers.get("authorization", "")
    if not aut.lower().startswith("bearer "):
        return None
    chave = aut[7:].strip().upper()
    h = hmac.new(config().segredo.encode(), chave.encode(), hashlib.sha256).hexdigest()
    a = s.scalars(select(Assinatura).where(Assinatura.chave_hash == h)).first()
    if a is None:
        raise HTTPException(status_code=401, detail="chave_invalida")
    return a


def _registrar_firewall(s, request: Request, assinatura, versao: int | None):
    fid = request.headers.get("x-firewall-id", "").strip()[:120]
    if not fid:
        return
    fw = s.scalars(select(Firewall).where(Firewall.firewall_id == fid)).first()
    if fw is None:
        fw = Firewall(firewall_id=fid, status="aprovado")
        s.add(fw)
    fw.hostname = request.headers.get("x-hostname", "")[:160]
    fw.versao_pacote = request.headers.get("x-pacote-versao", "")[:40]
    fw.ultimo_ip = auth.ip_cliente(request)
    fw.visto_em = datetime.now(timezone.utc)
    if versao is not None:
        fw.versao_listas = versao
    if assinatura is not None and not fw.cliente_id:
        fw.cliente_id = assinatura.cliente_id


def _corpo_manifesto(v, cliente_id):
    return json.dumps(manifesto_publico(v, cliente_id), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


@app.get("/api/v1/manifest")
def api_manifest(request: Request):
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        v = versao_ativa(s)
        if v is None:
            return JSONResponse({"erro": "sem_versao"}, status_code=503)
        _registrar_firewall(s, request, a, None)
        corpo = _corpo_manifesto(v, a.cliente_id if a and a.status == "ativa" else None)
    etag = '"' + hashlib.sha256(corpo).hexdigest() + '"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(corpo, media_type="application/json", headers={
        "ETag": etag, "Cache-Control": "no-cache", "X-Assinatura-Ed25519": assinar_b64(corpo)})


@app.get("/api/v1/manifest.sig", response_class=PlainTextResponse)
def api_manifest_sig(request: Request):
    """Assinatura (base64) do mesmo corpo que /api/v1/manifest devolve agora."""
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        v = versao_ativa(s)
        if v is None:
            return PlainTextResponse("sem_versao", status_code=503)
        corpo = _corpo_manifesto(v, a.cliente_id if a and a.status == "ativa" else None)
    return assinar_b64(corpo) + "\n"


@app.get("/api/v1/chave-publica", response_class=PlainTextResponse)
def api_chave_publica():
    return publica_pem()


@app.get("/api/v1/cat/{chave}/{arquivo}")
def api_arquivo(chave: str, arquivo: str, request: Request, v: int | None = None):
    if arquivo not in ("dominios.txt.gz", "ips.txt.gz"):
        raise HTTPException(status_code=404)
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        ver = s.get(Versao, v) if v else versao_ativa(s)
        if ver is None or ver.status == "descartada":
            raise HTTPException(status_code=404)
        info = (ver.manifesto or {}).get("categorias", {}).get(chave)
        cliente = a.cliente_id if a and a.status == "ativa" else None
        # privada de outro cliente: 404, sem confirmar que existe
        if info is None or (info.get("tipo") == "privada" and cliente not in info.get("clientes", [])):
            raise HTTPException(status_code=404)
        _registrar_firewall(s, request, a, ver.versao)
        tipo = "dominios" if arquivo.startswith("dominios") else "ips"
        sha = info[tipo]["sha256"]
        numero = ver.versao
    caminho = dir_versao(numero) / "cat" / chave / arquivo
    if not caminho.exists():
        raise HTTPException(status_code=404)
    cab = {"ETag": f'"{sha}"', "X-Sha256": sha, "Cache-Control": "no-cache"}
    if request.headers.get("if-none-match") == f'"{sha}"':
        return Response(status_code=304, headers=cab)
    if config().entrega == "xsendfile":
        # o Apache (mod_xsendfile) entrega o arquivo, com Range e sem ocupar a app
        cab["X-Sendfile"] = str(caminho)
        return Response(b"", media_type="application/gzip", headers=cab)
    return FileResponse(caminho, media_type="application/gzip", headers=cab)


@app.get("/api/v1/licenca")
def api_licenca():
    return JSONResponse({"erro": "licenciamento_ainda_nao_disponivel"}, status_code=404)


# ==========================================================================
# Painel: apoio
# ==========================================================================
class Redirecionar(Exception):
    def __init__(self, url):
        self.url = url


@app.exception_handler(Redirecionar)
def _redir(request, exc):
    return RedirectResponse(exc.url, status_code=303)


def _ir(url: str, msg: str = "", erro: str = ""):
    sep = "&" if "?" in url else "?"
    if msg:
        url += f"{sep}msg={quote(msg)}"
    elif erro:
        url += f"{sep}erro={quote(erro)}"
    return RedirectResponse(url, status_code=303)


def _exigir(s, request: Request, sistema: bool = False):
    u, ses = auth.sessao_atual(s, request)
    if u is None:
        raise Redirecionar("/admin/login")
    if u.trocar_senha and request.url.path != "/admin/senha":
        raise Redirecionar("/admin/senha")
    if sistema:
        if u.papel != "admin":
            raise HTTPException(status_code=403, detail="Só administradores.")
        if not auth.rede_sistema(request):
            raise HTTPException(status_code=403, detail="Área de sistema: só pela rede do escritório ou VPN.")
    return u, ses


def _pagina(request, nome, u, ses, **ctx):
    ctx.update(usuario=u, csrf=ses.csrf if ses else "", msg=request.query_params.get("msg", ""),
               erro=request.query_params.get("erro", ""), caminho=request.url.path,
               pode_sistema=bool(u and u.papel == "admin" and auth.rede_sistema(request)))
    return tpl.TemplateResponse(request, nome, ctx)


def _alerta_ip_novo(u, ip):
    url = getattr(config(), "alerta_webhook", "")
    if not url:
        return

    def enviar():
        try:
            dados = json.dumps({"evento": "login_ip_novo", "login": u.login, "nome": u.nome, "ip": ip,
                                "quando": datetime.now(timezone.utc).isoformat()}).encode()
            urllib.request.urlopen(urllib.request.Request(url, data=dados, headers={
                "Content-Type": "application/json"}), timeout=10)
        except Exception:
            pass
    threading.Thread(target=enviar, daemon=True).start()


@app.exception_handler(HTTPException)
def _http(request: Request, exc: HTTPException):
    if request.url.path.startswith("/admin"):
        return tpl.TemplateResponse(request, "erro.html", {"status": exc.status_code, "detalhe": exc.detail},
                                    status_code=exc.status_code)
    return JSONResponse({"erro": exc.detail}, status_code=exc.status_code)


# ==========================================================================
# Login
# ==========================================================================
@app.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request):
    return tpl.TemplateResponse(request, "login.html", {"erro": request.query_params.get("erro", "")})


@app.post("/admin/login")
def login(request: Request, login: str = Form(...), senha: str = Form(...)):
    with transacao() as s:
        u, erro = auth.autenticar(s, request, login.strip(), senha)
        if u is None:
            s.commit()
            return tpl.TemplateResponse(request, "login.html", {"erro": erro}, status_code=401)
        token, ip_novo = auth.criar_sessao(s, request, u)
        auth.limpar_sessoes(s)
    if ip_novo:
        _alerta_ip_novo(u, auth.ip_cliente(request))
    r = RedirectResponse("/admin", status_code=303)
    # Secure quando o acesso e por HTTPS (HAProxy); pela rede interna em http o cookie ainda funciona
    r.set_cookie(auth.COOKIE, token, httponly=True, secure=config().cookie_seguro and auth.eh_https(request),
                 samesite="strict",
                 path="/admin")
    return r


@app.post("/admin/sair")
def sair(request: Request):
    with transacao() as s:
        u, ses = auth.sessao_atual(s, request)
        if u:
            auth.auditar(s, request, u.login, "logout")
        auth.encerrar(s, request)
    r = RedirectResponse("/admin/login", status_code=303)
    r.delete_cookie(auth.COOKIE, path="/admin")
    return r


@app.get("/admin/senha", response_class=HTMLResponse)
def senha_form(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request)
        return _pagina(request, "admin/senha.html", u, ses)


@app.post("/admin/senha")
def trocar_senha(request: Request, csrf: str = Form(""), atual: str = Form(""), nova: str = Form(""),
                 repetir: str = Form("")):
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        try:
            PasswordHasher().verify(u.senha_hash, atual)
        except (VerificationError, InvalidHashError):
            return _ir("/admin/senha", erro="A senha atual não confere.")
        if nova != repetir:
            return _ir("/admin/senha", erro="As senhas novas não conferem.")
        if nova == atual:
            return _ir("/admin/senha", erro="A senha nova precisa ser diferente da atual.")
        erro = auth.senha_fraca(nova)
        if erro:
            return _ir("/admin/senha", erro=erro[0].upper() + erro[1:] + ".")
        u.senha_hash, u.trocar_senha = auth.hash_senha(nova), False
        auth.auditar(s, request, u.login, "senha_trocada", "usuarios", u.id)
    return _ir("/admin", msg="Senha trocada.")


# ==========================================================================
# Inicio
# ==========================================================================
@app.get("/admin", response_class=HTMLResponse)
def inicio(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request)
        v = versao_ativa(s)
        travadas = s.scalars(select(Versao).where(Versao.status == "travada").order_by(Versao.versao.desc())
                             .limit(5)).all()
        fontes_erro = s.scalars(select(Fonte).where(Fonte.ativa.is_(True), Fonte.ultimo_status.like("erro%"))).all()
        fontes = s.scalars(select(Fonte).order_by(Fonte.nome)).all()
        limite = datetime.now(timezone.utc) - timedelta(hours=48)
        sumidos = s.scalars(select(Firewall).where(Firewall.visto_em < limite).order_by(Firewall.visto_em)).all()
        firewalls = s.scalar(select(func.count()).select_from(Firewall)) or 0
        ultima = s.scalars(select(Versao).order_by(Versao.versao.desc())).first()
        cats = []
        if v:
            for chave, info in sorted(v.manifesto.get("categorias", {}).items(), key=lambda x: x[1]["nome"]):
                cats.append({"chave": chave, "nome": info["nome"], "tipo": info.get("tipo"),
                             "dominios": info["dominios"]["itens"], "ips": info["ips"]["itens"]})
        pendente = config().flag_publicar.exists()
        return _pagina(request, "admin/inicio.html", u, ses, versao=v, travadas=travadas, fontes_erro=fontes_erro,
                       fontes=fontes, sumidos=sumidos, firewalls=firewalls, cats=cats, ultima=ultima,
                       avisos=(v.avisos if v else []), pendente=pendente)


@app.post("/admin/publicar")
def publicar(request: Request, csrf: str = Form("")):
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        f = config().flag_publicar
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(u.login)
        auth.auditar(s, request, u.login, "publicar_agora")
    return _ir("/admin", msg="Publicação pedida. A versão nova sai em até 1 minuto (com as mesmas travas).")


# ==========================================================================
# Dominios e IPs
# ==========================================================================
@app.get("/admin/buscar", response_class=HTMLResponse)
def buscar(request: Request, q: str = ""):
    with transacao() as s:
        u, ses = _exigir(s, request)
        cats = s.scalars(select(Categoria).where(Categoria.ativa.is_(True)).order_by(Categoria.nome)).all()
        res = None
        q = q.strip()
        if q:
            try:
                tipo, val = norm_valor(q)
            except ValorInvalido as e:
                return _pagina(request, "admin/buscar.html", u, ses, q=q, cats=cats, res=None, erro_busca=str(e))
            v = versao_ativa(s)
            ids = {c.id: c for c in s.scalars(select(Categoria)).all()}
            entradas = s.scalars(select(Entrada).where(Entrada.valor == val).order_by(Entrada.criado_em.desc())).all()
            if tipo == "dominio":
                pais_val = [p for p in _pais(val)]
                ent_pais = s.scalars(select(Entrada).where(Entrada.valor.in_(pais_val), Entrada.valor != val,
                                                           Entrada.ativa.is_(True))).all()
            else:
                ent_pais = []
            res = {
                "tipo": tipo, "valor": val,
                "categorias": (onde_esta_dominio(v, val) if tipo == "dominio" else onde_esta_ip(v, val)) if v else [],
                "fontes": origens_dominio(s, val) if tipo == "dominio" else [],
                "entradas": [(e, ids.get(e.categoria_id)) for e in entradas],
                "entradas_pais": [(e, ids.get(e.categoria_id)) for e in ent_pais],
                "versao": v.versao if v else None,
            }
        return _pagina(request, "admin/buscar.html", u, ses, q=q, cats=cats, res=res, erro_busca="")


def _pais(d):
    p = d.split(".")
    return [".".join(p[i:]) for i in range(len(p) - 1)]


@app.post("/admin/entradas")
async def nova_entrada(request: Request, csrf: str = Form(""), categoria: str = Form(...),
                       operacao: str = Form(...), valores: str = Form(""), comentario: str = Form(""),
                       voltar: str = Form("/admin/buscar"), arquivo: UploadFile | None = File(None)):
    if operacao not in ("incluir", "retirar"):
        raise HTTPException(status_code=400)
    texto = valores
    if arquivo is not None and arquivo.filename:
        dados = await arquivo.read(10 * 1024 * 1024 + 1)
        if len(dados) > 10 * 1024 * 1024:
            return _ir(voltar, erro="Arquivo maior que 10 MB.")
        texto += "\n" + dados.decode("utf-8", "replace")
    linhas = [l.strip() for l in texto.replace(",", "\n").splitlines()]
    linhas = [l for l in linhas if l and not l.startswith("#")]
    if not linhas:
        return _ir(voltar, erro="Informe ao menos um domínio ou IP.")
    if len(linhas) > 100000:
        return _ir(voltar, erro="Máximo de 100 mil itens por importação.")
    if not voltar.startswith("/admin"):
        voltar = "/admin/buscar"
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        cat = s.scalars(select(Categoria).where(Categoria.chave == categoria)).first()
        if cat is None:
            return _ir(voltar, erro="Categoria não encontrada.")
        validos, invalidos, avisos = [], [], []
        vistos = set()
        for l in linhas:
            try:
                tipo, val = norm_valor(l)
            except ValorInvalido as e:
                invalidos.append(f"{l} ({e})")
                continue
            if (tipo, val) in vistos:
                continue
            vistos.add((tipo, val))
            validos.append((tipo, val))
        existentes = {(e.tipo, e.valor): e for e in s.scalars(select(Entrada).where(
            Entrada.categoria_id == cat.id, Entrada.ativa.is_(True))).all()}
        criados = 0
        for tipo, val in validos:
            e = existentes.get((tipo, val))
            if e is not None and e.operacao == operacao:
                continue  # ja esta assim
            if e is not None:
                e.ativa = False  # incluir desfaz retirar e vice-versa
            s.add(Entrada(categoria_id=cat.id, valor=val, tipo=tipo, operacao=operacao,
                          comentario=comentario.strip()[:500], autor=u.login))
            criados += 1
            if operacao == "retirar" and tipo == "dominio":
                for p in _pais(val)[1:]:
                    if (("dominio", p) in existentes and existentes[("dominio", p)].operacao == "incluir"):
                        avisos.append(f"{val}: o domínio pai {p} continua incluído, então retirar não tem efeito")
                        break
        auth.auditar(s, request, u.login, f"entrada_{operacao}", "entradas", cat.chave,
                     depois={"itens": [v for _, v in validos][:200], "total": len(validos),
                             "comentario": comentario.strip()[:500]})
    partes = [f"{criados} item(ns) para {operacao} em {cat.nome}. Entra na próxima versão (até 1 minuto)."]
    if invalidos:
        partes.append(f"{len(invalidos)} inválido(s): " + "; ".join(invalidos[:5]))
    if avisos:
        partes.append(" ".join(avisos[:3]))
    destino = voltar
    return _ir(destino, msg=" ".join(partes))


@app.post("/admin/entradas/{eid}/desfazer")
def desfazer_entrada(eid: int, request: Request, csrf: str = Form(""), voltar: str = Form("/admin/buscar")):
    if not voltar.startswith("/admin"):
        voltar = "/admin/buscar"
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        e = s.get(Entrada, eid)
        if e is None:
            raise HTTPException(status_code=404)
        e.ativa = False
        auth.auditar(s, request, u.login, "entrada_desfeita", "entradas", e.id,
                     antes={"valor": e.valor, "operacao": e.operacao, "categoria_id": e.categoria_id})
    return _ir(voltar, msg="Entrada desfeita. Vale na próxima versão.")


# ==========================================================================
# Categorias
# ==========================================================================
@app.get("/admin/categorias", response_class=HTMLResponse)
def categorias(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request)
        cats = s.scalars(select(Categoria).order_by(Categoria.nome)).all()
        v = versao_ativa(s)
        totais = (v.manifesto.get("categorias", {}) if v else {})
        manuais = dict(s.execute(select(Entrada.categoria_id, func.count()).where(Entrada.ativa.is_(True))
                                 .group_by(Entrada.categoria_id)).all())
        fontes_por_cat = {}
        for m, f in s.execute(select(Mapeamento, Fonte).join(Fonte, Fonte.id == Mapeamento.fonte_id)).all():
            fontes_por_cat.setdefault(m.categoria_id, []).append(f.nome + (f" ({m.categoria_origem})"
                                                                           if m.categoria_origem else ""))
        return _pagina(request, "admin/categorias.html", u, ses, cats=cats, totais=totais, manuais=manuais,
                       fontes_por_cat=fontes_por_cat)


@app.get("/admin/categorias/{chave}", response_class=HTMLResponse)
def categoria(chave: str, request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request)
        c = s.scalars(select(Categoria).where(Categoria.chave == chave)).first()
        if c is None:
            raise HTTPException(status_code=404, detail="Categoria não encontrada.")
        ents = s.scalars(select(Entrada).where(Entrada.categoria_id == c.id).order_by(Entrada.criado_em.desc())
                         .limit(500)).all()
        maps = s.execute(select(Mapeamento, Fonte).join(Fonte, Fonte.id == Mapeamento.fonte_id)
                         .where(Mapeamento.categoria_id == c.id)).all()
        v = versao_ativa(s)
        info = (v.manifesto.get("categorias", {}).get(chave) if v else None)
        return _pagina(request, "admin/categoria.html", u, ses, c=c, ents=ents, maps=maps, info=info,
                       versao=v)


@app.post("/admin/categorias")
def salvar_categoria(request: Request, csrf: str = Form(""), chave: str = Form(...), nome: str = Form(...),
                     descricao: str = Form(""), ativa: str = Form(""), nova: str = Form("")):
    import re
    chave = chave.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,78}$", chave):
        return _ir("/admin/categorias", erro="Chave inválida: use letras minúsculas, números e hífen.")
    if chave.startswith("cli-") and nova:
        return _ir("/admin/categorias", erro="Chaves cli-… são das categorias privadas de clientes (fase 2).")
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        c = s.scalars(select(Categoria).where(Categoria.chave == chave)).first()
        if nova:
            if c is not None:
                return _ir("/admin/categorias", erro="Já existe uma categoria com essa chave.")
            c = Categoria(chave=chave, nome=nome.strip()[:120], descricao=descricao.strip(), tipo="publica",
                          ativa=True)
            s.add(c)
            auth.auditar(s, request, u.login, "categoria_criada", "categorias", chave, depois={"nome": c.nome})
            destino = f"/admin/categorias/{chave}"
        else:
            if c is None:
                raise HTTPException(status_code=404)
            antes = {"nome": c.nome, "descricao": c.descricao, "ativa": c.ativa}
            c.nome, c.descricao, c.ativa = nome.strip()[:120], descricao.strip(), bool(ativa)
            auth.auditar(s, request, u.login, "categoria_editada", "categorias", chave, antes=antes,
                         depois={"nome": c.nome, "descricao": c.descricao, "ativa": c.ativa})
            destino = f"/admin/categorias/{chave}"
    return _ir(destino, msg="Categoria salva. Vale na próxima versão.")


# ==========================================================================
# Sistema: fontes, versoes, protegidos, usuarios, auditoria
# ==========================================================================
@app.get("/admin/sistema/fontes", response_class=HTMLResponse)
def fontes(request: Request):
    from ..fontes import indice
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        fs = s.scalars(select(Fonte).order_by(Fonte.nome)).all()
        cats = s.scalars(select(Categoria).order_by(Categoria.nome)).all()
        maps = {}
        for m in s.scalars(select(Mapeamento)).all():
            maps.setdefault(m.fonte_id, []).append(m)
        catnome = {c.id: c for c in cats}
        idx = {f.id: indice(f.id) for f in fs}
        return _pagina(request, "admin/fontes.html", u, ses, fontes=fs, cats=cats, maps=maps, catnome=catnome,
                       idx=idx)


@app.post("/admin/sistema/fontes")
def salvar_fonte(request: Request, csrf: str = Form(""), fid: int = Form(0), nome: str = Form(...),
                 url: str = Form(...), formato: str = Form(...), frequencia_h: int = Form(24),
                 ativa: str = Form("")):
    if formato not in ("dominios", "hosts", "adblock", "pacote", "ips"):
        return _ir("/admin/sistema/fontes", erro="Formato inválido.")
    if not url.startswith(("https://", "http://")):
        return _ir("/admin/sistema/fontes", erro="Use uma URL http(s).")
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        f = s.get(Fonte, fid) if fid else None
        if f is None:
            f = Fonte(ultimo_status="", ultimo_sha256="", retrato_sha256="", baixar_agora=True)
            s.add(f)
        f.nome, f.url, f.formato = nome.strip()[:120], url.strip(), formato
        f.frequencia_h, f.ativa = max(1, min(frequencia_h, 168)), bool(ativa)
        s.flush()
        auth.auditar(s, request, u.login, "fonte_salva", "fontes", f.id,
                     depois={"nome": f.nome, "url": f.url, "formato": f.formato, "ativa": f.ativa})
    return _ir("/admin/sistema/fontes", msg="Fonte salva. O download começa em até 1 minuto.")


@app.post("/admin/sistema/fontes/{fid}/baixar")
def baixar_fonte(fid: int, request: Request, csrf: str = Form("")):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        f = s.get(Fonte, fid)
        if f is None:
            raise HTTPException(status_code=404)
        f.baixar_agora = True
        auth.auditar(s, request, u.login, "fonte_baixar_agora", "fontes", f.id)
    return _ir("/admin/sistema/fontes", msg="Download pedido (até 1 minuto).")


@app.post("/admin/sistema/mapeamentos")
def mapear(request: Request, csrf: str = Form(""), fonte_id: int = Form(...), origem: str = Form(""),
           categoria: str = Form(""), remover: int = Form(0)):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        if remover:
            m = s.get(Mapeamento, remover)
            if m:
                auth.auditar(s, request, u.login, "mapeamento_removido", "mapeamentos", m.id,
                             antes={"fonte": m.fonte_id, "origem": m.categoria_origem, "categoria": m.categoria_id})
                s.delete(m)
            return _ir("/admin/sistema/fontes", msg="Mapeamento removido.")
        c = s.scalars(select(Categoria).where(Categoria.chave == categoria)).first()
        if c is None or s.get(Fonte, fonte_id) is None:
            return _ir("/admin/sistema/fontes", erro="Fonte ou categoria inválida.")
        origem = origem.strip()
        existe = s.scalars(select(Mapeamento).where(Mapeamento.fonte_id == fonte_id,
                                                    Mapeamento.categoria_origem == origem,
                                                    Mapeamento.categoria_id == c.id)).first()
        if not existe:
            s.add(Mapeamento(fonte_id=fonte_id, categoria_origem=origem, categoria_id=c.id))
            auth.auditar(s, request, u.login, "mapeamento_criado", "mapeamentos", "",
                         depois={"fonte": fonte_id, "origem": origem, "categoria": c.chave})
    return _ir("/admin/sistema/fontes", msg="Mapeamento salvo. Vale na próxima versão.")


@app.get("/admin/sistema/versoes", response_class=HTMLResponse)
def versoes(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        vs = s.scalars(select(Versao).order_by(Versao.versao.desc()).limit(30)).all()
        return _pagina(request, "admin/versoes.html", u, ses, versoes=vs)


@app.post("/admin/sistema/versoes/{n}/ativar")
def ativar_versao(n: int, request: Request, csrf: str = Form("")):
    from ..montagem import ativar
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        try:
            ativar(s, n)
        except ValueError as e:
            return _ir("/admin/sistema/versoes", erro=str(e))
        auth.auditar(s, request, u.login, "versao_ativada", "versoes", n)
    return _ir("/admin/sistema/versoes", msg=f"Versão {n} ativa. Os firewalls recebem em até 5 minutos.")


@app.get("/admin/sistema/protegidos", response_class=HTMLResponse)
def protegidos(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        ps = s.scalars(select(Protegido).order_by(Protegido.tipo, Protegido.valor)).all()
        return _pagina(request, "admin/protegidos.html", u, ses, protegidos=ps)


@app.post("/admin/sistema/protegidos")
def salvar_protegido(request: Request, csrf: str = Form(""), valor: str = Form(""), motivo: str = Form(""),
                     remover: int = Form(0)):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        if remover:
            p = s.get(Protegido, remover)
            if p:
                auth.auditar(s, request, u.login, "protegido_removido", "protegidos", p.valor)
                s.delete(p)
            return _ir("/admin/sistema/protegidos", msg="Removido. Vale na próxima versão.")
        v = valor.strip().lower()
        try:
            if v.startswith("*."):
                tipo, v = "dominio", "*." + norm_dominio(v[2:])
            else:
                tipo, v = norm_valor(v)
                if tipo == "ip":
                    v = norm_ip(v)
        except ValorInvalido as e:
            return _ir("/admin/sistema/protegidos", erro=str(e))
        if s.scalars(select(Protegido).where(Protegido.valor == v)).first() is None:
            s.add(Protegido(valor=v, tipo=tipo, motivo=motivo.strip()[:300]))
            auth.auditar(s, request, u.login, "protegido_criado", "protegidos", v)
    return _ir("/admin/sistema/protegidos", msg="Protegido salvo. Vale na próxima versão.")


@app.get("/admin/sistema/usuarios", response_class=HTMLResponse)
def usuarios(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        us = s.scalars(select(Usuario).order_by(Usuario.nome)).all()
        return _pagina(request, "admin/usuarios.html", u, ses, usuarios=us)


@app.post("/admin/sistema/usuarios")
def salvar_usuario(request: Request, csrf: str = Form(""), uid: int = Form(0), login: str = Form(""),
                   nome: str = Form(""), papel: str = Form("tecnico"), senha: str = Form(""),
                   ativo: str = Form("")):
    if papel not in ("tecnico", "admin"):
        papel = "tecnico"
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        alvo = s.get(Usuario, uid) if uid else None
        if senha:
            erro = auth.senha_fraca(senha)
            if erro:
                return _ir("/admin/sistema/usuarios", erro=erro)
        if alvo is None:
            login = login.strip().lower()
            if not login or not senha:
                return _ir("/admin/sistema/usuarios", erro="Informe login e senha.")
            if s.scalars(select(Usuario).where(Usuario.login == login)).first():
                return _ir("/admin/sistema/usuarios", erro="Login já existe.")
            alvo = Usuario(login=login, nome=nome.strip() or login, papel=papel,
                           senha_hash=auth.hash_senha(senha))
            s.add(alvo)
            auth.auditar(s, request, u.login, "usuario_criado", "usuarios", login, depois={"papel": papel})
        else:
            if alvo.id == u.id and (not ativo or papel != "admin"):
                return _ir("/admin/sistema/usuarios", erro="Você não pode desativar nem rebaixar o próprio usuário.")
            alvo.nome, alvo.papel, alvo.ativo = nome.strip() or alvo.nome, papel, bool(ativo)
            if senha:
                alvo.senha_hash, alvo.falhas, alvo.bloqueado_ate = auth.hash_senha(senha), 0, None
            auth.auditar(s, request, u.login, "usuario_editado", "usuarios", alvo.login,
                         depois={"papel": papel, "ativo": alvo.ativo, "senha_trocada": bool(senha)})
    return _ir("/admin/sistema/usuarios", msg="Usuário salvo.")


@app.get("/admin/sistema/auditoria", response_class=HTMLResponse)
def auditoria(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        regs = s.scalars(select(Auditoria).order_by(Auditoria.id.desc()).limit(300)).all()
        return _pagina(request, "admin/auditoria.html", u, ses, regs=regs)
