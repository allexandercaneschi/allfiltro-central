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
from ..models import (Assinatura, Auditoria, Categoria, CategoriaCliente, Cliente, Entrada, Firewall, Fonte,
                      Mapeamento, Protegido, Usuario, Versao, Pacote)
from .. import pacotes as pac
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
def hash_chave(chave: str) -> str:
    return hmac.new(config().segredo.encode(), chave.strip().upper().encode(), hashlib.sha256).hexdigest()


def gerar_chave() -> str:
    """ALLF-XXXXX-XXXXX-XXXXX-XXXXX (sem 0/O/1/I para ditar por telefone sem erro)."""
    import secrets
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    blocos = ["".join(secrets.choice(alfabeto) for _ in range(5)) for _ in range(4)]
    return "ALLF-" + "-".join(blocos)


def _cliente_da_chave(s, request: Request):
    """Assinatura da chave do cliente (Authorization: Bearer ALLF-...); None sem chave."""
    aut = request.headers.get("authorization", "")
    if not aut.lower().startswith("bearer "):
        return None
    h = hash_chave(aut[7:])
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
        if assinatura is not None:
            # firewall novo acima do limite da assinatura fica aguardando aprovacao no painel
            aprovados = s.scalar(select(func.count()).select_from(Firewall).where(
                Firewall.cliente_id == assinatura.cliente_id, Firewall.status == "aprovado")) or 0
            if aprovados >= (assinatura.max_firewalls or 1):
                fw.status = "aguardando"
    fw.hostname = request.headers.get("x-hostname", "")[:160]
    fw.versao_pacote = request.headers.get("x-pacote-versao", "")[:40]
    fw.ultimo_ip = auth.ip_cliente(request)
    fw.visto_em = datetime.now(timezone.utc)
    if versao is not None:
        fw.versao_listas = versao
    if assinatura is not None and fw.cliente_id != assinatura.cliente_id:
        fw.cliente_id = assinatura.cliente_id
    return fw


def _cliente_efetivo(assinatura, fw) -> str | None:
    """Cliente que recebe as categorias privadas nesta consulta."""
    if assinatura is None:
        return None
    if config().licenciamento != "ligado":
        return assinatura.cliente_id
    from datetime import date
    if assinatura.status != "ativa" or (assinatura.validade and assinatura.validade < date.today()):
        return None
    if fw is not None and fw.status != "aprovado":
        return None
    return assinatura.cliente_id


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
        fw = _registrar_firewall(s, request, a, None)
        corpo = _corpo_manifesto(v, _cliente_efetivo(a, fw))
    etag = '"' + hashlib.sha256(corpo).hexdigest() + '"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(corpo, media_type="application/json", headers={
        "ETag": etag, "Cache-Control": "no-cache", "X-Assinatura-Ed25519": assinar_b64(corpo)})


def _redes_estado() -> dict:
    from .. import redes
    e = redes.ler_estado()
    mm = e.get("fontes", {}).get("maxmind", {})
    com_erro = sorted(k for k, x in e.get("fontes", {}).items() if not x.get("ok") and k != "maxmind")
    try:
        pub = datetime.fromisoformat(e["publicado_em"]) if e.get("publicado_em") else None
    except ValueError:
        pub = None
    return {"publicado_em": pub, "listas": e.get("listas", 0), "erro": e.get("erro", ""),
            "maxmind": "ok" if e.get("maxmind_usada") and mm.get("ok", True) else (mm.get("erro") or "sem chave"),
            "com_erro": com_erro}


@app.get("/api/v1/redes")
def api_redes(request: Request):
    """Manifesto das listas de paises e servicos (assinado como o das categorias)."""
    from .. import redes
    m = redes.manifesto_assinado()
    if m is None:
        return JSONResponse({"erro": "sem_listas"}, status_code=503)
    corpo, etag = m
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(corpo, media_type="application/json", headers={
        "ETag": etag, "Cache-Control": "no-cache", "X-Assinatura-Ed25519": assinar_b64(corpo)})


@app.get("/api/v1/redes/{nome}.txt.gz")
def api_redes_lista(nome: str, request: Request):
    from .. import redes
    p = redes.caminho_lista(nome)
    if p is None:
        raise HTTPException(status_code=404)
    p = p.resolve()
    from ..arquivos import sha256 as sha256_arquivo
    return _entregar(p, sha256_arquivo(p), request, "application/gzip")


@app.get("/api/v1/manifest.sig", response_class=PlainTextResponse)
def api_manifest_sig(request: Request):
    """Assinatura (base64) do mesmo corpo que /api/v1/manifest devolve agora."""
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        v = versao_ativa(s)
        if v is None:
            return PlainTextResponse("sem_versao", status_code=503)
        fid = request.headers.get("x-firewall-id", "").strip()[:120]
        fw = s.scalars(select(Firewall).where(Firewall.firewall_id == fid)).first() if fid else None
        corpo = _corpo_manifesto(v, _cliente_efetivo(a, fw))
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
        fw = _registrar_firewall(s, request, a, ver.versao)
        cliente = _cliente_efetivo(a, fw)
        # privada de outro cliente: 404, sem confirmar que existe
        if info is None or (info.get("tipo") == "privada" and cliente not in info.get("clientes", [])):
            raise HTTPException(status_code=404)
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


def _entregar(caminho: Path, sha: str, request: Request, tipo: str, nome: str = ""):
    cab = {"ETag": f'"{sha}"', "X-Sha256": sha, "Cache-Control": "no-cache"}
    if nome:
        cab["Content-Disposition"] = f'attachment; filename="{nome}"'
    if request.headers.get("if-none-match") == f'"{sha}"':
        return Response(status_code=304, headers=cab)
    if config().entrega == "xsendfile":
        cab["X-Sendfile"] = str(caminho)
        return Response(b"", media_type=tipo, headers=cab)
    return FileResponse(caminho, media_type=tipo, headers=cab)


@app.get("/api/v1/pacote")
def api_pacote(request: Request):
    """Ultima versao do pacote para o canal deste firewall (assinada como o manifesto)."""
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        fw = _registrar_firewall(s, request, a, None)
        canal = fw.canal if fw is not None and fw.canal in pac.CANAIS else "estavel"
        p = pac.ultimo(s, canal)
        if p is None:
            return JSONResponse({"erro": "sem_pacote"}, status_code=404)
        corpo = json.dumps(pac.manifesto(p, canal), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return Response(corpo, media_type="application/json", headers={
        "Cache-Control": "no-cache", "X-Assinatura-Ed25519": assinar_b64(corpo)})


@app.get("/api/v1/pacote/{versao}/all-filtros.sh")
def api_pacote_arquivo(versao: str, request: Request):
    with transacao() as s:
        p = s.scalars(select(Pacote).where(Pacote.versao == versao)).first()
        if p is None or p.canal == "retirado":
            raise HTTPException(status_code=404)
        sha = p.sha256
    caminho = pac.caminho(versao)
    if not caminho.exists():
        raise HTTPException(status_code=404)
    return _entregar(caminho, sha, request, "text/x-shellscript", "all-filtros.sh")


@app.get("/instalar/all-filtros.sh")
def instalar_pacote(request: Request):
    """Primeira instalacao: ultima versao estavel (fetch https://.../instalar/all-filtros.sh)."""
    with transacao() as s:
        p = pac.ultimo(s, "estavel")
        if p is None:
            raise HTTPException(status_code=404)
        versao, sha = p.versao, p.sha256
    return _entregar(pac.caminho(versao), sha, request, "text/x-shellscript", "all-filtros.sh")


@app.get("/instalar/all-filtros.sh.sha256", response_class=PlainTextResponse)
def instalar_pacote_sha(request: Request):
    with transacao() as s:
        p = pac.ultimo(s, "estavel")
        if p is None:
            raise HTTPException(status_code=404)
        return f"{p.sha256}  all-filtros.sh\n"


@app.get("/api/v1/licenca")
def api_licenca(request: Request):
    """Situacao da assinatura do cliente, assinada como o manifesto."""
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        if a is None:
            return JSONResponse({"erro": "chave_ausente"}, status_code=401)
        fw = _registrar_firewall(s, request, a, None)
        c = s.get(Cliente, a.cliente_id)
        aprovados = s.scalar(select(func.count()).select_from(Firewall).where(
            Firewall.cliente_id == a.cliente_id, Firewall.status == "aprovado")) or 0
        dados = {
            "cliente": a.cliente_id, "nome": c.nome if c else "", "status": a.status, "plano": a.plano,
            "validade": a.validade.isoformat() if a.validade else None, "max_firewalls": a.max_firewalls,
            "firewalls_aprovados": aprovados, "firewall": {"id": fw.firewall_id, "status": fw.status} if fw else None,
            "licenciamento": config().licenciamento, "valida": _cliente_efetivo(a, fw) is not None,
            "emitida_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    corpo = json.dumps(dados, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return Response(corpo, media_type="application/json", headers={
        "Cache-Control": "no-store", "X-Assinatura-Ed25519": assinar_b64(corpo)})


@app.post("/api/v1/classificar")
async def api_classificar(request: Request):
    """Categoria dos sites acessados. Corpo: {"dominios": {"dominio": acessos, ...}} (ate 2000).
    Resposta: {"versao": N, "categorias": {"dominio": ["Nome", ...]}} (lista vazia = sem categoria)."""
    from ..classificar import MAX_POR_PEDIDO, classificar, registrar_sem_categoria, versao_com_indice
    try:
        corpo = await request.json()
        pedidos = corpo.get("dominios") or {}
        if isinstance(pedidos, list):
            pedidos = {d: 1 for d in pedidos}
        if not isinstance(pedidos, dict):
            raise ValueError
    except Exception:
        return JSONResponse({"erro": "corpo_invalido"}, status_code=400)
    if len(pedidos) > MAX_POR_PEDIDO:
        return JSONResponse({"erro": "muitos_dominios", "maximo": MAX_POR_PEDIDO}, status_code=413)
    doms, original = {}, {}  # normalizado -> acessos; normalizado -> como o firewall mandou
    for d, n in pedidos.items():
        try:
            nd = norm_dominio(str(d))
        except ValorInvalido:
            continue
        doms[nd] = doms.get(nd, 0) + (int(n) if str(n).isdigit() else 1)
        original.setdefault(nd, []).append(str(d))
    with transacao() as s:
        a = _cliente_da_chave(s, request)
        if a is None:
            return JSONResponse({"erro": "chave_ausente"}, status_code=401)
        fw = _registrar_firewall(s, request, a, None)
        cliente = _cliente_efetivo(a, fw)
        v = versao_com_indice(s)
        if v is None:
            return JSONResponse({"erro": "indice_em_preparo"}, status_code=503)
        res = classificar(v.versao, v.manifesto or {}, list(doms), cliente)
        registrar_sem_categoria(s, {d: doms[d] for d, c in res.items() if not c}, a.cliente_id)
    saida = {o: c for d, c in res.items() for o in original[d]}
    return JSONResponse({"versao": v.versao, "categorias": saida}, headers={"Cache-Control": "no-store"})


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
                       avisos=(v.avisos if v else []), pendente=pendente, redes_estado=_redes_estado())


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
# Sites sem categoria (acessos dos clientes que nenhuma categoria pega)
# ==========================================================================
@app.get("/admin/sem-categoria", response_class=HTMLResponse)
def sem_categoria_tela(request: Request, dias: int = 30, ver: str = ""):
    from ..classificar import classificar, versao_com_indice
    from ..models import SemCategoria
    dias = dias if dias in (1, 7, 30, 90) else 30
    with transacao() as s:
        u, ses = _exigir(s, request)
        desde = datetime.now(timezone.utc) - timedelta(days=dias)
        q = select(SemCategoria).where(SemCategoria.ultimo_em >= desde)
        q = q.where(SemCategoria.ignorado.is_(ver == "ignorados"))
        linhas = s.scalars(q.order_by(SemCategoria.acessos.desc()).limit(400)).all()
        # o que ja foi classificado (entrou numa categoria) sai da lista
        v = versao_com_indice(s)
        ja = {}
        if v is not None and linhas:
            ja = {d: c for d, c in classificar(v.versao, v.manifesto or {}, [l.dominio for l in linhas], None).items() if c}
        nomes = {c.cliente_id: c.nome for c in s.scalars(select(Cliente)).all()}
        itens = [{"dominio": l.dominio, "acessos": l.acessos, "clientes": [nomes.get(c, c) for c in (l.clientes or [])],
                  "ultimo_em": l.ultimo_em, "ignorado": l.ignorado} for l in linhas if l.dominio not in ja][:300]
        cats = s.scalars(select(Categoria).where(Categoria.ativa.is_(True)).order_by(Categoria.nome)).all()
        total = s.scalar(select(func.count()).select_from(SemCategoria).where(
            SemCategoria.ultimo_em >= desde, SemCategoria.ignorado.is_(False))) or 0
        return _pagina(request, "admin/sem_categoria.html", u, ses, sites=itens, cats=cats, dias=dias, ver=ver,
                       total=total, versao=v.versao if v else None)


@app.post("/admin/sem-categoria")
async def sem_categoria_acao(request: Request):
    from ..models import SemCategoria
    form = await request.form()
    csrf, acao, categoria = form.get("csrf", ""), form.get("acao", ""), form.get("categoria", "")
    doms = [str(d) for d in form.getlist("d")][:500]
    voltar = "/admin/sem-categoria" + (f"?dias={form.get('dias')}" if str(form.get("dias", "")).isdigit() else "")
    if not doms:
        return _ir(voltar, erro="Marque ao menos um site.")
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        if acao in ("ignorar", "voltar"):
            for d in doms:
                l = s.get(SemCategoria, d)
                if l is not None:
                    l.ignorado = acao == "ignorar"
            auth.auditar(s, request, u.login, f"sem_categoria_{acao}", "sem_categoria", "",
                         depois={"itens": doms[:200]})
            return _ir(voltar, msg=f"{len(doms)} site(s) " + ("ignorado(s)." if acao == "ignorar" else "de volta na lista."))
        cat = s.scalars(select(Categoria).where(Categoria.chave == categoria)).first()
        if cat is None:
            return _ir(voltar, erro="Escolha a categoria.")
        existentes = {e.valor: e for e in s.scalars(select(Entrada).where(
            Entrada.categoria_id == cat.id, Entrada.tipo == "dominio", Entrada.ativa.is_(True))).all()}
        criados = 0
        for d in doms:
            try:
                val = norm_dominio(d)
            except ValorInvalido:
                continue
            e = existentes.get(val)
            if e is not None and e.operacao == "incluir":
                continue
            if e is not None:
                e.ativa = False
            s.add(Entrada(categoria_id=cat.id, valor=val, tipo="dominio", operacao="incluir",
                          comentario="classificado em Sites sem categoria", autor=u.login))
            criados += 1
        auth.auditar(s, request, u.login, "entrada_incluir", "entradas", cat.chave,
                     depois={"itens": doms[:200], "total": len(doms), "comentario": "classificado em Sites sem categoria"})
    return _ir(voltar, msg=f"{criados} site(s) em {cat.nome}. Vale na próxima versão (alguns minutos); "
                           "os firewalls reclassificam em até 12 horas.")


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
        clientes = s.scalars(select(Cliente).order_by(Cliente.nome)).all()
        marcados = set(s.scalars(select(CategoriaCliente.cliente_id).where(CategoriaCliente.categoria_id == c.id)))
        return _pagina(request, "admin/categoria.html", u, ses, c=c, ents=ents, maps=maps, info=info,
                       versao=v, clientes=clientes, marcados=marcados)


@app.post("/admin/categorias")
async def salvar_categoria(request: Request, csrf: str = Form(""), chave: str = Form(...), nome: str = Form(...),
                           descricao: str = Form(""), ativa: str = Form(""), nova: str = Form(""),
                           tipo: str = Form("publica")):
    import re
    form = await request.form()
    clientes_sel = [str(x) for x in form.getlist("clientes")]
    tipo = "privada" if tipo == "privada" else "publica"
    chave = chave.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,78}$", chave):
        return _ir("/admin/categorias", erro="Chave inválida: use letras minúsculas, números e hífen.")
    with transacao() as s:
        u, ses = _exigir(s, request)
        auth.conferir_csrf(ses, csrf)
        c = s.scalars(select(Categoria).where(Categoria.chave == chave)).first()
        if nova:
            if c is not None:
                return _ir("/admin/categorias", erro="Já existe uma categoria com essa chave.")
            c = Categoria(chave=chave, nome=nome.strip()[:120], descricao=descricao.strip(), tipo=tipo,
                          ativa=True)
            s.add(c)
            s.flush()
            auth.auditar(s, request, u.login, "categoria_criada", "categorias", chave,
                         depois={"nome": c.nome, "tipo": tipo})
            destino = f"/admin/categorias/{chave}"
            msg = ("Categoria privada criada: marque abaixo os clientes que a recebem." if tipo == "privada"
                   else "Categoria criada. Vale na próxima versão.")
            return _ir(destino, msg=msg)
        else:
            if c is None:
                raise HTTPException(status_code=404)
            antes_cli = sorted(s.scalars(select(CategoriaCliente.cliente_id).where(
                CategoriaCliente.categoria_id == c.id)))
            antes = {"nome": c.nome, "descricao": c.descricao, "ativa": c.ativa, "tipo": c.tipo, "clientes": antes_cli}
            c.nome, c.descricao, c.ativa, c.tipo = nome.strip()[:120], descricao.strip(), bool(ativa), tipo
            validos = set(s.scalars(select(Cliente.cliente_id)))
            novos = sorted(set(clientes_sel) & validos) if tipo == "privada" else []
            for cc in s.scalars(select(CategoriaCliente).where(CategoriaCliente.categoria_id == c.id)).all():
                if cc.cliente_id not in novos:
                    s.delete(cc)
            for cid in set(novos) - set(antes_cli):
                s.add(CategoriaCliente(categoria_id=c.id, cliente_id=cid))
            auth.auditar(s, request, u.login, "categoria_editada", "categorias", chave, antes=antes,
                         depois={"nome": c.nome, "descricao": c.descricao, "ativa": c.ativa, "tipo": tipo,
                                 "clientes": novos})
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


# ==========================================================================
# Sistema: clientes, chaves (assinaturas) e firewalls
# ==========================================================================
def _dados_cliente(s, cid):
    c = s.get(Cliente, cid)
    if c is None:
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
    assinaturas = s.scalars(select(Assinatura).where(Assinatura.cliente_id == cid)
                            .order_by(Assinatura.criado_em.desc())).all()
    firewalls = s.scalars(select(Firewall).where(Firewall.cliente_id == cid).order_by(Firewall.hostname)).all()
    privadas = s.scalars(select(Categoria).join(CategoriaCliente, CategoriaCliente.categoria_id == Categoria.id)
                         .where(CategoriaCliente.cliente_id == cid).order_by(Categoria.nome)).all()
    return c, assinaturas, firewalls, privadas


@app.get("/admin/sistema/clientes", response_class=HTMLResponse)
def clientes(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        cs = s.scalars(select(Cliente).order_by(Cliente.nome)).all()
        fws = s.scalars(select(Firewall).order_by(Firewall.visto_em.desc().nulls_last())).all()
        por_cliente = {}
        for fw in fws:
            por_cliente.setdefault(fw.cliente_id, []).append(fw)
        chaves = dict(s.execute(select(Assinatura.cliente_id, func.count()).where(Assinatura.status == "ativa")
                                .group_by(Assinatura.cliente_id)).all())
        return _pagina(request, "admin/clientes.html", u, ses, clientes=cs, por_cliente=por_cliente, chaves=chaves,
                       sem_cliente=por_cliente.get(None, []), agora=datetime.now(timezone.utc))


@app.post("/admin/sistema/clientes")
def salvar_cliente(request: Request, csrf: str = Form(""), cliente_id: str = Form(...), nome: str = Form(...),
                   ativo: str = Form(""), novo: str = Form("")):
    import re
    cid = cliente_id.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9_-]{1,59}$", cid):
        return _ir("/admin/sistema/clientes", erro="Id inválido: minúsculas, números, hífen ou _ (o mesmo id do painel de navegação).")
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        c = s.get(Cliente, cid)
        if novo:
            if c is not None:
                return _ir("/admin/sistema/clientes", erro="Já existe um cliente com esse id.")
            s.add(Cliente(cliente_id=cid, nome=nome.strip()[:160], ativo=True))
            auth.auditar(s, request, u.login, "cliente_criado", "clientes", cid, depois={"nome": nome.strip()})
        else:
            if c is None:
                raise HTTPException(status_code=404)
            antes = {"nome": c.nome, "ativo": c.ativo}
            c.nome, c.ativo = nome.strip()[:160], bool(ativo)
            auth.auditar(s, request, u.login, "cliente_editado", "clientes", cid, antes=antes,
                         depois={"nome": c.nome, "ativo": c.ativo})
    return _ir(f"/admin/sistema/clientes/{cid}", msg="Cliente salvo.")


@app.get("/admin/sistema/clientes/{cid}", response_class=HTMLResponse)
def cliente(cid: str, request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        c, assinaturas, firewalls, privadas = _dados_cliente(s, cid)
        return _pagina(request, "admin/cliente.html", u, ses, c=c, assinaturas=assinaturas, firewalls=firewalls,
                       privadas=privadas, chave_nova="", licenciamento=config().licenciamento)


@app.post("/admin/sistema/clientes/{cid}/chave", response_class=HTMLResponse)
def nova_chave(cid: str, request: Request, csrf: str = Form(""), plano: str = Form("padrao"),
               validade: str = Form(""), max_firewalls: int = Form(1), substituir: str = Form("")):
    """Gera a chave e mostra UMA vez (a central guarda so o hash)."""
    from datetime import date
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        c, _, _, _ = _dados_cliente(s, cid)
        val = None
        if validade.strip():
            try:
                val = date.fromisoformat(validade.strip())
            except ValueError:
                return _ir(f"/admin/sistema/clientes/{cid}", erro="Validade inválida.")
        if substituir:
            for a in s.scalars(select(Assinatura).where(Assinatura.cliente_id == cid,
                                                        Assinatura.status == "ativa")).all():
                a.status = "cancelada"
        chave = gerar_chave()
        a = Assinatura(cliente_id=cid, chave_hash=hash_chave(chave), chave_final=chave[-4:],
                       plano=(plano.strip() or "padrao")[:40], inicio=date.today(), validade=val,
                       status="ativa", max_firewalls=max(1, min(max_firewalls, 50)), criado_por=u.login)
        s.add(a)
        auth.auditar(s, request, u.login, "chave_gerada", "assinaturas", cid,
                     depois={"final": chave[-4:], "plano": a.plano, "validade": validade, "max_firewalls":
                             a.max_firewalls, "substituiu": bool(substituir)})
        s.flush()
        c, assinaturas, firewalls, privadas = _dados_cliente(s, cid)
        return _pagina(request, "admin/cliente.html", u, ses, c=c, assinaturas=assinaturas, firewalls=firewalls,
                       privadas=privadas, chave_nova=chave, licenciamento=config().licenciamento)


@app.post("/admin/sistema/assinaturas/{aid}")
def status_assinatura(aid: int, request: Request, csrf: str = Form(""), status: str = Form(...),
                      max_firewalls: int = Form(0), validade: str = Form("-")):
    from datetime import date
    if status not in ("ativa", "suspensa", "cancelada"):
        raise HTTPException(status_code=400)
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        a = s.get(Assinatura, aid)
        if a is None:
            raise HTTPException(status_code=404)
        if a.status == "cancelada" and status != "cancelada":
            return _ir(f"/admin/sistema/clientes/{a.cliente_id}", erro="Chave cancelada não volta: gere uma nova.")
        antes = {"status": a.status, "max_firewalls": a.max_firewalls, "validade": str(a.validade or "")}
        a.status = status
        if max_firewalls:
            a.max_firewalls = max(1, min(max_firewalls, 50))
        if validade != "-":
            try:
                a.validade = date.fromisoformat(validade) if validade.strip() else None
            except ValueError:
                return _ir(f"/admin/sistema/clientes/{a.cliente_id}", erro="Validade inválida.")
        auth.auditar(s, request, u.login, "assinatura_alterada", "assinaturas", aid, antes=antes,
                     depois={"status": a.status, "max_firewalls": a.max_firewalls, "validade": str(a.validade or "")})
        cid = a.cliente_id
    return _ir(f"/admin/sistema/clientes/{cid}", msg="Assinatura atualizada.")


@app.get("/admin/sistema/paises", response_class=HTMLResponse)
def paises_tela(request: Request):
    from .. import redes
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        e = redes.ler_estado()
        conta, chave = redes.maxmind_credenciais()
        m = redes.manifesto_assinado()
        listas = json.loads(m[0]).get("listas", {}) if m else {}
        grupos = {"pais": 0, "continente": 0, "servico": [], "satelite": 0}
        for k, v in listas.items():
            t = k.split("-", 1)[0]
            if t == "servico":
                grupos["servico"].append(v)
            else:
                grupos[t] = grupos.get(t, 0) + 1
        fontes = []
        for k, x in sorted(e.get("fontes", {}).items()):
            ok_em = None
            try:
                ok_em = datetime.fromisoformat(x["ok_em"]) if x.get("ok_em") else None
            except ValueError:
                pass
            fontes.append({"nome": k, "ok": x.get("ok", False), "erro": x.get("erro", ""), "ok_em": ok_em})
        return _pagina(request, "admin/paises.html", u, ses, estado=_redes_estado(), fontes=fontes, grupos=grupos,
                       br=listas.get("pais-br"), conta=conta, tem_chave=bool(chave), pedido=redes.atualizacao_pedida())


@app.post("/admin/sistema/paises/maxmind")
def paises_maxmind(request: Request, csrf: str = Form(""), conta: str = Form(""), chave: str = Form(""),
                   acao: str = Form("salvar")):
    from .. import redes
    conta = conta.strip()
    chave = chave.strip()
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        atual_conta, atual_chave = redes.maxmind_credenciais()
        if acao == "apagar":
            redes.salvar_credenciais("", "")
            auth.auditar(s, request, u.login, "maxmind_apagada", "redes", "maxmind")
            return _ir("/admin/sistema/paises", msg="Chave da MaxMind apagada. As listas passam a usar só os registros oficiais.")
        chave = chave or atual_chave  # campo vazio = manter a chave salva
        if not conta.isdigit() or not (8 <= len(chave) <= 80) or not all(c.isalnum() or c == "_" for c in chave):
            return _ir("/admin/sistema/paises", erro="Informe o ID da conta (só números) e a chave de licença da MaxMind.")
        erro = redes.testar_maxmind(conta, chave)
        if acao == "testar":
            return _ir("/admin/sistema/paises", **({"erro": f"Teste: {erro}."} if erro else {"msg": "Teste: a MaxMind aceitou a conta e a chave (nada foi salvo)."}))
        if erro:
            return _ir("/admin/sistema/paises", erro=f"Não salvei: {erro}.")
        redes.salvar_credenciais(conta, chave)
        redes.pedir_atualizacao()
        auth.auditar(s, request, u.login, "maxmind_salva", "redes", "maxmind", depois={"conta": conta})
    return _ir("/admin/sistema/paises", msg="Conta da MaxMind salva e testada. As listas são refeitas com ela no próximo minuto.")


@app.post("/admin/sistema/paises/atualizar")
def paises_atualizar(request: Request, csrf: str = Form("")):
    from .. import redes
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        redes.pedir_atualizacao()
        auth.auditar(s, request, u.login, "redes_atualizar", "redes", "todas")
    return _ir("/admin/sistema/paises", msg="Pedido registrado: as listas de países e serviços são baixadas e refeitas no próximo minuto.")


@app.get("/admin/sistema/pacote", response_class=HTMLResponse)
def pacote_tela(request: Request):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        ps = sorted(s.scalars(select(Pacote)).all(), key=lambda p: pac.chave_versao(p.versao), reverse=True)
        fws = s.scalars(select(Firewall).order_by(Firewall.hostname)).all()
        por_versao = {}
        for fw in fws:
            por_versao[fw.versao_pacote or "?"] = por_versao.get(fw.versao_pacote or "?", 0) + 1
        return _pagina(request, "admin/pacote.html", u, ses, pacotes=ps, firewalls=fws, por_versao=por_versao,
                       ultimo_teste=pac.ultimo(s, "teste"), ultimo_estavel=pac.ultimo(s, "estavel"),
                       url_publica=config().url_publica)


@app.post("/admin/sistema/pacote")
async def pacote_enviar(request: Request, csrf: str = Form(""), notas: str = Form(""),
                        arquivo: UploadFile = File(...)):
    conteudo = await arquivo.read(pac.TAMANHO_MAX + 1)
    try:
        versao = pac.validar(conteudo)
    except pac.PacoteInvalido as e:
        return _ir("/admin/sistema/pacote", erro=f"Arquivo recusado: {e}.")
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        if s.scalars(select(Pacote).where(Pacote.versao == versao)).first() is not None:
            return _ir("/admin/sistema/pacote", erro=f"A versão {versao} já foi enviada. Gere uma versão nova (build.py) para publicar outra correção.")
        sha = pac.gravar(conteudo, versao)
        s.add(Pacote(versao=versao, sha256=sha, tamanho=len(conteudo), canal="teste", notas=notas.strip()[:2000],
                     enviado_por=u.login))
        auth.auditar(s, request, u.login, "pacote_enviado", "pacotes", versao, depois={"sha256": sha, "canal": "teste"})
    return _ir("/admin/sistema/pacote", msg=f"Versão {versao} publicada no canal teste. Os firewalls do canal teste instalam na próxima madrugada (ou em Verificar agora, no firewall).")


@app.post("/admin/sistema/pacote/{pid}")
def pacote_acao(pid: int, request: Request, csrf: str = Form(""), acao: str = Form(...)):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        p = s.get(Pacote, pid)
        if p is None:
            raise HTTPException(status_code=404)
        antes = p.canal
        if acao == "promover":
            p.canal, p.promovido_em = "estavel", datetime.now(timezone.utc)
        elif acao in ("teste", "retirado"):
            p.canal = acao
        else:
            raise HTTPException(status_code=400)
        auth.auditar(s, request, u.login, "pacote_canal", "pacotes", p.versao, antes={"canal": antes}, depois={"canal": p.canal})
        versao, canal = p.versao, p.canal
    nomes = {"estavel": "estável (todos os firewalls)", "teste": "teste", "retirado": "retirada (ninguém mais instala)"}
    return _ir("/admin/sistema/pacote", msg=f"Versão {versao}: {nomes[canal]}.")


@app.post("/admin/sistema/firewalls/{fid}")
def acao_firewall(fid: int, request: Request, csrf: str = Form(""), acao: str = Form(...),
                  cliente_id: str = Form(""), canal: str = Form(""), volta: str = Form("")):
    with transacao() as s:
        u, ses = _exigir(s, request, sistema=True)
        auth.conferir_csrf(ses, csrf)
        fw = s.get(Firewall, fid)
        if fw is None:
            raise HTTPException(status_code=404)
        antes = {"cliente": fw.cliente_id, "status": fw.status}
        voltar = f"/admin/sistema/clientes/{fw.cliente_id}" if fw.cliente_id else "/admin/sistema/clientes"
        if acao == "aprovar":
            fw.status = "aprovado"
        elif acao == "aguardar":
            fw.status = "aguardando"
        elif acao == "vincular":
            if s.get(Cliente, cliente_id) is None:
                return _ir(voltar, erro="Cliente inválido.")
            fw.cliente_id = cliente_id
            voltar = f"/admin/sistema/clientes/{cliente_id}"
        elif acao == "canal":
            if volta == "/admin/sistema/pacote":
                voltar = volta
            if canal not in pac.CANAIS:
                return _ir(voltar, erro="Canal inválido.")
            fw.canal = canal
        elif acao == "remover":
            s.delete(fw)
        else:
            raise HTTPException(status_code=400)
        auth.auditar(s, request, u.login, f"firewall_{acao}", "firewalls", fw.firewall_id, antes=antes,
                     depois={"cliente": cliente_id or fw.cliente_id, "status": fw.status})
    return _ir(voltar, msg="Firewall atualizado.")
