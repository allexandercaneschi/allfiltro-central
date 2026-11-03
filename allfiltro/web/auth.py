"""Login, sessoes e protecoes do painel.

- Senha com Argon2; bloqueio de 15 min apos 5 tentativas erradas (alem do
  limite por IP no HAProxy).
- Sessao no banco (so o hash do token), expira apos N min sem uso; cookie sem
  validade (some ao fechar o navegador), Secure, HttpOnly, SameSite=Strict.
- CSRF: token por sessao em todo formulario POST.
- IP real do cliente: X-Forwarded-For so e aceito vindo dos proxies confiaveis.
"""
import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request
from sqlalchemy import delete, select

from ..config import config
from ..models import Auditoria, Sessao, Usuario

COOKIE = "allf_sessao"
MAX_FALHAS = 5
BLOQUEIO = timedelta(minutes=15)
_ph = PasswordHasher()
# hash qualquer para gastar o mesmo tempo quando o login nao existe
_HASH_FALSO = _ph.hash(secrets.token_hex(16))


def hash_senha(senha: str) -> str:
    return _ph.hash(senha)


def senha_fraca(senha: str) -> str:
    if len(senha) < 12:
        return "a senha precisa de pelo menos 12 caracteres"
    if senha.lower() == senha or senha.upper() == senha or not any(c.isdigit() for c in senha):
        return "use letras maiusculas, minusculas e numeros"
    return ""


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def ip_cliente(request: Request) -> str:
    """Anda o X-Forwarded-For da direita para a esquerda pulando os proxies confiaveis."""
    cfg = config()
    direto = request.client.host if request.client else ""

    def confiavel(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in r for r in cfg.proxies_confiaveis)

    if not confiavel(direto):
        return direto
    cadeia = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    for ip in reversed(cadeia):
        if not confiavel(ip):
            return ip
    return cadeia[0] if cadeia else direto


def eh_https(request: Request) -> bool:
    """HTTPS direto, ou HTTPS no HAProxy (X-Forwarded-Proto vindo de proxy confiavel)."""
    if request.url.scheme == "https":
        return True
    cfg = config()
    try:
        direto = ipaddress.ip_address(request.client.host if request.client else "")
    except ValueError:
        return False
    if not any(direto in r for r in cfg.proxies_confiaveis):
        return False
    return request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower() == "https"


def auditar(s, request: Request | None, usuario: str, acao: str, tabela: str = "", registro: str = "",
            antes=None, depois=None):
    s.add(Auditoria(usuario=usuario, ip=ip_cliente(request) if request else "", acao=acao, tabela=tabela,
                    registro=str(registro), antes=antes, depois=depois))


def autenticar(s, request: Request, login: str, senha: str):
    """Devolve (usuario, erro)."""
    agora = datetime.now(timezone.utc)
    u = s.scalars(select(Usuario).where(Usuario.login == login)).first()
    if u is None or not u.ativo:
        try:
            _ph.verify(_HASH_FALSO, senha)
        except (VerificationError, InvalidHashError):
            pass
        auditar(s, request, login, "login_falhou", "usuarios", login)
        return None, "Usuário ou senha inválidos."
    if u.bloqueado_ate and u.bloqueado_ate > agora:
        auditar(s, request, login, "login_bloqueado", "usuarios", u.id)
        return None, "Usuário bloqueado por tentativas erradas. Tente de novo em alguns minutos."
    try:
        _ph.verify(u.senha_hash, senha)
    except (VerificationError, InvalidHashError):
        u.falhas = (u.falhas or 0) + 1
        if u.falhas >= MAX_FALHAS:
            u.bloqueado_ate = agora + BLOQUEIO
            u.falhas = 0
        auditar(s, request, login, "login_falhou", "usuarios", u.id)
        return None, "Usuário ou senha inválidos."
    if _ph.check_needs_rehash(u.senha_hash):
        u.senha_hash = _ph.hash(senha)
    u.falhas = 0
    u.bloqueado_ate = None
    return u, ""


def criar_sessao(s, request: Request, u: Usuario) -> tuple[str, bool]:
    """Devolve (token, ip_novo). ip_novo = login de um IP nunca visto (alerta)."""
    token = secrets.token_urlsafe(32)
    ip = ip_cliente(request)
    s.add(Sessao(token_hash=_h(token), usuario_id=u.id, csrf=secrets.token_urlsafe(24), ip=ip))
    vistos = list(u.ips_vistos or [])
    ip_novo = bool(vistos) and ip not in vistos
    if ip not in vistos:
        u.ips_vistos = (vistos + [ip])[-50:]
    u.ultimo_login = datetime.now(timezone.utc)
    u.ultimo_ip = ip
    auditar(s, request, u.login, "login", "usuarios", u.id, depois={"ip_novo": ip_novo})
    return token, ip_novo


def sessao_atual(s, request: Request):
    """(usuario, sessao) ou (None, None). Renova o ultimo uso."""
    token = request.cookies.get(COOKIE)
    if not token:
        return None, None
    ses = s.get(Sessao, _h(token))
    if ses is None:
        return None, None
    agora = datetime.now(timezone.utc)
    if agora - ses.ultimo_uso > timedelta(minutes=config().sessao_min):
        s.delete(ses)
        return None, None
    u = s.get(Usuario, ses.usuario_id)
    if u is None or not u.ativo:
        s.delete(ses)
        return None, None
    ses.ultimo_uso = agora
    return u, ses


def encerrar(s, request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        s.execute(delete(Sessao).where(Sessao.token_hash == _h(token)))


def limpar_sessoes(s):
    limite = datetime.now(timezone.utc) - timedelta(minutes=config().sessao_min)
    s.execute(delete(Sessao).where(Sessao.ultimo_uso < limite))


def conferir_csrf(ses: Sessao, recebido: str):
    if not recebido or not secrets.compare_digest(ses.csrf, recebido):
        raise HTTPException(status_code=403, detail="Formulário expirado. Recarregue a página e tente de novo.")


def rede_sistema(request: Request) -> bool:
    try:
        ip = ipaddress.ip_address(ip_cliente(request))
    except ValueError:
        return False
    return any(ip in r for r in config().redes_sistema)
