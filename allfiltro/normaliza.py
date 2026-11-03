"""Normalizacao de dominios e IPs (entrada manual, importacao e fontes)."""
import ipaddress
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_ESQUEMA = re.compile(r"^[a-z][a-z0-9+.-]*://")


class ValorInvalido(ValueError):
    pass


def dominio(texto: str, aceita_curinga: bool = False) -> str:
    """'https://WWW.Ação.com.br:443/x' -> 'xn--ao-7ia5b.com.br'.

    Recusa curinga (*) e dominio sem ponto. Fontes externas costumam trazer
    '*.dominio' ou '.dominio': com aceita_curinga=True isso vira 'dominio'.
    """
    d = (texto or "").strip().lower()
    d = _ESQUEMA.sub("", d)
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    if d.startswith("[") or d.count(":") > 1:
        raise ValorInvalido("parece um IPv6, use o tipo IP")
    d = d.split(":", 1)[0].strip().rstrip(".")
    if aceita_curinga:
        while d.startswith("*.") or d.startswith("."):
            d = d[2:] if d.startswith("*.") else d[1:]
    if "*" in d:
        raise ValorInvalido("curinga (*) nao e aceito: use o dominio pai, ele ja vale para os subdominios")
    if d.startswith("www."):
        d = d[4:]
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise ValorInvalido(f"dominio com acento invalido: {e}")
    if "." not in d:
        raise ValorInvalido("dominio sem ponto")
    if len(d) > 253:
        raise ValorInvalido("dominio longo demais")
    rotulos = d.split(".")
    if not all(_LABEL.match(r) for r in rotulos):
        raise ValorInvalido("caracteres invalidos no dominio")
    if rotulos[-1].isdigit():
        raise ValorInvalido("parece um IP, use o tipo IP")
    return d


def ip(texto: str) -> str:
    """'10.1.2.3/8' -> '10.0.0.0/8'; endereco unico fica sem mascara."""
    t = (texto or "").strip()
    try:
        if "/" in t:
            rede = ipaddress.ip_network(t, strict=False)
            if rede.num_addresses == 1:
                return str(rede.network_address)
            return str(rede)
        return str(ipaddress.ip_address(t))
    except ValueError:
        raise ValorInvalido("IP ou faixa CIDR invalido")


def eh_ip(texto: str) -> bool:
    t = (texto or "").strip()
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def valor(texto: str):
    """Detecta o tipo: devolve ('ip', valor) ou ('dominio', valor)."""
    t = (texto or "").strip()
    if eh_ip(t):
        return "ip", ip(t)
    return "dominio", dominio(t)


def linha_de_fonte(linha: str, formato: str):
    """Uma linha de lista externa -> ('dominio'|'ip', valor) ou None (comentario, lixo)."""
    l = linha.strip()
    if not l or l[0] in "#!;[":
        return None
    if formato == "hosts":
        partes = l.split()
        if len(partes) < 2 or partes[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            return None
        l = partes[1]
        if l in ("localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"):
            return None
    elif formato == "adblock":
        if not l.startswith("||"):
            return None
        l = l[2:].split("^", 1)[0].split("$", 1)[0]
    else:
        l = l.split("#", 1)[0].split()[0] if l.split("#", 1)[0].strip() else ""
        if not l:
            return None
    try:
        if eh_ip(l):
            return "ip", ip(l)
        if formato == "ips":
            return None
        return "dominio", dominio(l, aceita_curinga=True)
    except ValorInvalido:
        return None


def invertido(d: str) -> str:
    """'ge.globo.com' -> 'com.globo.ge' (ordenar assim agrupa pai e filhos)."""
    return ".".join(reversed(d.split(".")))


def pais(d: str):
    """'a.b.globo.com' -> ['a.b.globo.com', 'b.globo.com', 'globo.com', 'com']."""
    p = d.split(".")
    return [".".join(p[i:]) for i in range(len(p))]
