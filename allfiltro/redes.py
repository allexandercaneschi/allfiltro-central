"""Listas de rede (IPs) da central: paises, continentes e servicos.

Para a aba Paises do ALL Filtros (entrada pelas WANs so de alguns paises,
com excecoes de servicos e de IPs):

  pais-<cc>          faixas de um pais (ex.: pais-br), IPv4 e IPv6
  continente-<cc>    faixas de um continente (af, an, as, eu, na, oc, sa) - so com MaxMind
  satelite-proxy     faixas marcadas pela MaxMind como proxy anonimo ou satelite
  servico-<nome>     faixas publicadas pelo proprio servico (Microsoft 365, Google...)

Fontes:
  - registros oficiais de IP (LACNIC, ARIN, RIPE, APNIC, AFRINIC): onde o IP
    foi registrado; publicos, sem chave; sempre usados
  - MaxMind GeoLite2-Country (CSV): onde o IP e usado; precisa de conta e chave
    (maxmind_conta / maxmind_chave em /etc/allfiltro/allfiltro.conf)
  As duas sao somadas: um IP do Brasil em qualquer uma conta como Brasil (para
  a regra "so Brasil" isso evita barrar quem esta aqui, como a Starlink).

Arquivos: /srv/allfiltro/redes/<geracao>/<lista>.txt.gz e manifest.json
(assinado como o das categorias); "atual" aponta para a geracao em uso.
Fonte que falhar mantem o ultimo download bom.
"""
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

from . import VERSAO
from .arquivos import gz_deterministico, sha256
from .config import config

RIR = {
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripe": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
SERVICOS = {
    "microsoft365": ("Microsoft 365", "https://endpoints.office.com/endpoints/worldwide?clientrequestid={uuid}", "m365"),
    "google": ("Google (serviços)", "https://www.gstatic.com/ipranges/goog.json", "google"),
    "google-cloud": ("Google Cloud", "https://www.gstatic.com/ipranges/cloud.json", "google"),
    "aws": ("Amazon AWS", "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
    "cloudflare": ("Cloudflare", "https://www.cloudflare.com/ips-v4\nhttps://www.cloudflare.com/ips-v6", "texto"),
    "starlink": ("Starlink", "https://geoip.starlinkisp.net/feed.csv", "starlink"),
}
CONTINENTES = {"af": "África", "an": "Antártida", "as": "Ásia", "eu": "Europa", "na": "América do Norte",
               "oc": "Oceania", "sa": "América do Sul"}
MAXMIND_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip"
INTERVALO = 24 * 3600          # registros, servicos e MaxMind: uma vez por dia
INTERVALO_ERRO = 3 * 3600      # fonte com erro: tenta de novo em 3 h
MIN_BR = 500                   # sanidade: lista do Brasil com menos que isso nao e publicada


def dir_redes() -> Path:
    return config().dados / "redes"


def _estado_arq() -> Path:
    return dir_redes() / "estado.json"


def ler_estado() -> dict:
    try:
        return json.loads(_estado_arq().read_text())
    except (OSError, ValueError):
        return {}


def _gravar_estado(e: dict) -> None:
    dir_redes().mkdir(parents=True, exist_ok=True)
    tmp = _estado_arq().with_suffix(".tmp")
    tmp.write_text(json.dumps(e, ensure_ascii=False, indent=1, sort_keys=True))
    tmp.replace(_estado_arq())


class _SemRedirecionar(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _baixar(url: str, destino: Path, auth: tuple | None = None) -> None:
    ua = {"User-Agent": f"ALL-Filtros-Central/{VERSAO}"}
    if auth:
        # MaxMind: a autenticacao vai so no primeiro pedido; o download em si e
        # um redirecionamento para um armazenamento que recusa o cabecalho
        req = urllib.request.Request(url, headers=dict(ua, Authorization="Basic " + b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()))
        try:
            urllib.request.build_opener(_SemRedirecionar).open(req, timeout=60).close()
            raise OSError("a MaxMind nao redirecionou para o download")
        except urllib.error.HTTPError as ex:
            if ex.code not in (301, 302, 303, 307, 308) or not ex.headers.get("Location"):
                raise OSError("MaxMind: HTTP %s (conta ou chave errada?)" % ex.code if ex.code in (401, 403) else f"MaxMind: HTTP {ex.code}")
            url = ex.headers["Location"]
    req = urllib.request.Request(url, headers=ua)
    with urllib.request.urlopen(req, timeout=180) as r, open(destino, "wb") as f:
        if getattr(r, "status", 200) not in (None, 200):
            raise OSError(f"HTTP {r.status}")
        shutil.copyfileobj(r, f, 1 << 20)
    if destino.stat().st_size == 0:
        raise OSError("arquivo vazio")


def _vencida(e: dict, nome: str) -> bool:
    x = e.get("fontes", {}).get(nome, {})
    ultima = x.get("tentativa", 0)
    espera = INTERVALO if x.get("ok", False) else INTERVALO_ERRO
    return time.time() - ultima >= espera


# ---------------------------------------------------------------- leitura
def _rede(txt: str):
    try:
        return ipaddress.ip_network(txt.strip(), strict=False)
    except ValueError:
        return None


def _ler_rir(arq: Path, listas: dict) -> int:
    n = 0
    with open(arq, encoding="utf-8", errors="replace") as f:
        for l in f:
            if l.startswith("#"):
                continue
            p = l.strip().split("|")
            if len(p) < 7 or p[1] in ("", "*") or p[2] not in ("ipv4", "ipv6") or p[6] not in ("allocated", "assigned"):
                continue
            cc = p[1].lower()
            if len(cc) != 2 or not cc.isalpha():
                continue
            try:
                if p[2] == "ipv4":
                    ini = ipaddress.IPv4Address(p[3])
                    redes = ipaddress.summarize_address_range(ini, ini + int(p[4]) - 1)
                else:
                    redes = [ipaddress.IPv6Network(f"{p[3]}/{p[4]}", strict=False)]
            except (ValueError, ipaddress.AddressValueError):
                continue
            s = listas.setdefault(f"pais-{cc}", set())
            for r in redes:
                s.add(r)
                n += 1
    return n


def _ler_maxmind(arq: Path, listas: dict, nomes: dict) -> int:
    n = 0
    with zipfile.ZipFile(arq) as z:
        membros = {Path(m).name: m for m in z.namelist()}
        locais = {}
        for nome_csv in ("GeoLite2-Country-Locations-en.csv", "GeoLite2-Country-Locations-pt-BR.csv"):
            if nome_csv not in membros:
                continue
            with z.open(membros[nome_csv]) as f:
                for row in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8")):
                    g = row.get("geoname_id", "")
                    cc = (row.get("country_iso_code") or "").lower()
                    cont = (row.get("continent_code") or "").lower()
                    locais.setdefault(g, {}).update({"cc": cc, "cont": cont})
                    if cc and row.get("country_name"):
                        nomes[f"pais-{cc}"] = row["country_name"]  # pt-BR vem por ultimo e vence
        for nome_csv in ("GeoLite2-Country-Blocks-IPv4.csv", "GeoLite2-Country-Blocks-IPv6.csv"):
            if nome_csv not in membros:
                continue
            with z.open(membros[nome_csv]) as f:
                for row in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8")):
                    r = _rede(row.get("network", ""))
                    if r is None:
                        continue
                    loc = locais.get(row.get("geoname_id") or "") or locais.get(row.get("registered_country_geoname_id") or "") or {}
                    if loc.get("cc"):
                        listas.setdefault(f"pais-{loc['cc']}", set()).add(r)
                    if loc.get("cont") in CONTINENTES:
                        listas.setdefault(f"continente-{loc['cont']}", set()).add(r)
                    if row.get("is_anonymous_proxy") == "1" or row.get("is_satellite_provider") == "1":
                        listas.setdefault("satelite-proxy", set()).add(r)
                    n += 1
    return n


def _ler_servico(tipo: str, arqs: list, s: set) -> int:
    antes = len(s)
    for arq in arqs:
        texto = Path(arq).read_text(encoding="utf-8", errors="replace")
        if tipo == "m365":
            for e in json.loads(texto):
                for ip in e.get("ips", []) or []:
                    r = _rede(ip)
                    if r:
                        s.add(r)
        elif tipo == "google":
            for p in json.loads(texto).get("prefixes", []):
                r = _rede(p.get("ipv4Prefix") or p.get("ipv6Prefix") or "")
                if r:
                    s.add(r)
        elif tipo == "aws":
            d = json.loads(texto)
            for p in d.get("prefixes", []) + d.get("ipv6_prefixes", []):
                r = _rede(p.get("ip_prefix") or p.get("ipv6_prefix") or "")
                if r:
                    s.add(r)
        elif tipo == "starlink":
            for l in texto.splitlines():
                r = _rede(l.split(",")[0]) if l and not l.startswith("#") else None
                if r:
                    s.add(r)
        else:  # texto: uma faixa por linha
            for l in texto.splitlines():
                r = _rede(l.split("#")[0]) if l.strip() else None
                if r:
                    s.add(r)
    return len(s) - antes


# ---------------------------------------------------------------- geracao
def _escrever(redes: set, destino_gz: Path, tmpdir: Path) -> tuple[int, int, str]:
    v4 = list(ipaddress.collapse_addresses(sorted(r for r in redes if r.version == 4)))
    v6 = list(ipaddress.collapse_addresses(sorted(r for r in redes if r.version == 6)))
    txt = tmpdir / (destino_gz.name + ".txt")
    with open(txt, "w") as f:
        for r in v4 + v6:
            f.write(f"{r}\n")
    gz_deterministico(txt, destino_gz)
    txt.unlink()
    return len(v4) + len(v6), destino_gz.stat().st_size, sha256(destino_gz)


def atualizar(forcar: bool = False) -> dict:
    """Baixa o que venceu e, se algo mudou, gera e publica uma nova geracao.

    Retorna o estado (o mesmo de estado.json)."""
    cfg = config()
    base = dir_redes()
    fontes_dir = base / "fontes"
    fontes_dir.mkdir(parents=True, exist_ok=True)
    e = ler_estado()
    e.setdefault("fontes", {})
    baixou = False
    agora = time.time()

    def baixar(nome: str, url: str, destino: Path, auth=None) -> None:
        nonlocal baixou
        if not forcar and not _vencida(e, nome):
            return
        x = e["fontes"].setdefault(nome, {})
        x["tentativa"] = agora
        tmp = destino.with_suffix(destino.suffix + ".novo")
        try:
            _baixar(url, tmp, auth)
            if not destino.exists() or sha256(tmp) != sha256(destino):
                tmp.replace(destino)
                baixou = True
            else:
                tmp.unlink()
            x.update(ok=True, erro="", ok_em=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        except Exception as ex:  # rede, HTTP, TLS
            tmp.unlink(missing_ok=True)
            x.update(ok=False, erro=str(ex)[:200])

    for nome, url in RIR.items():
        baixar(f"rir-{nome}", url, fontes_dir / f"rir-{nome}.txt")
    conta = getattr(cfg, "maxmind_conta", "")
    chave = getattr(cfg, "maxmind_chave", "")
    if conta and chave:
        baixar("maxmind", MAXMIND_URL, fontes_dir / "maxmind.zip", (conta, chave))
    else:
        e["fontes"]["maxmind"] = {"ok": False, "erro": "sem chave (maxmind_conta / maxmind_chave)"}
    for nome, (_, urls, _) in SERVICOS.items():
        for i, url in enumerate(urls.split("\n")):
            baixar(f"servico-{nome}-{i}", url.format(uuid=uuid.uuid4()), fontes_dir / f"servico-{nome}-{i}.txt")

    atual = base / "atual"
    if not baixou and not forcar and (atual / "manifest.json").exists():
        _gravar_estado(e)
        return e

    # ---- monta todas as listas
    listas: dict[str, set] = {}
    nomes: dict[str, str] = {}
    for nome in RIR:
        arq = fontes_dir / f"rir-{nome}.txt"
        if arq.exists():
            _ler_rir(arq, listas)
    mm = fontes_dir / "maxmind.zip"
    e["maxmind_usada"] = False
    if mm.exists() and conta and chave:
        try:
            _ler_maxmind(mm, listas, nomes)
            e["maxmind_usada"] = True
        except (zipfile.BadZipFile, OSError, ValueError) as ex:
            e["fontes"]["maxmind"].update(ok=False, erro=f"arquivo inválido: {ex}"[:200])
    for nome, (rotulo, urls, tipo) in SERVICOS.items():
        arqs = [fontes_dir / f"servico-{nome}-{i}.txt" for i in range(len(urls.split("\n")))]
        arqs = [a for a in arqs if a.exists()]
        if arqs:
            s = listas.setdefault(f"servico-{nome}", set())
            try:
                _ler_servico(tipo, arqs, s)
            except (ValueError, KeyError) as ex:
                e["fontes"].setdefault(f"servico-{nome}-0", {}).update(ok=False, erro=f"formato: {ex}"[:200])
            nomes[f"servico-{nome}"] = rotulo
            if not s:
                del listas[f"servico-{nome}"]
    for cc, rotulo in CONTINENTES.items():
        nomes[f"continente-{cc}"] = rotulo
    nomes["satelite-proxy"] = "Proxy anônimo e satélite"
    nomes.setdefault("pais-br", "Brasil")

    if len(listas.get("pais-br", ())) < MIN_BR:
        e["erro"] = f"lista do Brasil com {len(listas.get('pais-br', ()))} faixas: não publicada (mantida a anterior)"
        _gravar_estado(e)
        return e

    # ---- grava a geracao nova
    geracao = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    destino = base / geracao
    tmpdir = Path(tempfile.mkdtemp(dir=cfg.dir_tmp if cfg.dir_tmp.exists() else None))
    try:
        destino.mkdir(parents=True)
        manifesto = {"formato": 1, "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "central": cfg.url_publica, "maxmind": e["maxmind_usada"], "listas": {}}
        for nome in sorted(listas):
            itens, tam, sha = _escrever(listas[nome], destino / f"{nome}.txt.gz", tmpdir)
            tipo = nome.split("-", 1)[0]
            manifesto["listas"][nome] = {"nome": nomes.get(nome, nome.split("-", 1)[1].upper()), "tipo": tipo,
                                         "itens": itens, "bytes": tam, "sha256": sha,
                                         "url": f"/api/v1/redes/{nome}.txt.gz"}
        anterior = None
        try:
            anterior = json.loads((atual / "manifest.json").read_text())
        except (OSError, ValueError):
            pass
        iguais = anterior is not None and {k: v["sha256"] for k, v in anterior.get("listas", {}).items()} == \
            {k: v["sha256"] for k, v in manifesto["listas"].items()}
        if iguais and not forcar:
            shutil.rmtree(destino)
        else:
            corpo = json.dumps(manifesto, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            (destino / "manifest.json").write_bytes(corpo)
            for p in [destino] + list(destino.iterdir()):
                os.chmod(p, 0o755 if p.is_dir() else 0o644)
            link_tmp = base / "atual.novo"
            link_tmp.unlink(missing_ok=True)
            link_tmp.symlink_to(geracao)
            link_tmp.replace(atual)
            e["geracao"] = geracao
            e["listas"] = len(manifesto["listas"])
            # guarda so as 2 ultimas geracoes
            gens = sorted(p for p in base.iterdir() if p.is_dir() and p.name.isdigit())
            for velha in gens[:-2]:
                shutil.rmtree(velha, ignore_errors=True)
        e["publicado_em"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        e["erro"] = ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    _gravar_estado(e)
    return e


def manifesto_assinado() -> tuple[bytes, str] | None:
    """(corpo, etag) do manifesto em uso, ou None."""
    try:
        corpo = (dir_redes() / "atual" / "manifest.json").read_bytes()
    except OSError:
        return None
    return corpo, '"' + hashlib.sha256(corpo).hexdigest() + '"'


def caminho_lista(nome: str) -> Path | None:
    if not nome.replace("-", "").isalnum():
        return None
    p = dir_redes() / "atual" / f"{nome}.txt.gz"
    return p if p.exists() else None
