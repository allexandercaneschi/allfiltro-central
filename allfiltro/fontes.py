"""Download das fontes externas e "retrato" de cada uma em arquivos.

Retrato de uma fonte: /srv/allfiltro/fontes/<id>/
    <origem>.dom   dominios normalizados, ordenados (LC_ALL=C), sem repeticao
    <origem>.ip    IPs e faixas normalizados, ordenados
    indice.json    {origem: {"dominios": n, "ips": n}}
<origem> e a pasta da categoria no pacote (ex.: gambling na UT1) ou "_" numa
lista de categoria unica. Fonte com erro (HTTP != 200, arquivo vazio, formato
estranho) mantem o ultimo retrato valido.
"""
import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import VERSAO
from .arquivos import contar_linhas, ordenar_unico
from .config import config
from .normaliza import linha_de_fonte

UNICA = "_"
TAMANHO_MAX = 512 * 1024 * 1024
_ORIGEM_OK = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class ErroFonte(Exception):
    pass


def baixar(url: str, destino: Path) -> str:
    """Baixa para destino; devolve o sha256. file:// e aceito (testes)."""
    req = urllib.request.Request(url, headers={"User-Agent": f"ALL-Filtros-Central/{VERSAO}"})
    h = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(req, timeout=120) as r, open(destino, "wb") as f:
            status = getattr(r, "status", None)  # None em file:// (testes)
            if status not in (None, 200):
                raise ErroFonte(f"HTTP {status}")
            for bloco in iter(lambda: r.read(1 << 20), b""):
                total += len(bloco)
                if total > TAMANHO_MAX:
                    raise ErroFonte("arquivo maior que 512 MB")
                h.update(bloco)
                f.write(bloco)
    except ErroFonte:
        raise
    except urllib.error.HTTPError as e:
        raise ErroFonte(f"HTTP {e.code}")
    except Exception as e:  # rede, DNS, TLS
        raise ErroFonte(f"falha no download: {e}")
    if total == 0:
        raise ErroFonte("arquivo vazio")
    return h.hexdigest()


def _linhas_texto(caminho: Path):
    """Linhas de um arquivo texto, gz descompactado se preciso."""
    with open(caminho, "rb") as f:
        inicio = f.read(2)
    if inicio == b"\x1f\x8b":
        import gzip
        arq = gzip.open(caminho, "rb")
    else:
        arq = open(caminho, "rb")
    with arq:
        for l in arq:
            yield l.decode("utf-8", "replace")


def _membros_pacote(caminho: Path):
    """(origem, linhas) de cada lista de um tar.gz com pastas (UT1: <cat>/domains).

    Pasta que e atalho para outra (na UT1, malware -> phishing) entra com o
    nome do atalho e o conteudo da pasta de destino.
    """
    try:
        tar = tarfile.open(caminho, "r:*")
    except tarfile.TarError as e:
        raise ErroFonte(f"pacote invalido: {e}")
    with tar:
        membros = tar.getmembers()
        listas = {}  # pasta -> [membro de lista]
        atalhos = {}  # pasta atalho -> pasta destino
        for m in membros:
            nome = m.name.strip("/")
            partes = nome.split("/")
            if m.issym() and m.linkname and "/" not in m.linkname.strip("/") and _ORIGEM_OK.match(partes[-1]):
                atalhos["/".join(partes)] = "/".join(partes[:-1] + [m.linkname.strip("/")])
                continue
            if len(partes) < 2 or partes[-1] not in ("domains", "ips", "domains.txt", "ips.txt"):
                continue
            if m.isfile() or m.islnk() or m.issym():
                listas.setdefault("/".join(partes[:-1]), []).append(m)
        for atalho, destino in atalhos.items():
            if atalho not in listas and destino in listas:
                listas[atalho] = listas[destino]
        for pasta in sorted(listas):
            origem = pasta.split("/")[-1]
            if not _ORIGEM_OK.match(origem):
                continue
            for m in listas[pasta]:
                try:
                    f = tar.extractfile(m)
                except (KeyError, tarfile.TarError):
                    f = None
                if f is None:
                    continue
                yield origem, (l.decode("utf-8", "replace") for l in f)


def gerar_retrato(arquivo: Path, formato: str, destino: Path) -> dict:
    """Normaliza o arquivo baixado e grava o retrato em destino (pasta nova)."""
    cfg = config()
    destino.mkdir(parents=True)
    tmp = Path(tempfile.mkdtemp(dir=cfg.dir_tmp))
    brutos = {}  # origem -> (arq dom, arq ip)

    def abrir(origem):
        if origem not in brutos:
            brutos[origem] = (open(tmp / f"{origem}.dom.bruto", "w"), open(tmp / f"{origem}.ip.bruto", "w"))
        return brutos[origem]

    try:
        if formato == "pacote":
            fontes = _membros_pacote(arquivo)
        else:
            fontes = [(UNICA, _linhas_texto(arquivo))]
        fmt_linha = "dominios" if formato == "pacote" else formato
        for origem, linhas in fontes:
            fd, fi = abrir(origem)
            for l in linhas:
                r = linha_de_fonte(l, fmt_linha)
                if r is None:
                    continue
                (fi if r[0] == "ip" else fd).write(r[1] + "\n")
        for fd, fi in brutos.values():
            fd.close()
            fi.close()
        if not brutos:
            raise ErroFonte("nenhuma lista reconhecida no arquivo")
        indice = {}
        for origem in brutos:
            for ext in ("dom", "ip"):
                ordenar_unico(tmp / f"{origem}.{ext}.bruto", destino / f"{origem}.{ext}", tmp)
            indice[origem] = {"dominios": contar_linhas(destino / f"{origem}.dom"),
                              "ips": contar_linhas(destino / f"{origem}.ip")}
        if sum(v["dominios"] + v["ips"] for v in indice.values()) == 0:
            raise ErroFonte("formato estranho: nenhum dominio ou IP valido")
        (destino / "indice.json").write_text(json.dumps(indice, ensure_ascii=False, indent=1, sort_keys=True))
        return indice
    finally:
        for fd, fi in brutos.values():
            fd.close()
            fi.close()
        shutil.rmtree(tmp, ignore_errors=True)


def dir_retrato(fonte_id: int) -> Path:
    return config().dir_fontes / str(fonte_id)


def indice(fonte_id: int) -> dict:
    try:
        return json.loads((dir_retrato(fonte_id) / "indice.json").read_text())
    except (OSError, ValueError):
        return {}


def hash_retrato(pasta: Path) -> str:
    """sha256 do conteudo util (muda so quando os itens mudam)."""
    h = hashlib.sha256()
    for arq in sorted(pasta.glob("*.dom")) + sorted(pasta.glob("*.ip")):
        h.update(arq.name.encode())
        with open(arq, "rb") as f:
            for bloco in iter(lambda: f.read(1 << 20), b""):
                h.update(bloco)
    return h.hexdigest()


def atualizar(fonte) -> tuple[bool, str]:
    """Baixa e refaz o retrato de uma fonte (objeto Fonte). Devolve (mudou, status).

    Atualiza os campos da fonte; quem chama faz o commit.
    """
    cfg = config()
    cfg.dir_tmp.mkdir(parents=True, exist_ok=True)
    cfg.dir_fontes.mkdir(parents=True, exist_ok=True)
    agora = datetime.now(timezone.utc)
    trab = Path(tempfile.mkdtemp(dir=cfg.dir_tmp))
    try:
        arquivo = trab / "download"
        sha = baixar(fonte.url, arquivo)
        fonte.ultimo_download = agora
        if sha == fonte.ultimo_sha256 and (dir_retrato(fonte.id) / "indice.json").exists():
            fonte.ultimo_status = "ok (sem mudanca)"
            return False, fonte.ultimo_status
        novo = trab / "retrato"
        idx = gerar_retrato(arquivo, fonte.formato, novo)
        hr = hash_retrato(novo)
        atual = dir_retrato(fonte.id)
        velho = trab / "velho"
        if atual.exists():
            atual.rename(velho)
        novo.rename(atual)
        fonte.ultimo_sha256 = sha
        mudou = hr != fonte.retrato_sha256
        fonte.retrato_sha256 = hr
        total_d = sum(v["dominios"] for v in idx.values())
        total_i = sum(v["ips"] for v in idx.values())
        fonte.ultimo_status = f"ok: {total_d} dominios, {total_i} IPs em {len(idx)} lista(s)"
        return mudou, fonte.ultimo_status
    except ErroFonte as e:
        fonte.ultimo_download = agora
        fonte.ultimo_status = f"erro: {e} (mantido o ultimo retrato valido)"
        return False, fonte.ultimo_status
    finally:
        shutil.rmtree(trab, ignore_errors=True)
