"""Arquivos de lista: ordenacao em disco e busca binaria (pouca memoria).

Listas como a UT1 adulto (~5 milhoes de linhas) nunca entram inteiras na
memoria: tudo passa por arquivos ordenados com o `sort` do sistema.
"""
import gzip
import hashlib
import os
import subprocess
from pathlib import Path

AMBIENTE_SORT = dict(os.environ, LC_ALL="C")


def ordenar_unico(entrada: Path, saida: Path, tmpdir: Path) -> None:
    """sort -u em disco, ordem de bytes (LC_ALL=C), memoria limitada."""
    tmpdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["sort", "-u", "-S", "128M", "-T", str(tmpdir), "-o", str(saida), str(entrada)],
                   check=True, env=AMBIENTE_SORT)


def contar_linhas(caminho: Path) -> int:
    if not caminho.exists():
        return 0
    n = 0
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            n += bloco.count(b"\n")
    return n


def sha256(caminho: Path) -> str:
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def gz_deterministico(entrada: Path, saida: Path) -> None:
    """gzip sem data nem nome: o mesmo conteudo sempre da o mesmo sha256."""
    with open(entrada, "rb") as fi, open(saida, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as gz:
            for bloco in iter(lambda: fi.read(1 << 20), b""):
                gz.write(bloco)


def contem(caminho: Path, linha: str) -> bool:
    """Busca binaria de uma linha exata num arquivo ordenado com LC_ALL=C."""
    if not caminho.exists():
        return False
    alvo = linha.encode()
    with open(caminho, "rb") as f:
        f.seek(0, os.SEEK_END)
        tamanho = f.tell()

        def linha_a_partir(p):
            """Primeira linha inteira que comeca em p ou depois."""
            if p > 0:
                f.seek(p - 1)
                if f.read(1) != b"\n":
                    f.readline()
            else:
                f.seek(0)
            l = f.readline()
            return l.rstrip(b"\n") if l else None

        # menor posicao cuja linha seguinte e >= alvo (as linhas crescem com a posicao)
        lo, hi = 0, tamanho
        while lo < hi:
            meio = (lo + hi) // 2
            l = linha_a_partir(meio)
            if l is None or l >= alvo:
                hi = meio
            else:
                lo = meio + 1
        return linha_a_partir(lo) == alvo
