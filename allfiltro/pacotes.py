"""Pacote ALL Filtros (all-filtros.sh) distribuido pela central.

Cada versao enviada pelo painel fica em /srv/allfiltro/pacotes/<versao>/all-filtros.sh
e entra no canal "teste". Promovida, vai para "estavel". Os firewalls perguntam
/api/v1/pacote; a resposta e assinada (Ed25519) como o manifesto das listas, e o
pfSense confere a assinatura e o sha256 antes de instalar.
"""
import hashlib
import re
from pathlib import Path

from sqlalchemy import select

from .config import config
from .models import Pacote

CANAIS = ("teste", "estavel")
TAMANHO_MAX = 20 * 1024 * 1024
_VERSAO = re.compile(r'^VERSION="(\d+\.\d+\.\d+)"$', re.M)


class PacoteInvalido(Exception):
    pass


def chave_versao(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def validar(conteudo: bytes) -> str:
    """Confere que e um all-filtros.sh gerado pelo build.py; devolve a versao."""
    if len(conteudo) > TAMANHO_MAX:
        raise PacoteInvalido("arquivo maior que 20 MB")
    if not conteudo.startswith(b"#!/bin/sh"):
        raise PacoteInvalido("não é um script sh (esperado o all-filtros.sh da pasta dist/)")
    try:
        texto = conteudo.decode("utf-8")
    except UnicodeDecodeError:
        raise PacoteInvalido("arquivo não é texto UTF-8")
    m = _VERSAO.search(texto[:20000])
    if not m or "ALL Filtros" not in texto[:5000]:
        raise PacoteInvalido('não encontrei VERSION="x.y.z" do ALL Filtros no começo do arquivo')
    return m.group(1)


def caminho(versao: str) -> Path:
    return config().dir_pacotes / versao / "all-filtros.sh"


def gravar(conteudo: bytes, versao: str) -> str:
    """Grava o arquivo (legivel pelo Apache) e devolve o sha256."""
    destino = caminho(versao)
    destino.parent.mkdir(parents=True, exist_ok=True)
    config().dir_pacotes.chmod(0o755)
    destino.parent.chmod(0o755)
    tmp = destino.with_suffix(".tmp")
    tmp.write_bytes(conteudo)
    tmp.chmod(0o644)
    tmp.rename(destino)
    return hashlib.sha256(conteudo).hexdigest()


def ultimo(s, canal: str):
    """Versao mais nova que o canal recebe: teste ve teste + estavel."""
    canais = ("teste", "estavel") if canal == "teste" else ("estavel",)
    ps = s.scalars(select(Pacote).where(Pacote.canal.in_(canais))).all()
    return max(ps, key=lambda p: chave_versao(p.versao)) if ps else None


def manifesto(p: Pacote, canal: str) -> dict:
    return {"formato": 1, "versao": p.versao, "sha256": p.sha256, "tamanho": p.tamanho, "canal": canal,
            "url": f"/api/v1/pacote/{p.versao}/all-filtros.sh", "notas": p.notas or ""}
