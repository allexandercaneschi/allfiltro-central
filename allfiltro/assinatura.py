"""Assinatura Ed25519 do manifesto.

A chave privada fica so no servidor (/etc/allfiltro/ed25519.pem, com copia no
RDM). A publica vai embutida no pacote ALL Filtros, que confere com:
    openssl pkeyutl -verify -rawin -pubin -inkey central.pub -in manifest.json -sigfile manifest.sig
(o PHP do pfSense nao tem sodium; o openssl de linha de comando tem Ed25519)
"""
import base64
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import config


def gerar(caminho: Path) -> None:
    chave = Ed25519PrivateKey.generate()
    pem = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.touch(mode=0o600)
    caminho.write_bytes(pem)
    caminho.chmod(0o600)


@lru_cache(maxsize=1)
def _privada():
    return serialization.load_pem_private_key(config().chave_privada.read_bytes(), password=None)


def publica_pem() -> str:
    return _privada().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def assinar(dados: bytes) -> bytes:
    return _privada().sign(dados)


def assinar_b64(dados: bytes) -> str:
    return base64.b64encode(assinar(dados)).decode()
