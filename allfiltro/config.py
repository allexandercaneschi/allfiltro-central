"""Configuracao da central: /etc/allfiltro/allfiltro.conf (INI).

Variavel ALLFILTRO_CONF aponta outro arquivo (testes).
"""
import configparser
import ipaddress
import os
from functools import lru_cache
from pathlib import Path

ARQUIVO_PADRAO = "/etc/allfiltro/allfiltro.conf"


class Config:
    def __init__(self, caminho: str):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(caminho, encoding="utf-8")
        g = cp["geral"] if cp.has_section("geral") else {}
        rede = cp["rede"] if cp.has_section("rede") else {}

        self.arquivo = caminho
        self.banco_url = g.get("banco_url", "postgresql+psycopg://allfiltro@localhost/listas")
        self.dados = Path(g.get("dados", "/srv/allfiltro"))
        self.segredo = g.get("segredo", "")  # HMAC das chaves de cliente
        self.chave_privada = Path(g.get("chave_privada", "/etc/allfiltro/ed25519.pem"))
        self.url_publica = g.get("url_publica", "https://allfiltro.alltecnologias.com.br").rstrip("/")
        # "xsendfile" (Apache entrega o arquivo) ou "app" (a propria app entrega)
        self.entrega = g.get("entrega", "xsendfile")
        self.cookie_seguro = g.get("cookie_seguro", "sim") != "nao"
        self.sessao_min = int(g.get("sessao_min", "30"))
        # webhook do n8n para alertas (login de IP nunca visto); vazio = desligado
        self.alerta_webhook = g.get("alerta_webhook", "")
        # "desligado": a chave so identifica o cliente (nada e bloqueado por licenca)
        # "ligado": assinatura suspensa/vencida ou firewall acima do limite nao recebe as privadas
        self.licenciamento = g.get("licenciamento", "desligado")

        # quem pode passar o IP real do cliente em X-Forwarded-For (Apache local + HAProxy)
        self.proxies_confiaveis = _redes(rede.get("proxies_confiaveis", "127.0.0.1/32 ::1/128"))
        # quem pode abrir /admin/sistema (rede do escritorio + VPN)
        self.redes_sistema = _redes(rede.get("redes_sistema", "127.0.0.1/32"))

    @property
    def dir_fontes(self) -> Path:
        return self.dados / "fontes"

    @property
    def dir_versoes(self) -> Path:
        return self.dados / "versoes"

    @property
    def dir_pacotes(self) -> Path:
        return self.dados / "pacotes"

    @property
    def dir_tmp(self) -> Path:
        return self.dados / "tmp"

    @property
    def flag_publicar(self) -> Path:
        return self.dados / "run" / "publicar"


def _redes(texto: str):
    redes = []
    for parte in texto.replace(",", " ").split():
        redes.append(ipaddress.ip_network(parte, strict=False))
    return redes


@lru_cache(maxsize=1)
def config() -> Config:
    return Config(os.environ.get("ALLFILTRO_CONF", ARQUIVO_PADRAO))
