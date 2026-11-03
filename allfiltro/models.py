"""Modelo de dados (banco "listas"). Ver briefing, secao Modelo de dados.

Diferenca do briefing: o "retrato" de cada fonte (itens_fonte) fica em arquivos
ordenados em /srv/allfiltro/fontes, nao no banco. A UT1 sozinha tem ~5 milhoes
de dominios; em arquivo a montagem roda com pouca memoria e a busca e binaria.
"""
from datetime import datetime

from sqlalchemy import (BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, String, Text,
                        UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def agora():
    return func.now()


class Categoria(Base):
    __tablename__ = "categorias"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chave: Mapped[str] = mapped_column(String(80), unique=True)
    nome: Mapped[str] = mapped_column(String(120))
    descricao: Mapped[str] = mapped_column(Text, default="")
    tipo: Mapped[str] = mapped_column(String(10), default="publica")  # publica | privada
    ativa: Mapped[bool] = mapped_column(Boolean, default=True)
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())


class CategoriaCliente(Base):
    __tablename__ = "categoria_clientes"
    categoria_id: Mapped[int] = mapped_column(ForeignKey("categorias.id", ondelete="CASCADE"), primary_key=True)
    cliente_id: Mapped[str] = mapped_column(ForeignKey("clientes.cliente_id", ondelete="CASCADE"), primary_key=True)


class Fonte(Base):
    __tablename__ = "fontes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nome: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(Text)
    # dominios | hosts | adblock | pacote (tar.gz com pastas, como a UT1) | ips
    formato: Mapped[str] = mapped_column(String(20))
    frequencia_h: Mapped[int] = mapped_column(Integer, default=24)
    ativa: Mapped[bool] = mapped_column(Boolean, default=True)
    ultimo_download: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ultimo_status: Mapped[str] = mapped_column(Text, default="")
    ultimo_sha256: Mapped[str] = mapped_column(String(64), default="")
    retrato_sha256: Mapped[str] = mapped_column(String(64), default="")  # muda quando o conteudo util muda
    baixar_agora: Mapped[bool] = mapped_column(Boolean, default=False)


class Mapeamento(Base):
    __tablename__ = "mapeamentos"
    __table_args__ = (UniqueConstraint("fonte_id", "categoria_origem", "categoria_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fonte_id: Mapped[int] = mapped_column(ForeignKey("fontes.id", ondelete="CASCADE"))
    categoria_origem: Mapped[str] = mapped_column(String(120), default="")  # vazio = lista de categoria unica
    categoria_id: Mapped[int] = mapped_column(ForeignKey("categorias.id", ondelete="CASCADE"))


class Entrada(Base):
    __tablename__ = "entradas"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    categoria_id: Mapped[int] = mapped_column(ForeignKey("categorias.id", ondelete="CASCADE"), index=True)
    valor: Mapped[str] = mapped_column(String(300), index=True)
    tipo: Mapped[str] = mapped_column(String(10))  # dominio | ip
    operacao: Mapped[str] = mapped_column(String(10))  # incluir | retirar
    comentario: Mapped[str] = mapped_column(Text, default="")
    autor: Mapped[str] = mapped_column(String(80), default="")
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())
    ativa: Mapped[bool] = mapped_column(Boolean, default=True)


class Protegido(Base):
    __tablename__ = "protegidos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    valor: Mapped[str] = mapped_column(String(300), unique=True)
    tipo: Mapped[str] = mapped_column(String(10))  # dominio (vale para os subdominios) | ip (endereco ou faixa)
    motivo: Mapped[str] = mapped_column(Text, default="")


class Cliente(Base):
    __tablename__ = "clientes"
    cliente_id: Mapped[str] = mapped_column(String(60), primary_key=True)  # mesmo id do painel de navegacao
    nome: Mapped[str] = mapped_column(String(160))
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)


class Assinatura(Base):
    __tablename__ = "assinaturas"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cliente_id: Mapped[str] = mapped_column(ForeignKey("clientes.cliente_id", ondelete="CASCADE"), index=True)
    chave_hash: Mapped[str] = mapped_column(String(64), unique=True)
    chave_final: Mapped[str] = mapped_column(String(4))
    plano: Mapped[str] = mapped_column(String(40), default="padrao")
    inicio: Mapped[datetime | None] = mapped_column(Date)
    validade: Mapped[datetime | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(12), default="ativa")  # ativa | suspensa | cancelada
    max_firewalls: Mapped[int] = mapped_column(Integer, default=1)
    criado_por: Mapped[str] = mapped_column(String(80), default="")
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())


class Firewall(Base):
    __tablename__ = "firewalls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cliente_id: Mapped[str | None] = mapped_column(ForeignKey("clientes.cliente_id", ondelete="SET NULL"))
    firewall_id: Mapped[str] = mapped_column(String(120), unique=True)
    hostname: Mapped[str] = mapped_column(String(160), default="")
    status: Mapped[str] = mapped_column(String(12), default="aprovado")  # aprovado | aguardando
    versao_pacote: Mapped[str] = mapped_column(String(40), default="")
    versao_listas: Mapped[int | None] = mapped_column(Integer)
    ultimo_ip: Mapped[str] = mapped_column(String(64), default="")
    visto_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Versao(Base):
    __tablename__ = "versoes"
    versao: Mapped[int] = mapped_column(Integer, primary_key=True)
    gerado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())
    manifesto: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(12))  # ativa | travada | anterior | descartada
    erro: Mapped[str] = mapped_column(Text, default="")
    estado: Mapped[str] = mapped_column(String(64), default="")  # hash das entradas usadas
    avisos: Mapped[list] = mapped_column(JSONB, default=list)
    gerado_por: Mapped[str] = mapped_column(String(80), default="")


class Usuario(Base):
    __tablename__ = "usuarios"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nome: Mapped[str] = mapped_column(String(120))
    login: Mapped[str] = mapped_column(String(60), unique=True)
    senha_hash: Mapped[str] = mapped_column(Text)
    papel: Mapped[str] = mapped_column(String(10), default="tecnico")  # tecnico | admin
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)
    ultimo_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ultimo_ip: Mapped[str] = mapped_column(String(64), default="")
    totp_segredo: Mapped[str] = mapped_column(String(64), default="")  # vazio: TOTP ainda nao ligado
    falhas: Mapped[int] = mapped_column(Integer, default=0)
    bloqueado_ate: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ips_vistos: Mapped[list] = mapped_column(JSONB, default=list)


class Sessao(Base):
    __tablename__ = "sessoes"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id", ondelete="CASCADE"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64), default="")
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())
    ultimo_uso: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora())


class Auditoria(Base):
    __tablename__ = "auditoria"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    quando: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=agora(), index=True)
    usuario: Mapped[str] = mapped_column(String(80), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    acao: Mapped[str] = mapped_column(String(60))
    tabela: Mapped[str] = mapped_column(String(40), default="")
    registro: Mapped[str] = mapped_column(String(120), default="")
    antes: Mapped[dict | None] = mapped_column(JSONB)
    depois: Mapped[dict | None] = mapped_column(JSONB)
