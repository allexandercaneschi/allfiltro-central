"""Conexao com o PostgreSQL (banco listas)."""
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import config


@lru_cache(maxsize=1)
def engine():
    return create_engine(config().banco_url, pool_pre_ping=True, pool_size=5, max_overflow=5)


@lru_cache(maxsize=1)
def _fabrica():
    return sessionmaker(bind=engine(), expire_on_commit=False)


def sessao() -> Session:
    return _fabrica()()


@contextmanager
def transacao():
    s = sessao()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
