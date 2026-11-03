"""Migracoes do banco listas. A URL vem de /etc/allfiltro/allfiltro.conf."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from allfiltro.config import config as cfg
from allfiltro.models import Base

if context.config.config_file_name:
    fileConfig(context.config.config_file_name)

target_metadata = Base.metadata


def run():
    eng = create_engine(cfg().banco_url)
    with eng.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
