"""sites sem categoria (classificacao dos acessos)

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'sem_categoria',
        sa.Column('dominio', sa.String(length=300), primary_key=True),
        sa.Column('acessos', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('clientes', postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('primeiro_em', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('ultimo_em', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('ignorado', sa.Boolean(), server_default='false', nullable=False),
    )
    op.create_index('ix_sem_categoria_ultimo_em', 'sem_categoria', ['ultimo_em'])


def downgrade():
    op.drop_index('ix_sem_categoria_ultimo_em', table_name='sem_categoria')
    op.drop_table('sem_categoria')
