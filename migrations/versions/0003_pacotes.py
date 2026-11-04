"""pacotes do ALL Filtros e canal por firewall

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('firewalls', sa.Column('canal', sa.String(length=10), server_default='estavel', nullable=False))
    op.create_table(
        'pacotes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('versao', sa.String(length=40), nullable=False, unique=True),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('tamanho', sa.Integer(), nullable=False),
        sa.Column('canal', sa.String(length=10), nullable=False),
        sa.Column('notas', sa.Text(), nullable=False, server_default=''),
        sa.Column('enviado_por', sa.String(length=80), nullable=False, server_default=''),
        sa.Column('enviado_em', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('promovido_em', sa.DateTime(timezone=True)),
    )


def downgrade():
    op.drop_table('pacotes')
    op.drop_column('firewalls', 'canal')
