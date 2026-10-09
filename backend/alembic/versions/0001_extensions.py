"""extensions

Revision ID: 0001
Revises: 
Create Date: 2026-10-09 12:00:00.000000

"""
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

def downgrade() -> None:
    op.execute("DROP EXTENSION IF EXISTS citext")
