"""Columna ``users.tokens_invalid_before`` para revocar todos los tokens de un usuario (H-37).

Revision ID: c96ea3dd0ecb
Revises: 954103ffaf3c
Create Date: 2026-10-10 17:52:40.814157

Escrita a mano (spec Fase 5 §3.5). El Cap. 6 §Revocación y renovación pide "revocar todos los
tokens vivos" de un usuario al cambiar su contraseña, desactivarlo o cambiar sus roles, pero
``revoked_tokens`` solo revoca ``jti`` individuales. Con esta columna se rechaza todo token humano
cuyo ``iat`` sea anterior a ella.

NULL = nunca se ha revocado en bloque. Sin índice: siempre se lee junto con la fila del usuario,
por su llave primaria.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c96ea3dd0ecb"
down_revision: str | Sequence[str] | None = "954103ffaf3c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Agrega ``users.tokens_invalid_before TIMESTAMPTZ NULL``."""
    op.add_column(
        "users",
        sa.Column("tokens_invalid_before", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Quita la columna."""
    op.drop_column("users", "tokens_invalid_before")
