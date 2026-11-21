"""Tabla ``chain_signatures``: firma diaria Ed25519 del cierre de la cadena de la bitácora (H-81).

Revision ID: 4e885580d0a4
Revises: c96ea3dd0ecb
Create Date: 2026-10-29 15:53:02.880077

Generada con ``--autogenerate`` y revisada. Las conclusiones de TT1 prometen la firma del cierre
diario de la cadena; sin ella la cadena no tiene ancla (H-46). Cada fila firma ``last_hash`` (el
``current_hash`` de ``last_audit_id``) con la llave de ``PORTERO_OPLOG_SIGNING_PRIVATE_KEY``.

- ``last_audit_id`` con FK ``ON DELETE RESTRICT``: borrar una fila firmada exige borrar antes
  la firma. ``UNIQUE``: dos firmas no cierran en el mismo registro.
- ``signature`` con ``CHECK`` de 64 bytes, el largo de una firma Ed25519 (RFC 8032).
- No toca ``audit_logs``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4e885580d0a4"
down_revision: str | Sequence[str] | None = "c96ea3dd0ecb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Crea ``chain_signatures``."""
    op.create_table(
        "chain_signatures",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_audit_id", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_thumbprint", sa.CHAR(length=43), nullable=False),
        sa.CheckConstraint(
            "octet_length(signature) = 64", name=op.f("ck_chain_signatures_signature_ed25519")
        ),
        sa.ForeignKeyConstraint(
            ["last_audit_id"],
            ["audit_logs.id"],
            name=op.f("fk_chain_signatures_last_audit_id_audit_logs"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_chain_signatures")),
        sa.UniqueConstraint("last_audit_id", name=op.f("uq_chain_signatures_last_audit_id")),
    )


def downgrade() -> None:
    """Borra ``chain_signatures`` (y con ella todas las firmas)."""
    op.drop_table("chain_signatures")
