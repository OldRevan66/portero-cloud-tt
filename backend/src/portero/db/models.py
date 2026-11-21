"""Modelos SQLAlchemy 2.0 tipados de las 11 tablas del Cap. 5 §Modelo de Datos, con las
precisiones H-03, H-04, H-06 y H-12 (spec §2), más ``chain_signatures`` (firma diaria del cierre
de la cadena, H-81).

Convenciones:
- PK UUID generadas en la aplicación (``uuid.uuid4``), salvo ``roles`` (catálogo de enteros)
  y ``audit_logs`` (BIGSERIAL, preserva el orden de inserción).
- Fechas ``TIMESTAMP WITH TIME ZONE`` en UTC.
- Sin ``relationship()``: los repositorios consultan de forma explícita. Con SQLAlchemy
  asíncrono una carga perezosa implícita fallaría fuera de un ``await``.
- ``updated_at`` lo mantiene un *trigger* de la base (Cap. 5), creado en la migración inicial;
  por eso se declara ``server_onupdate=FetchedValue()``.
- Los índices llevan nombre explícito para que la migración sea legible ante revisión.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    FetchedValue,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import CHAR, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
}


class Base(DeclarativeBase):
    """Base declarativa con convención de nombres para restricciones (Alembic)."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB,
    }


def _now() -> Any:
    """``DEFAULT CURRENT_TIMESTAMP`` del lado del servidor."""
    return func.now()


class User(Base):
    """Actores humanos A-01..A-03 (Cap. 5, tabla ``users``; RF-008, RF-013)."""

    __tablename__ = "users"
    __mapper_args__ = {"eager_defaults": True}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(server_default=true())
    failed_login_attempts: Mapped[int] = mapped_column(server_default=text("0"))
    locked_until: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    tokens_invalid_before: Mapped[datetime | None]
    """H-37 (spec Fase 5 §3.5): se rechaza todo token humano con ``iat`` anterior a esta fecha.
    La fijan el cambio de contraseña, la desactivación y los cambios de asignaciones."""
    created_at: Mapped[datetime] = mapped_column(server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=_now(), server_onupdate=FetchedValue()
    )


class Role(Base):
    """Catálogo de los 3 roles (RF-011); se siembra en la migración inicial."""

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str | None] = mapped_column(Text)


class Project(Base):
    """Proyectos de la organización (Cap. 5; RF-030, RF-032)."""

    __tablename__ = "projects"
    __mapper_args__ = {"eager_defaults": True}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=_now(), server_onupdate=FetchedValue()
    )
    archived_at: Mapped[datetime | None]


class Environment(Base):
    """Ambientes de un proyecto (Cap. 5; RF-031)."""

    __tablename__ = "environments"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=_now())


class UserRoleAssignment(Base):
    """Rol de un usuario con alcance instancia / proyecto / ambiente (Cap. 5; RF-012).

    La pertenencia del ambiente al proyecto se valida en la aplicación (spec §2). El UNIQUE usa
    ``NULLS NOT DISTINCT`` (PostgreSQL 15+): sin eso dos asignaciones globales iguales (ambos
    alcances NULL) no chocarían, porque en SQL estándar NULL ≠ NULL (H-19).
    """

    __tablename__ = "user_role_assignments"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "role_id",
            "project_id",
            "environment_id",
            name="uq_user_role_assignments_alcance",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint(
            "environment_id IS NULL OR project_id IS NOT NULL", name="ambiente_requiere_proyecto"
        ),
        Index("ix_user_role_assignments_user_id_project_id", "user_id", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE")
    )
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=_now())


class Secret(Base):
    """Metadatos del secreto y puntero a su versión activa (Cap. 5; RF-001, RF-004, RF-007).

    ``current_version_id`` es la denormalización controlada del Cap. 5 §Normalización. Como
    ``secret_versions.secret_id`` apunta de regreso, la FK se crea después de ambas tablas
    (``use_alter``). Es NULL solo dentro de la transacción de creación.
    """

    __tablename__ = "secrets"
    __mapper_args__ = {"eager_defaults": True}
    __table_args__ = (
        Index("ix_secrets_project_id_environment_id", "project_id", "environment_id"),
        Index(
            "uq_secrets_nombre_activo",
            "project_id",
            "environment_id",
            "name",
            unique=True,
            postgresql_where=text("archived_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("environments.id"))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "secret_versions.id",
            use_alter=True,
            name="fk_secrets_current_version_id_secret_versions",
        )
    )
    # "metadata" está reservado por SQLAlchemy en las clases declarativas; la columna conserva
    # el nombre del Cap. 5.
    metadata_: Mapped[dict[str, Any] | None] = mapped_column("metadata")
    expires_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=_now(), server_onupdate=FetchedValue()
    )
    archived_at: Mapped[datetime | None]


class SecretVersion(Base):
    """Valor cifrado de una versión: se mapea 1:1 a ``CiphertextBundle`` (spec §1.4; RF-006).

    ``auth_tag`` es nullable como en el Cap. 5; el Servicio de Gestión de Secretos rechaza una
    fila sin tag al leerla.
    """

    __tablename__ = "secret_versions"
    __table_args__ = (UniqueConstraint("secret_id", "version_number"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    secret_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("secrets.id", ondelete="CASCADE"))
    version_number: Mapped[int]
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary)
    aead_algorithm: Mapped[str] = mapped_column(String(64))
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    wrap_algorithm: Mapped[str] = mapped_column(String(64))
    kek_version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("kek_versions.id"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=_now())


class KekVersion(Base):
    """Generaciones de la KEK: sal, parámetros y verificador, nunca la clave (Cap. 5; H-06).

    El índice único parcial garantiza a lo más una versión activa (H-18).
    """

    __tablename__ = "kek_versions"
    __table_args__ = (
        CheckConstraint("source IN ('password_kdf', 'external_kms')", name="source_valido"),
        Index(
            "uq_kek_versions_una_activa",
            text("(deactivated_at IS NULL)"),
            unique=True,
            postgresql_where=text("deactivated_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    version_number: Mapped[int] = mapped_column(unique=True)
    source: Mapped[str] = mapped_column(String(32))
    kdf_algorithm: Mapped[str | None] = mapped_column(String(64))
    kdf_params: Mapped[dict[str, Any] | None]
    external_ref: Mapped[str | None] = mapped_column(String(512))
    activated_at: Mapped[datetime] = mapped_column(server_default=_now())
    deactivated_at: Mapped[datetime | None]
    verifier: Mapped[bytes | None] = mapped_column(LargeBinary)


class AuditLog(Base):
    """Bitácora con cadena de hashes del Servicio de Registro de Operaciones (Cap. 5;
    RF-016..RF-021; H-04, H-12).

    ``project_id`` y ``environment_id`` no tienen FK a propósito: el registro debe sobrevivir al
    archivado o borrado del recurso (H-12). ``details`` jamás contiene valores de secretos.
    El encadenamiento por hash se implementa en la Fase 5 (H-11).
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("actor_type IN ('human', 'service')", name="actor_type_valido"),
        CheckConstraint("result IN ('success', 'failure')", name="result_valido"),
        Index("ix_audit_logs_event_timestamp", text("event_timestamp DESC")),
        Index(
            "ix_audit_logs_actor_user_id_event_timestamp",
            "actor_user_id",
            text("event_timestamp DESC"),
        ),
        Index("ix_audit_logs_resource_type_resource_id", "resource_type", "resource_id"),
        Index(
            "ix_audit_logs_project_id_event_timestamp", "project_id", text("event_timestamp DESC")
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # BIGSERIAL
    event_timestamp: Mapped[datetime]
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    actor_type: Mapped[str] = mapped_column(String(32))
    actor_ref: Mapped[str] = mapped_column(String(255))
    verb: Mapped[str] = mapped_column(String(32))
    resource_type: Mapped[str | None] = mapped_column(String(32))
    resource_id: Mapped[uuid.UUID | None]
    result: Mapped[str] = mapped_column(String(16))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    previous_hash: Mapped[str | None] = mapped_column(CHAR(64))
    current_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    project_id: Mapped[uuid.UUID | None]
    environment_id: Mapped[uuid.UUID | None]
    details: Mapped[dict[str, Any] | None]


class ChainSignature(Base):
    """Firma Ed25519 del cierre de la cadena de ``audit_logs`` (conclusiones de TT1; H-81).

    ``created_at`` lo fija la aplicación, no la BD, porque entra en el mensaje firmado. La FK con
    ``ON DELETE RESTRICT`` es defensa en profundidad: para borrar una fila firmada hay que borrar
    antes su firma, y eso lo delata la verificación cruzada con el evento ``sign_chain``.
    """

    __tablename__ = "chain_signatures"
    __table_args__ = (CheckConstraint("octet_length(signature) = 64", name="signature_ed25519"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime]
    last_audit_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_logs.id", ondelete="RESTRICT"), unique=True
    )
    last_hash: Mapped[str] = mapped_column(CHAR(64))
    signature: Mapped[bytes] = mapped_column(LargeBinary)
    public_key_thumbprint: Mapped[str] = mapped_column(CHAR(43))


class RevokedToken(Base):
    """Lista de revocación de tokens (Cap. 5; RF-015; H-03).

    ``user_id`` y ``revoked_by`` son nullable: los tokens de servicio no tienen usuario y la
    rotación automática de refresh tokens no tiene actor administrativo (H-03).
    """

    __tablename__ = "revoked_tokens"
    __table_args__ = (
        CheckConstraint("token_type IN ('access', 'refresh', 'service')", name="token_type_valido"),
        Index("ix_revoked_tokens_expires_at", "expires_at"),
    )

    token_jti: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    token_type: Mapped[str] = mapped_column(String(16))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime] = mapped_column(server_default=_now())
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str | None] = mapped_column(String(128))


class ServiceAccount(Base):
    """Aplicaciones Cliente A-04 con PAT acotado a proyecto/ambiente (Cap. 5; RF-010).

    Solo se guarda ``SHA-256(token)`` (spec §3.3). La pertenencia del ambiente al proyecto se
    valida en la aplicación (Cap. 5).
    """

    __tablename__ = "service_accounts"
    __table_args__ = (
        Index("ix_service_accounts_project_id", "project_id"),
        Index(
            "ix_service_accounts_project_id_vigentes",
            "project_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    token_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    token_prefix: Mapped[str] = mapped_column(String(32))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=_now())
    last_used_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
