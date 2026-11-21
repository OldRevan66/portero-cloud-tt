"""Servicio de Gestión de Secretos: crear, consultar, rotar, actualizar y archivar secretos por
versiones (Algoritmos 1 a 3 del Cap. 6; CU-02, CU-03, CU-04; spec núcleo §1.7; spec Fase 5 §2).

Orden de operaciones de H-10. Como el AAD liga el ciphertext a ``secret_id`` y
``version_number`` (H-05), ambos deben conocerse antes de cifrar:

- Creación: el ``secret_id`` se genera en la aplicación antes de cifrar; versión = 1.
- Rotación, en una sola transacción: ``SELECT ... FOR UPDATE`` del secreto → N+1 → cifrar →
  ``INSERT secret_versions`` → ``UPDATE secrets.current_version_id`` → ``COMMIT``. El bloqueo de
  fila hace que dos rotaciones simultáneas se serialicen en lugar de calcular el mismo N+1.

Los diagramas de secuencia muestran el cifrado antes del ``BEGIN``; el cambio es de
implementación y no altera el flujo entre componentes (spec núcleo §1.7).

**Registro de operaciones (H-11).** Cada método que cambia algo o revela un valor recibe el
``OperationActor`` y registra su evento en el Servicio de Registro de Operaciones **dentro de su
propia transacción**, justo antes del ``commit`` (spec Fase 5 §5.4):

- ``create_secret``, ``rotate_secret``, ``update_secret`` y ``archive_secret``: si el registro
  falla, se revierte el cambio.
- ``read_secret_value``: ``read_secret`` se registra **antes de devolver el valor**. Si el
  registro o el ``commit`` fallan, el valor ya descifrado se borra con ``secure_zero`` y no se
  entrega (fail-closed).

Por eso el actor es obligatorio: ningún llamador puede revelar un valor sin dejar rastro.

Los valores llegan y salen como ``bytearray`` y pertenecen al llamador, que los borra con
``secure_zero`` al terminar (Algoritmo 2 del Cap. 6; H-13). Este servicio nunca los registra
(RNF-006): ``details`` solo lleva números de versión y nombres de campos.

Las consultas de metadatos (``get_secret``, ``list_secrets``, ``list_versions``) no se registran
(spec Fase 5 §5.2) ni la autorización se decide aquí: eso lo hace antes el API REST Gateway con
el Módulo RBAC (H-14).
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from portero.crypto.engine import CiphertextBundle, CryptoEngine, SecretContext
from portero.crypto.errors import CryptoIntegrityError
from portero.crypto.memory import secure_zero
from portero.db.models import Secret, SecretVersion
from portero.db.repositories.secret import SecretRepository
from portero.oplog.service import OperationActor, OperationLogService
from portero.secrets_mgmt.errors import (
    EnvironmentNotInProjectError,
    SecretNameConflictError,
    SecretNotFoundError,
)

_UNIQUE_ACTIVE_NAME = "uq_secrets_nombre_activo"


@dataclass(frozen=True)
class SecretVersionRef:
    """Identifica la versión creada (respuesta de CU-02 y CU-04, sin el valor)."""

    secret_id: uuid.UUID
    version_id: uuid.UUID
    version_number: int
    created_at: datetime


@dataclass(frozen=True)
class SecretMetadata:
    """Metadatos de un secreto, nunca su valor (spec Fase 5 §2). ``version`` es el número de la
    versión actual."""

    id: uuid.UUID
    name: str
    description: str | None
    version: int
    project_id: uuid.UUID
    environment_id: uuid.UUID
    created_at: datetime
    created_by: uuid.UUID
    updated_at: datetime


@dataclass(frozen=True)
class SecretVersionInfo:
    """Una versión del historial, sin ciphertext ni valor (spec Fase 5 §2; RF-006)."""

    version: int
    created_at: datetime
    created_by: uuid.UUID
    aead_algorithm: str


@dataclass(frozen=True)
class VersionPage:
    """Una página del historial. ``next_before`` es la clave del cursor siguiente (la última
    versión entregada), o ``None`` si no hay más (spec Fase 5 §1)."""

    items: list[SecretVersionInfo]
    next_before: int | None


def _metadata(secret: Secret, version: int) -> SecretMetadata:
    return SecretMetadata(
        id=secret.id,
        name=secret.name,
        description=secret.description,
        version=version,
        project_id=secret.project_id,
        environment_id=secret.environment_id,
        created_at=secret.created_at,
        created_by=secret.created_by,
        updated_at=secret.updated_at,
    )


def _human_id(actor: OperationActor) -> uuid.UUID:
    """``created_by`` de una versión: solo un humano escribe secretos (un service account solo
    tiene ``secrets:read``, spec núcleo §4); si no, es un error de programación."""
    if actor.actor_user_id is None:
        raise ValueError("escribir un secreto requiere un actor humano")
    return actor.actor_user_id


def _version_row(
    ctx: SecretContext, bundle: CiphertextBundle, created_by: uuid.UUID
) -> SecretVersion:
    """``CiphertextBundle`` → fila de ``secret_versions`` (mapeo 1:1, spec §1.4)."""
    return SecretVersion(
        id=uuid.uuid4(),
        secret_id=ctx.secret_id,
        version_number=ctx.version_number,
        ciphertext=bundle.ciphertext,
        nonce=bundle.nonce,
        auth_tag=bundle.auth_tag,
        aead_algorithm=bundle.aead_algorithm,
        wrapped_dek=bundle.wrapped_dek,
        wrap_algorithm=bundle.wrap_algorithm,
        kek_version_id=bundle.kek_version_id,
        created_by=created_by,
    )


def bundle_from_row(row: SecretVersion) -> CiphertextBundle:
    """Fila de ``secret_versions`` → ``CiphertextBundle``. Sin tag no hay autenticación."""
    if row.auth_tag is None:
        raise CryptoIntegrityError("el secreto cifrado no pasó la verificación de integridad")
    return CiphertextBundle(
        ciphertext=row.ciphertext,
        nonce=row.nonce,
        auth_tag=row.auth_tag,
        wrapped_dek=row.wrapped_dek,
        aead_algorithm=row.aead_algorithm,
        wrap_algorithm=row.wrap_algorithm,
        kek_version_id=row.kek_version_id,
    )


class SecretService:
    """Servicio de Gestión de Secretos (Cap. 5, diagrama de componentes).

    Cada método recibe la ``AsyncSession`` de la petición y confirma (o revierte) su propia
    transacción.
    """

    def __init__(self, crypto: CryptoEngine, oplog: OperationLogService | None = None) -> None:
        self._crypto = crypto
        self._oplog = oplog or OperationLogService()

    @staticmethod
    def wipe(value: bytearray) -> None:
        """Borra un valor en claro con ``secure_zero`` (Algoritmo 2 del Cap. 6; H-13). Existe
        para que el API REST Gateway borre sus ``bytearray`` sin importar el Motor
        Criptográfico (regla de capas: solo ``secrets_mgmt`` y ``auth`` usan ``crypto``)."""
        secure_zero(value)

    # --- Consultas de metadatos (sin registro, spec Fase 5 §5.2) --------------------------------

    async def get_secret(
        self, session: AsyncSession, secret_id: uuid.UUID
    ) -> SecretMetadata | None:
        """Metadatos del secreto activo (CU-03), o ``None`` si no existe, está archivado o su
        proyecto está archivado: el API responde 404 igual en los tres casos (spec §2)."""
        row = await SecretRepository(session).get_active_with_version(secret_id)
        return None if row is None else _metadata(*row)

    async def list_secrets(
        self, session: AsyncSession, project_id: uuid.UUID, environment_id: uuid.UUID
    ) -> list[SecretMetadata]:
        """Metadatos de los secretos activos del ambiente, por nombre (CU-03). Nunca valores."""
        repo = SecretRepository(session)
        rows = await repo.list_active_with_version(project_id, environment_id)
        return [_metadata(secret, version) for secret, version in rows]

    async def list_versions(
        self, session: AsyncSession, secret_id: uuid.UUID, *, limit: int, before: int | None
    ) -> VersionPage:
        """Historial de versiones paginado por cursor, de la más reciente a la más antigua
        (RF-006; spec Fase 5 §1). Pide ``limit + 1`` filas para saber si hay otra página."""
        rows = await SecretRepository(session).list_versions(
            secret_id, limit=limit + 1, before=before
        )
        items = [
            SecretVersionInfo(r.version_number, r.created_at, r.created_by, r.aead_algorithm)
            for r in rows[:limit]
        ]
        next_before = items[-1].version if len(rows) > limit else None
        return VersionPage(items, next_before)

    # --- Escrituras (registro en la misma transacción, H-11) ------------------------------------

    async def create_secret(
        self,
        session: AsyncSession,
        *,
        actor: OperationActor,
        project_id: uuid.UUID,
        environment_id: uuid.UUID,
        name: str,
        value: bytearray,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
        expires_at: datetime | None = None,
    ) -> SecretVersionRef:
        """Crea un secreto con su versión 1 y registra ``create_secret`` (CU-02; Algoritmo 1 del
        Cap. 6; H-10, H-11).

        Raises:
            EnvironmentNotInProjectError: el ambiente no es del proyecto.
            SecretNameConflictError: ya existe un secreto activo con ese nombre en el ambiente.
        """
        created_by = _human_id(actor)
        repo = SecretRepository(session)
        try:
            if not await repo.environment_belongs_to_project(project_id, environment_id):
                raise EnvironmentNotInProjectError("el ambiente no pertenece al proyecto")
            # Paso 6 de seq_crear_secreto. El índice único parcial cubre la carrera entre dos
            # creaciones simultáneas (ver el manejo de IntegrityError abajo).
            if await repo.active_name_exists(project_id, environment_id, name):
                raise SecretNameConflictError("ya existe un secreto activo con ese nombre")

            secret_id = uuid.uuid4()  # H-10: antes de cifrar, porque forma parte del AAD
            ctx = SecretContext(secret_id=secret_id, version_number=1)
            bundle = self._crypto.encrypt_secret(value, ctx=ctx)

            secret = Secret(
                id=secret_id,
                project_id=project_id,
                environment_id=environment_id,
                name=name,
                description=description,
                metadata_=metadata,
                expires_at=expires_at,
                created_by=created_by,
            )
            await repo.add_secret(secret)  # current_version_id aún NULL (Cap. 5)
            version = _version_row(ctx, bundle, created_by)
            await repo.add_version(version)
            await repo.set_current_version(secret, version.id)
            await session.refresh(version, ["created_at"])
            await self._oplog.record(
                session,
                actor.event(
                    "create_secret",
                    "success",
                    resource_type="secret",
                    resource_id=secret_id,
                    project_id=project_id,
                    environment_id=environment_id,
                ),
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_ACTIVE_NAME in str(exc.orig):
                raise SecretNameConflictError(
                    "ya existe un secreto activo con ese nombre"
                ) from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return SecretVersionRef(secret_id, version.id, 1, version.created_at)

    async def rotate_secret(
        self,
        session: AsyncSession,
        secret_id: uuid.UUID,
        new_value: bytearray,
        *,
        actor: OperationActor,
    ) -> SecretVersionRef:
        """Agrega la versión N+1 con una DEK nueva, la vuelve la actual y registra
        ``rotate_secret`` con ``{from_version, to_version}`` (CU-04; Algoritmo 3 del Cap. 6;
        RF-006; H-10, H-11; spec Fase 5 §5.3). Las versiones anteriores no se tocan.

        Raises:
            SecretNotFoundError: el secreto no existe o está archivado.
        """
        created_by = _human_id(actor)
        repo = SecretRepository(session)
        try:
            secret = await repo.get_secret_for_update(secret_id)  # bloquea la fila (H-10)
            if secret is None or secret.archived_at is not None:
                raise SecretNotFoundError("secreto no encontrado")

            current = await repo.max_version_number(secret_id)
            next_number = current + 1
            ctx = SecretContext(secret_id=secret_id, version_number=next_number)
            bundle = self._crypto.encrypt_secret(new_value, ctx=ctx)  # dentro de la transacción

            version = _version_row(ctx, bundle, created_by)
            await repo.add_version(version)
            await repo.set_current_version(secret, version.id)
            await session.refresh(version, ["created_at"])
            await self._oplog.record(
                session,
                actor.event(
                    "rotate_secret",
                    "success",
                    resource_type="secret",
                    resource_id=secret_id,
                    project_id=secret.project_id,
                    environment_id=secret.environment_id,
                    details={"from_version": current, "to_version": next_number},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return SecretVersionRef(secret_id, version.id, next_number, version.created_at)

    async def update_secret(
        self,
        session: AsyncSession,
        secret_id: uuid.UUID,
        changes: Mapping[str, str | None],
        *,
        actor: OperationActor,
    ) -> SecretMetadata:
        """Aplica un ``PATCH`` de metadatos (hoy solo ``description``; el valor solo cambia
        rotando, CU-04) y registra ``update_secret`` con los **nombres** de los campos
        cambiados, nunca sus valores (spec Fase 5 §5.3; H-11).

        Raises:
            SecretNotFoundError: el secreto no existe o está archivado.
        """
        repo = SecretRepository(session)
        try:
            secret = await repo.get_secret_for_update(secret_id)
            if secret is None or secret.archived_at is not None:
                raise SecretNotFoundError("secreto no encontrado")
            fields = sorted(k for k, v in changes.items() if getattr(secret, k) != v)
            for field in fields:
                setattr(secret, field, changes[field])
            await repo.flush()
            await session.refresh(secret)  # updated_at lo pone el trigger de la BD
            version = await repo.max_version_number(secret_id)  # la actual es siempre la mayor
            await self._oplog.record(
                session,
                actor.event(
                    "update_secret",
                    "success",
                    resource_type="secret",
                    resource_id=secret_id,
                    project_id=secret.project_id,
                    environment_id=secret.environment_id,
                    details={"fields": fields},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return _metadata(secret, version)

    async def archive_secret(
        self, session: AsyncSession, secret_id: uuid.UUID, *, actor: OperationActor
    ) -> None:
        """Archiva el secreto (``archived_at``; borrado lógico, spec Fase 5 §2) y registra
        ``archive_secret`` (H-11). Las versiones se conservan: la bitácora y la rotación de KEK
        las siguen necesitando. El nombre queda libre para un secreto nuevo.

        Raises:
            SecretNotFoundError: el secreto no existe o ya estaba archivado.
        """
        repo = SecretRepository(session)
        try:
            secret = await repo.get_secret_for_update(secret_id)
            if secret is None or secret.archived_at is not None:
                raise SecretNotFoundError("secreto no encontrado")
            await repo.archive(secret_id)
            await self._oplog.record(
                session,
                actor.event(
                    "archive_secret",
                    "success",
                    resource_type="secret",
                    resource_id=secret_id,
                    project_id=secret.project_id,
                    environment_id=secret.environment_id,
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

    # --- Lectura del valor (fail-closed, H-11) --------------------------------------------------

    async def read_secret_value(
        self,
        session: AsyncSession,
        secret_id: uuid.UUID,
        version_number: int | None = None,
        *,
        actor: OperationActor,
    ) -> bytearray:
        """Descifra la versión actual o una histórica y registra ``read_secret`` antes de
        devolverla (CU-03; Algoritmo 2 del Cap. 6; RF-006; H-11).

        Fail-closed: si el registro o el ``commit`` fallan, el valor descifrado se borra con
        ``secure_zero`` y se propaga la excepción; el valor nunca sale sin su registro. El
        llamador debe aplicar ``secure_zero`` al resultado después de usarlo (H-13).

        Raises:
            SecretNotFoundError: no existe el secreto, está archivado, o no existe esa versión.
            CryptoIntegrityError: la fila no autentica (alterada o intercambiada, H-05).
        """
        repo = SecretRepository(session)
        try:
            secret = await repo.get_secret(secret_id)
            if secret is None or secret.archived_at is not None:
                raise SecretNotFoundError("secreto no encontrado")

            if version_number is None:
                if secret.current_version_id is None:
                    raise SecretNotFoundError("secreto no encontrado")
                row = await repo.get_version_by_id(secret.current_version_id)
            else:
                row = await repo.get_version(secret_id, version_number)
            if row is None or row.secret_id != secret_id:
                raise SecretNotFoundError("versión no encontrada")

            ctx = SecretContext(secret_id=secret_id, version_number=row.version_number)
            plaintext = self._crypto.decrypt_secret(bundle_from_row(row), ctx=ctx)
        except BaseException:
            await session.rollback()
            raise
        try:
            await self._oplog.record(
                session,
                actor.event(
                    "read_secret",
                    "success",
                    resource_type="secret",
                    resource_id=secret_id,
                    project_id=secret.project_id,
                    environment_id=secret.environment_id,
                ),
            )
            await session.commit()  # el registro queda confirmado antes de entregar el valor
        except BaseException:
            secure_zero(plaintext)  # el valor no se entregará: se borra antes de propagar
            await session.rollback()
            raise
        return plaintext
