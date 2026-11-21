"""``SecretRepository`` y ``KekVersionRepository``: secretos, versiones cifradas y versiones de
KEK (Capa de Persistencia, Cap. 5 §Componentes).

Los servicios no ejecutan SQL directo: todo acceso a ``secrets``, ``secret_versions`` y
``kek_versions`` pasa por aquí. Las consultas usan el constructor de SQLAlchemy con parámetros
enlazados, nunca cadenas concatenadas (OWASP ASVS V5.3.4; riesgo P-04 del Cap. 5).

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy import Select, exists, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import Environment, KekVersion, Project, Secret, SecretVersion


class SecretRepository:
    """Acceso a ``secrets`` y ``secret_versions`` (Cap. 5 §Tablas secrets y secret_versions)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def environment_belongs_to_project(
        self, project_id: uuid.UUID, environment_id: uuid.UUID
    ) -> bool:
        """Valida en aplicación que el ambiente es del proyecto (Cap. 5; spec §2)."""
        stmt = select(
            exists().where(Environment.id == environment_id, Environment.project_id == project_id)
        )
        return bool(await self._session.scalar(stmt))

    async def active_name_exists(
        self, project_id: uuid.UUID, environment_id: uuid.UUID, name: str
    ) -> bool:
        """¿Hay un secreto no archivado con ese nombre en el ambiente? (paso 6 de CU-02)."""
        stmt = select(
            exists().where(
                Secret.project_id == project_id,
                Secret.environment_id == environment_id,
                Secret.name == name,
                Secret.archived_at.is_(None),
            )
        )
        return bool(await self._session.scalar(stmt))

    async def count_active_in_project(self, project_id: uuid.UUID) -> int:
        """Secretos no archivados del proyecto (RF-032: archivar exige confirmación si hay)."""
        stmt = select(func.count()).where(
            Secret.project_id == project_id, Secret.archived_at.is_(None)
        )
        return int(await self._session.scalar(stmt) or 0)

    async def archive_active_in_project(self, project_id: uuid.UUID) -> int:
        """``archived_at = now()`` en los secretos activos del proyecto (RF-032). Devuelve
        cuántos archivó."""
        result = await self._session.execute(
            update(Secret)
            .where(Secret.project_id == project_id, Secret.archived_at.is_(None))
            .values(archived_at=func.now())
            .returning(Secret.id)
            .execution_options(synchronize_session=False)
        )
        return len(result.scalars().all())

    async def environment_has_secrets(self, environment_id: uuid.UUID) -> bool:
        """¿El ambiente tiene secretos, activos **o archivados**? (H-39: sin CASCADE)."""
        stmt = select(exists().where(Secret.environment_id == environment_id))
        return bool(await self._session.scalar(stmt))

    async def add_secret(self, secret: Secret) -> None:
        """Inserta la fila de ``secrets`` y la envía a la BD (``flush``) sin confirmar."""
        self._session.add(secret)
        await self._session.flush()

    async def add_version(self, version: SecretVersion) -> None:
        """Inserta una fila de ``secret_versions`` y la envía a la BD sin confirmar."""
        self._session.add(version)
        await self._session.flush()

    async def set_current_version(self, secret: Secret, version_id: uuid.UUID) -> None:
        """``UPDATE secrets SET current_version_id = ...`` (denormalización del Cap. 5).

        ``updated_at`` lo actualiza el trigger de la base.
        """
        secret.current_version_id = version_id
        await self._session.flush()

    async def get_secret(self, secret_id: uuid.UUID) -> Secret | None:
        """Secreto por id, sin bloqueo."""
        return await self._session.get(Secret, secret_id)

    def _active_with_version(self) -> Select[tuple[Secret, int]]:
        """Secretos no archivados, de proyectos no archivados, con el número de su versión
        actual (``current_version_id`` → ``secret_versions.version_number``; spec Fase 5 §2)."""
        return (
            select(Secret, SecretVersion.version_number)
            .join(SecretVersion, SecretVersion.id == Secret.current_version_id)
            .join(Project, Project.id == Secret.project_id)
            .where(Secret.archived_at.is_(None), Project.archived_at.is_(None))
            .execution_options(populate_existing=True)
        )

    async def get_active_with_version(self, secret_id: uuid.UUID) -> tuple[Secret, int] | None:
        """El secreto activo y el número de su versión actual, o ``None`` si no existe, está
        archivado o su proyecto está archivado (los tres casos responden 404, spec §2)."""
        stmt = self._active_with_version().where(Secret.id == secret_id)
        row = (await self._session.execute(stmt)).one_or_none()
        return None if row is None else (row[0], row[1])

    async def list_active_with_version(
        self, project_id: uuid.UUID, environment_id: uuid.UUID
    ) -> list[tuple[Secret, int]]:
        """Secretos activos del ambiente con su versión actual, ordenados por nombre (CU-03)."""
        stmt = (
            self._active_with_version()
            .where(Secret.project_id == project_id, Secret.environment_id == environment_id)
            .order_by(Secret.name)
        )
        return [(s, n) for s, n in (await self._session.execute(stmt)).tuples()]

    async def list_versions(
        self, secret_id: uuid.UUID, *, limit: int, before: int | None
    ) -> Sequence[SecretVersion]:
        """Hasta ``limit`` versiones del secreto, de la más reciente a la más antigua, con
        ``version_number < before`` si se da (paginación por cursor, spec Fase 5 §1)."""
        stmt = select(SecretVersion).where(SecretVersion.secret_id == secret_id)
        if before is not None:
            stmt = stmt.where(SecretVersion.version_number < before)
        stmt = stmt.order_by(SecretVersion.version_number.desc()).limit(limit)
        return (await self._session.execute(stmt)).scalars().all()

    async def archive(self, secret_id: uuid.UUID) -> None:
        """``archived_at = now()`` (archivado lógico; el nombre queda libre por el índice único
        parcial ``uq_secrets_nombre_activo``)."""
        await self._session.execute(
            update(Secret)
            .where(Secret.id == secret_id)
            .values(archived_at=func.now())
            .execution_options(synchronize_session=False)
        )

    async def flush(self) -> None:
        """Envía a la BD los cambios pendientes (p. ej. la descripción) sin confirmar."""
        await self._session.flush()

    async def get_secret_for_update(self, secret_id: uuid.UUID) -> Secret | None:
        """``SELECT ... FROM secrets WHERE id = :id FOR UPDATE`` (H-10).

        Bloquea la fila hasta el fin de la transacción: una segunda rotación simultánea espera
        aquí y, al continuar, ya ve la versión que confirmó la primera. ``populate_existing``
        refresca el objeto si ya estaba en la sesión.
        """
        stmt = (
            select(Secret)
            .where(Secret.id == secret_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def max_version_number(self, secret_id: uuid.UUID) -> int:
        """Número de versión más alto del secreto (0 si no tiene versiones)."""
        stmt = select(func.coalesce(func.max(SecretVersion.version_number), 0)).where(
            SecretVersion.secret_id == secret_id
        )
        return int(await self._session.scalar(stmt) or 0)

    async def get_version(self, secret_id: uuid.UUID, version_number: int) -> SecretVersion | None:
        """Una versión concreta del historial (RF-006)."""
        stmt = select(SecretVersion).where(
            SecretVersion.secret_id == secret_id, SecretVersion.version_number == version_number
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_version_by_id(self, version_id: uuid.UUID) -> SecretVersion | None:
        """Versión por id (para seguir ``secrets.current_version_id``, CU-03)."""
        return await self._session.get(SecretVersion, version_id)

    async def lock_versions_for_kek_rotation(self) -> None:
        """``LOCK TABLE secret_versions IN EXCLUSIVE MODE`` hasta el fin de la transacción (H-40).

        Bloquea ``INSERT``/``UPDATE``/``DELETE`` de otras transacciones (y ``SELECT ... FOR
        UPDATE``), pero permite las lecturas simples. Así ninguna versión nueva, envuelta con la
        KEK vieja, se cuela mientras la rotación de KEK re-envuelve todas las DEKs.
        """
        await self._session.execute(text("LOCK TABLE secret_versions IN EXCLUSIVE MODE"))

    async def list_all_versions(self) -> Sequence[SecretVersion]:
        """Todas las filas de ``secret_versions``, de todos los secretos (incluidos los
        archivados): la rotación de KEK debe re-envolverlas todas (H-07)."""
        stmt = (
            select(SecretVersion)
            .order_by(SecretVersion.secret_id, SecretVersion.version_number)
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def set_wrapped_dek(
        self,
        version: SecretVersion,
        *,
        wrapped_dek: bytes,
        wrap_algorithm: str,
        kek_version_id: uuid.UUID,
    ) -> None:
        """``UPDATE`` de la envoltura de una versión (H-07). El valor cifrado no se toca."""
        version.wrapped_dek = wrapped_dek
        version.wrap_algorithm = wrap_algorithm
        version.kek_version_id = kek_version_id
        await self._session.flush()


class KekVersionRepository:
    """Acceso a ``kek_versions`` (Cap. 5 §Tabla kek_versions; H-06).

    Devuelve filas ORM; la traducción al ``KekVersionStore`` del Motor Criptográfico la hace
    ``portero.secrets_mgmt.kek_store``, porque la Capa de Persistencia no importa ``crypto``.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_active(self) -> KekVersion | None:
        """Versión con ``deactivated_at IS NULL`` (a lo más una, por índice único parcial)."""
        stmt = select(KekVersion).where(KekVersion.deactivated_at.is_(None))
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_active_for_update(self) -> KekVersion | None:
        """``SELECT ... WHERE deactivated_at IS NULL FOR UPDATE`` (H-07).

        Dos rotaciones de KEK simultáneas se serializan aquí: la segunda espera y, al continuar,
        ya ve la versión que dejó activa la primera (y su passphrase actual ya no es la de antes).
        """
        stmt = (
            select(KekVersion)
            .where(KekVersion.deactivated_at.is_(None))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def add(self, kek_version: KekVersion) -> None:
        """Inserta una versión y la envía a la BD sin confirmar."""
        self._session.add(kek_version)
        await self._session.flush()

    async def deactivate(self, kek_version_id: uuid.UUID) -> None:
        """``deactivated_at = now()`` (hora de la transacción, como ``activated_at``).

        Debe ir antes de insertar la versión nueva: el índice único parcial
        ``uq_kek_versions_una_activa`` (H-18) no admite dos versiones activas ni por un momento.
        """
        await self._session.execute(
            update(KekVersion)
            .where(KekVersion.id == kek_version_id)
            .values(deactivated_at=func.now())
            .execution_options(synchronize_session=False)
        )
