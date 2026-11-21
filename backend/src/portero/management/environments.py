"""Servicios de Gestión: casos de uso de ambientes de un proyecto (CU-07; RF-031; spec Fase 5
§2; H-39).

Igual que ``management.projects``: sin HTTP ni permisos, y cada escritura se registra en el
Servicio de Registro de Operaciones en la misma transacción que el cambio (H-11). El registro
lleva ``project_id`` y ``environment_id`` del ambiente (spec Fase 5 §5.3).

**H-39.** ``environments`` no tiene ``archived_at`` y ``secrets.environment_id`` no tiene
CASCADE: un ambiente se borra físicamente solo si no tiene secretos, ni activos ni archivados.

**H-41.** ``service_accounts.environment_id`` y ``user_role_assignments.environment_id`` sí
tienen CASCADE. Para que el borrado no se lleve en silencio el estado administrativo: con alguna
service account (vigente o revocada) → 409, igual que H-39; las asignaciones de rol del ambiente
sí caen, y ``delete_environment`` registra cuántas en ``details``.
"""

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import Environment
from portero.db.repositories.project import ProjectRepository
from portero.db.repositories.secret import SecretRepository
from portero.db.repositories.service_account import ServiceAccountRepository
from portero.db.repositories.user import UserRepository
from portero.management.errors import (
    EnvironmentHasSecretsError,
    EnvironmentHasServiceAccountsError,
    EnvironmentNameConflictError,
)
from portero.oplog.service import OperationActor, OperationEvent, OperationLogService

_UNIQUE_NAME = "uq_environments_project_id_name"


class EnvironmentService:
    """Servicio de Gestión de ambientes (Cap. 5, diagrama de componentes: Servicios de Gestión)."""

    def __init__(self, oplog: OperationLogService | None = None) -> None:
        self._oplog = oplog or OperationLogService()

    async def list_environments(
        self, session: AsyncSession, project_id: UUID
    ) -> Sequence[Environment]:
        """Todos los ambientes del proyecto; el filtrado por permisos (H-23d) lo hace la API."""
        return await ProjectRepository(session).list_environments(project_id)

    async def get_environment(
        self, session: AsyncSession, project_id: UUID, environment_id: UUID
    ) -> Environment | None:
        """El ambiente, solo si pertenece al proyecto; si no, ``None`` (→ 404)."""
        return await ProjectRepository(session).get_environment(project_id, environment_id)

    async def create_environment(
        self,
        session: AsyncSession,
        actor: OperationActor,
        project_id: UUID,
        *,
        name: str,
        description: str | None,
    ) -> Environment:
        """Crea un ambiente en el proyecto y registra ``create_environment``.

        Raises:
            EnvironmentNameConflictError: el proyecto ya tiene un ambiente con ese nombre.
        """
        repo = ProjectRepository(session)
        try:
            if await repo.environment_name_exists(project_id, name):
                raise EnvironmentNameConflictError("ya existe un ambiente con ese nombre")
            environment = Environment(project_id=project_id, name=name, description=description)
            await repo.add_environment(environment)
            await self._oplog.record(session, _event(actor, "create_environment", environment))
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_NAME in str(exc.orig):
                raise EnvironmentNameConflictError("ya existe un ambiente con ese nombre") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return environment

    async def update_environment(
        self,
        session: AsyncSession,
        actor: OperationActor,
        environment: Environment,
        changes: Mapping[str, str | None],
    ) -> Environment:
        """Aplica un ``PATCH`` (``name``, ``description``) y registra ``update_environment``
        con los nombres de los campos cambiados (spec Fase 5 §5.3).

        Raises:
            EnvironmentNameConflictError: el nombre nuevo ya existe en el proyecto.
        """
        repo = ProjectRepository(session)
        try:
            new_name = changes.get("name")
            if new_name is not None and await repo.environment_name_exists(
                environment.project_id, new_name, exclude_id=environment.id
            ):
                raise EnvironmentNameConflictError("ya existe un ambiente con ese nombre")
            fields = sorted(k for k, v in changes.items() if getattr(environment, k) != v)
            for field in fields:
                setattr(environment, field, changes[field])
            await repo.flush()
            await self._oplog.record(
                session,
                _event(actor, "update_environment", environment, details={"fields": fields}),
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_NAME in str(exc.orig):
                raise EnvironmentNameConflictError("ya existe un ambiente con ese nombre") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return environment

    async def delete_environment(
        self, session: AsyncSession, actor: OperationActor, environment: Environment
    ) -> None:
        """Borra físicamente el ambiente si no tiene secretos (H-39) ni service accounts
        (H-41) y registra ``delete_environment`` con las asignaciones de rol que caen por
        CASCADE: ``details={"removed_role_assignments": n}``.

        **H-49.** Primero bloquea la fila del ambiente (``FOR UPDATE``). Sin eso, una service
        account o un secreto creados entre la comprobación y el ``DELETE`` no se verían: la
        service account caería por CASCADE sin registro (reabre H-41) y el secreto daría un 500
        por la FK. Con el bloqueo, un INSERT concurrente espera o hace esperar al borrado, y la
        comprobación ve lo ya confirmado. Si otra petición ya lo borró, no hay nada que hacer.

        Raises:
            EnvironmentHasSecretsError: el ambiente tiene secretos, activos o archivados.
            EnvironmentHasServiceAccountsError: alguna service account apunta al ambiente.
        """
        try:
            if await ProjectRepository(session).lock_environment(environment.id) is None:
                await session.rollback()  # otra petición lo borró primero
                return
            if await SecretRepository(session).environment_has_secrets(environment.id):
                raise EnvironmentHasSecretsError("el ambiente tiene secretos")
            if await ServiceAccountRepository(session).exists_in_environment(environment.id):
                raise EnvironmentHasServiceAccountsError(
                    "el ambiente tiene o tuvo aplicaciones cliente y no se puede eliminar"
                )
            removed = await UserRepository(session).count_assignments_in_environment(environment.id)
            await ProjectRepository(session).delete_environment(environment.id)
            await self._oplog.record(
                session,
                _event(
                    actor,
                    "delete_environment",
                    environment,
                    details={"removed_role_assignments": removed},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


def _event(
    actor: OperationActor,
    verb: str,
    environment: Environment,
    *,
    details: dict[str, Any] | None = None,
) -> OperationEvent:
    """Evento de escritura sobre un ambiente, con su proyecto y su id como contexto."""
    return actor.event(
        verb,
        "success",
        resource_type="environment",
        resource_id=environment.id,
        project_id=environment.project_id,
        environment_id=environment.id,
        details=details,
    )
