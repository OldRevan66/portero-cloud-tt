"""Datos de autorización del actor: ``LoadAssignments`` del Algoritmo 5 del Cap. 6 y registro de
las denegaciones (spec Fase 5 §4, §5.2–5.4; H-14; OWASP ASVS V4.1.3, V4.1.5).

El Módulo RBAC es puro y no lee la BD. Este servicio le prepara la entrada (las asignaciones
**vigentes** en ``user_role_assignments``, no el claim ``roles`` del JWT) y deja constancia de
cada ``access_denied``. El API REST Gateway lo usa desde su dependencia de autorización, sin
tocar repositorios.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.repositories.user import UserRepository
from portero.oplog.service import ClientInfo, OperationActor, OperationLogService
from portero.rbac.evaluator import Actor, RoleAssignment


@dataclass(frozen=True)
class ActorAccess:
    """Lo que la dependencia de autorización necesita del actor en cada petición."""

    assignments: tuple[RoleAssignment, ...]
    operation_actor: OperationActor


class AccessService:
    """Carga de asignaciones y registro de denegaciones."""

    def __init__(self, oplog: OperationLogService | None = None) -> None:
        self._oplog = oplog or OperationLogService()

    async def load(
        self, session: AsyncSession, actor_id: UUID, actor: Actor, client: ClientInfo
    ) -> ActorAccess:
        """Asignaciones vigentes y ``actor_ref`` del actor (spec Fase 5 §4, §5.3).

        - Humano: sus filas de ``user_role_assignments`` (un cambio de roles surte efecto en la
          siguiente petición) y su correo como ``actor_ref``.
        - Service account: sin asignaciones (lo evalúa su ``scope``) y ``actor_ref=sa:<id>``.
        """
        if actor.actor_type != "human":
            return ActorAccess((), OperationActor("service", f"sa:{actor_id}", None, client))
        users = UserRepository(session)
        rows = await users.get_assignments(actor_id)
        user = await users.get_by_id(actor_id)
        actor_ref = user.email if user is not None else str(actor_id)
        assignments = tuple(
            RoleAssignment(
                role_id=r.role_id, project_id=r.project_id, environment_id=r.environment_id
            )
            for r in rows
        )
        return ActorAccess(assignments, OperationActor("human", actor_ref, actor_id, client))

    async def record_denial(
        self,
        session: AsyncSession,
        actor: OperationActor,
        *,
        permission: str,
        status: int,
        resource_type: str,
        resource_id: UUID | None,
        project_id: UUID | None,
        environment_id: UUID | None = None,
    ) -> None:
        """Registra ``access_denied`` en **su propia transacción**, antes de responder 403 o 404
        (spec Fase 5 §5.4). ``details`` lleva el permiso y el estado HTTP, nunca los roles."""
        try:
            await session.commit()  # cierra la transacción de lectura de la petición
            await self._oplog.record(
                session,
                actor.event(
                    "access_denied",
                    "failure",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    details={"permission": permission, "status": status},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
