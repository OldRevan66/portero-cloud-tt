"""Servicios de Gestión: casos de uso de proyectos (CU-07; RF-030 a RF-032; spec Fase 5 §2).

No saben nada de HTTP ni de permisos: la autorización (Algoritmo 5, H-14) ya la decidió el API
REST Gateway. Cada escritura se registra en el Servicio de Registro de Operaciones **en la misma
transacción** que el cambio, justo antes del ``commit`` (spec Fase 5 §5.4; H-11): si el registro
falla, el cambio se revierte.

Cada método controla su transacción (``commit`` o ``rollback``), como ``SecretService``.
"""

from collections.abc import Collection, Mapping, Sequence
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import Environment, Project
from portero.db.repositories.project import ProjectRepository
from portero.db.repositories.secret import SecretRepository
from portero.management.errors import ProjectHasActiveSecretsError, ProjectNameConflictError
from portero.oplog.service import OperationActor, OperationLogService

DEFAULT_ENVIRONMENTS = ("development", "staging", "production")
"""Ambientes que se crean junto con cada proyecto (RF-031)."""

_UNIQUE_NAME = "uq_projects_name"


class ProjectService:
    """Servicio de Gestión de proyectos (Cap. 5, diagrama de componentes: Servicios de Gestión)."""

    def __init__(self, oplog: OperationLogService | None = None) -> None:
        self._oplog = oplog or OperationLogService()

    async def list_projects(
        self, session: AsyncSession, ids: Collection[UUID] | None
    ) -> Sequence[Project]:
        """Proyectos no archivados; ``ids=None`` = todos, si no, solo los visibles (H-23c)."""
        return await ProjectRepository(session).list_active(ids)

    async def get_project(self, session: AsyncSession, project_id: UUID) -> Project | None:
        """Proyecto no archivado, o ``None`` (inexistente y archivado se tratan igual, spec §2)."""
        return await ProjectRepository(session).get_active(project_id)

    async def create_project(
        self,
        session: AsyncSession,
        actor: OperationActor,
        *,
        name: str,
        description: str | None,
    ) -> Project:
        """Crea el proyecto con sus tres ambientes en una transacción (RF-030, RF-031) y
        registra ``create_project``.

        Raises:
            ProjectNameConflictError: el nombre ya existe en la instancia.
        """
        if actor.actor_user_id is None:
            # Solo un humano tiene projects:manage de instancia; un PAT no llega aquí.
            raise ValueError("crear un proyecto requiere un actor humano")
        repo = ProjectRepository(session)
        try:
            if await repo.name_exists(name):
                raise ProjectNameConflictError("ya existe un proyecto con ese nombre")
            project = Project(name=name, description=description, created_by=actor.actor_user_id)
            await repo.add(project)
            for env_name in DEFAULT_ENVIRONMENTS:
                await repo.add_environment(Environment(project_id=project.id, name=env_name))
            await self._oplog.record(
                session,
                actor.event(
                    "create_project",
                    "success",
                    resource_type="project",
                    resource_id=project.id,
                    project_id=project.id,
                ),
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_NAME in str(exc.orig):  # carrera entre dos altas con el mismo nombre
                raise ProjectNameConflictError("ya existe un proyecto con ese nombre") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return project

    async def update_project(
        self,
        session: AsyncSession,
        actor: OperationActor,
        project: Project,
        changes: Mapping[str, str | None],
    ) -> Project:
        """Aplica un ``PATCH`` (``name``, ``description``) y registra ``update_project`` con los
        **nombres** de los campos cambiados, nunca sus valores (spec Fase 5 §5.3).

        Raises:
            ProjectNameConflictError: el nombre nuevo ya lo usa otro proyecto.
        """
        repo = ProjectRepository(session)
        try:
            new_name = changes.get("name")
            if new_name is not None and await repo.name_exists(new_name, exclude_id=project.id):
                raise ProjectNameConflictError("ya existe un proyecto con ese nombre")
            fields = sorted(k for k, v in changes.items() if getattr(project, k) != v)
            for field in fields:
                setattr(project, field, changes[field])
            await repo.flush()
            await self._oplog.record(
                session,
                actor.event(
                    "update_project",
                    "success",
                    resource_type="project",
                    resource_id=project.id,
                    project_id=project.id,
                    details={"fields": fields},
                ),
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_NAME in str(exc.orig):
                raise ProjectNameConflictError("ya existe un proyecto con ese nombre") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        await session.refresh(project)  # updated_at lo pone el trigger de la BD
        return project

    async def archive_project(
        self, session: AsyncSession, actor: OperationActor, project_id: UUID, *, confirm: bool
    ) -> bool:
        """Archiva el proyecto (``archived_at``, RF-032) y registra ``archive_project``.

        Si tiene secretos activos exige ``confirm`` y los archiva en la misma transacción. Bloquea
        la fila del proyecto para serializarse con otras escrituras sobre él.

        Returns:
            ``False`` si el proyecto ya no existe o ya estaba archivado (carrera con otro
            archivado); quien llama responde 404.

        Raises:
            ProjectHasActiveSecretsError: hay secretos activos y no se confirmó.
        """
        repo = ProjectRepository(session)
        secrets = SecretRepository(session)
        try:
            project = await repo.get_active_for_update(project_id)
            if project is None:
                await session.rollback()
                return False
            active = await secrets.count_active_in_project(project_id)
            if active and not confirm:
                raise ProjectHasActiveSecretsError(
                    "el proyecto tiene secretos activos; confirma el archivado"
                )
            archived = await secrets.archive_active_in_project(project_id) if active else 0
            await repo.archive(project_id)
            await self._oplog.record(
                session,
                actor.event(
                    "archive_project",
                    "success",
                    resource_type="project",
                    resource_id=project_id,
                    project_id=project_id,
                    details={"archived_secrets": archived},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return True
