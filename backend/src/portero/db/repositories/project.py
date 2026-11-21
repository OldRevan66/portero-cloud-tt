"""``ProjectRepository``: proyectos y ambientes (Capa de Persistencia, Cap. 5 §Componentes;
RF-030 a RF-032).

Todo acceso a ``projects`` y ``environments`` pasa por aquí. Las consultas usan el constructor de
SQLAlchemy con parámetros enlazados, nunca cadenas concatenadas (OWASP ASVS V5.3.4; riesgo P-04
del Cap. 5). Las asignaciones del actor ya las lee ``UserRepository.get_assignments``.

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

import uuid
from collections.abc import Collection, Sequence

from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import Environment, Project


class ProjectRepository:
    """Acceso a ``projects`` y ``environments`` (Cap. 5 §Tablas projects y environments)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- Proyectos ---

    async def get_active(self, project_id: uuid.UUID) -> Project | None:
        """Proyecto no archivado por id. Uno archivado se trata como inexistente (spec §2)."""
        stmt = (
            select(Project)
            .where(Project.id == project_id, Project.archived_at.is_(None))
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_active_for_update(self, project_id: uuid.UUID) -> Project | None:
        """``SELECT ... FOR UPDATE`` del proyecto no archivado: serializa el archivado con
        otras escrituras sobre el mismo proyecto."""
        stmt = (
            select(Project)
            .where(Project.id == project_id, Project.archived_at.is_(None))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_active(self, ids: Collection[uuid.UUID] | None) -> Sequence[Project]:
        """Proyectos no archivados, por nombre. ``ids=None`` = todos (Administrador de
        instancia); si no, solo esos (filtrado de ``GET /projects``, H-23c)."""
        stmt = select(Project).where(Project.archived_at.is_(None)).order_by(Project.name)
        if ids is not None:
            if not ids:
                return []
            stmt = stmt.where(Project.id.in_(ids))
        return (await self._session.execute(stmt)).scalars().all()

    async def name_exists(self, name: str, *, exclude_id: uuid.UUID | None = None) -> bool:
        """¿Hay otro proyecto con ese nombre? ``projects.name`` es UNIQUE en la instancia,
        también frente a los archivados (RF-030)."""
        condicion = Project.name == name
        if exclude_id is not None:
            condicion = condicion & (Project.id != exclude_id)
        return bool(await self._session.scalar(select(exists().where(condicion))))

    async def add(self, project: Project) -> None:
        """Inserta un proyecto y lo envía a la BD sin confirmar."""
        self._session.add(project)
        await self._session.flush()

    async def archive(self, project_id: uuid.UUID) -> None:
        """``archived_at = now()``: archivado lógico, la fila no se borra (RF-032)."""
        await self._session.execute(
            update(Project)
            .where(Project.id == project_id)
            .values(archived_at=func.now())
            .execution_options(synchronize_session=False)
        )

    # --- Ambientes ---

    async def list_environments(self, project_id: uuid.UUID) -> Sequence[Environment]:
        """Ambientes del proyecto, por nombre."""
        stmt = (
            select(Environment)
            .where(Environment.project_id == project_id)
            .order_by(Environment.name)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def get_environment(
        self, project_id: uuid.UUID, environment_id: uuid.UUID
    ) -> Environment | None:
        """Ambiente por id, solo si pertenece al proyecto (validación en aplicación, Cap. 5)."""
        stmt = (
            select(Environment)
            .where(Environment.id == environment_id, Environment.project_id == project_id)
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def lock_environment(self, environment_id: uuid.UUID) -> Environment | None:
        """``SELECT ... FOR UPDATE`` del ambiente (H-49). Serializa su borrado con los INSERT de
        secretos y service accounts, que toman ``FOR KEY SHARE`` sobre esta fila por la FK."""
        stmt = (
            select(Environment)
            .where(Environment.id == environment_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def environment_name_exists(
        self, project_id: uuid.UUID, name: str, *, exclude_id: uuid.UUID | None = None
    ) -> bool:
        """¿Hay otro ambiente con ese nombre en el proyecto? (UNIQUE (project_id, name))."""
        condicion = (Environment.project_id == project_id) & (Environment.name == name)
        if exclude_id is not None:
            condicion = condicion & (Environment.id != exclude_id)
        return bool(await self._session.scalar(select(exists().where(condicion))))

    async def add_environment(self, environment: Environment) -> None:
        """Inserta un ambiente y lo envía a la BD sin confirmar."""
        self._session.add(environment)
        await self._session.flush()

    async def delete_environment(self, environment_id: uuid.UUID) -> None:
        """Borrado físico del ambiente (H-39). Quien llama comprueba antes que no tenga
        secretos; las asignaciones y service accounts del ambiente caen por CASCADE."""
        await self._session.execute(
            delete(Environment)
            .where(Environment.id == environment_id)
            .execution_options(synchronize_session=False)
        )

    async def flush(self) -> None:
        """Envía a la BD los cambios pendientes de objetos ya cargados (p. ej. un ``PATCH``)."""
        await self._session.flush()
