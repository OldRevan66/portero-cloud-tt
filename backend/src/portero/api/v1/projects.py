"""Endpoints de proyectos y ambientes del API REST Gateway (CU-07; Cap. 6, tabla "Catálogo
maestro"; spec Fase 5 §2, §4.1, §4.2; RF-030 a RF-032; H-14, H-23c, H-23d, H-39).

Cada ruta sigue el mismo orden (spec Fase 5 §4):

1. Cargar el recurso (proyecto, y ambiente si aplica). Si no existe o está archivado → 404 sin
   registro (no hay recurso que proteger, spec §5.2).
2. Decidir la visibilidad: un proyecto es visible si el actor cubre el proyecto o alguno de sus
   ambientes (H-23d); un ambiente, si el actor tiene ``secrets:read`` en él.
3. ``Authorizer.require`` con el permiso de la tabla maestra: 404 si no es visible, 403 si lo es
   pero falta el permiso (H-14). Ambas denegaciones se registran como ``access_denied``.
4. Llamar al Servicio de Gestión, que registra la escritura en su misma transacción (H-11).

Los routers no tienen lógica de negocio ni tocan repositorios. Algoritmo 5 del Cap. 6; OWASP
ASVS V4.1.3 y V4.1.5.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from portero.api.deps import Authorizer, AuthorizerDep, SessionDep
from portero.api.errors import ApiProblem, problem_responses
from portero.api.params import CanonicalUUID, PlainText
from portero.db.models import Environment, Project
from portero.management.environments import EnvironmentService
from portero.management.errors import ConflictError
from portero.management.projects import ProjectService
from portero.rbac.evaluator import ALL_PROJECTS, AccessContext
from portero.rbac.permissions import Permission

router = APIRouter(prefix="/projects", tags=["proyectos"])

_projects = ProjectService()
_environments = EnvironmentService()

_Description = Annotated[PlainText | None, Field(max_length=1024)]


# --- Esquemas ------------------------------------------------------------------------------------


def _not_null(value: str | None) -> str:
    """En un ``PATCH`` se puede omitir ``name``, pero no enviarlo como ``null`` (NOT NULL)."""
    if value is None:
        raise ValueError("name no puede ser nulo")
    return value


class ProjectCreate(BaseModel):
    """Cuerpo de ``POST /projects``. ``extra="forbid"``: un campo de más → 400 (spec §1)."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText = Field(min_length=1, max_length=128)
    description: _Description = None


class ProjectUpdate(BaseModel):
    """Cuerpo de ``PATCH /projects/{pid}``: solo los campos enviados se actualizan."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText | None = Field(default=None, min_length=1, max_length=128)
    description: _Description = None

    _name_not_null = field_validator("name")(_not_null)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class EnvironmentCreate(BaseModel):
    """Cuerpo de ``POST /projects/{pid}/environments``."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText = Field(min_length=1, max_length=64)
    description: _Description = None


class EnvironmentUpdate(BaseModel):
    """Cuerpo de ``PATCH /projects/{pid}/environments/{eid}``."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText | None = Field(default=None, min_length=1, max_length=64)
    description: _Description = None

    _name_not_null = field_validator("name")(_not_null)


class EnvironmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    name: str
    description: str | None
    created_at: datetime


# --- Auxiliares ----------------------------------------------------------------------------------


def _conflict(exc: ConflictError) -> ApiProblem:
    """409 ``conflict``; los mensajes de ``management.errors`` no llevan datos internos."""
    return ApiProblem(409, "conflict", str(exc))


async def _load_project(session: SessionDep, project_id: UUID) -> Project:
    """Paso 1: el proyecto no archivado, o 404 sin registro (inexistente o archivado)."""
    project = await _projects.get_project(session, project_id)
    if project is None:
        raise ApiProblem(404, "resource-not-found")
    return project


async def _authorize_project(authz: Authorizer, project_id: UUID, permission: Permission) -> None:
    """Pasos 2 y 3 para operaciones con alcance de proyecto (tabla maestra)."""
    await authz.require(
        permission,
        AccessContext(project_id=project_id, environment_id=None),
        visible=authz.sees_project(project_id),
        resource_type="project",
        resource_id=project_id,
    )


async def _load_environment_for_management(
    session: SessionDep, authz: Authorizer, project_id: UUID, environment_id: UUID
) -> Environment:
    """``PATCH``/``DELETE`` de un ambiente: ``projects:manage`` con alcance de proyecto.

    El ambiente es visible si el actor tiene ``secrets:read`` en él (spec §4.1); uno que no
    pertenece al proyecto de la ruta no existe para esa ruta (404 sin registro).
    """
    await _load_project(session, project_id)
    environment = await _environments.get_environment(session, project_id, environment_id)
    if environment is None:
        raise ApiProblem(404, "resource-not-found")
    env_ctx = AccessContext(project_id=project_id, environment_id=environment_id)
    if not authz.allows(Permission.PROJECTS_MANAGE, AccessContext(project_id, None)):
        await authz.deny(
            403 if authz.allows(Permission.SECRETS_READ, env_ctx) else 404,
            Permission.PROJECTS_MANAGE,
            resource_type="environment",
            resource_id=environment_id,
            project_id=project_id,
            environment_id=environment_id,
        )
    return environment


# --- Proyectos -----------------------------------------------------------------------------------


@router.post(
    "",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un proyecto",
    responses=problem_responses(403, 409),
)
async def create_project(body: ProjectCreate, session: SessionDep, authz: AuthorizerDep) -> Project:
    """CU-07: crea un proyecto con sus ambientes ``development``, ``staging`` y ``production``
    (RF-030, RF-031). ``projects:manage`` con alcance de instancia: solo el Administrador."""
    await authz.require(
        Permission.PROJECTS_MANAGE,
        AccessContext(project_id=None, environment_id=None),
        visible=True,  # no hay recurso que ocultar: la denegación es 403
        resource_type="project",
        resource_id=None,
    )
    try:
        return await _projects.create_project(
            session, authz.operation_actor, name=body.name, description=body.description
        )
    except ConflictError as exc:
        raise _conflict(exc) from None


@router.get("", response_model=list[ProjectOut], summary="Listar los proyectos visibles")
async def list_projects(session: SessionDep, authz: AuthorizerDep) -> list[Project]:
    """CU-07: proyectos visibles para el actor (H-23c), sin los archivados. Es un filtrado, no
    una evaluación puntual: sin asignaciones, la lista sale vacía."""
    visibles = authz.visible_projects()
    ids = None if visibles is ALL_PROJECTS else visibles
    return list(await _projects.list_projects(session, ids))


@router.get(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Consultar un proyecto",
    responses=problem_responses(404),
)
async def get_project(
    project_id: CanonicalUUID, session: SessionDep, authz: AuthorizerDep
) -> Project:
    """CU-07: un proyecto, si el actor cubre el proyecto o alguno de sus ambientes (H-23d); si
    no, 404 igual al de un proyecto inexistente (H-14)."""
    project = await _load_project(session, project_id)
    if not authz.sees_project(project_id):
        await authz.deny(
            404,
            Permission.SECRETS_READ,
            resource_type="project",
            resource_id=project_id,
            project_id=project_id,
        )
    return project


@router.patch(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Actualizar un proyecto",
    responses=problem_responses(403, 404, 409),
)
async def update_project(
    project_id: CanonicalUUID, body: ProjectUpdate, session: SessionDep, authz: AuthorizerDep
) -> Project:
    """CU-07: actualiza nombre o descripción. ``projects:manage`` en el proyecto."""
    project = await _load_project(session, project_id)
    await _authorize_project(authz, project_id, Permission.PROJECTS_MANAGE)
    try:
        return await _projects.update_project(
            session, authz.operation_actor, project, body.model_dump(exclude_unset=True)
        )
    except ConflictError as exc:
        raise _conflict(exc) from None


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archivar un proyecto",
    responses=problem_responses(403, 404, 409),
)
async def archive_project(
    project_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    confirm: Annotated[bool, Query()] = False,
) -> Response:
    """CU-07: archiva el proyecto (RF-032). Con secretos activos exige ``?confirm=true`` (si
    no, 409) y los archiva también. ``projects:manage`` en el proyecto."""
    await _load_project(session, project_id)
    await _authorize_project(authz, project_id, Permission.PROJECTS_MANAGE)
    try:
        archived = await _projects.archive_project(
            session, authz.operation_actor, project_id, confirm=confirm
        )
    except ConflictError as exc:
        raise _conflict(exc) from None
    if not archived:  # otro archivado ganó la carrera
        raise ApiProblem(404, "resource-not-found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Ambientes -----------------------------------------------------------------------------------


@router.post(
    "/{project_id}/environments",
    response_model=EnvironmentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un ambiente",
    responses=problem_responses(403, 404, 409),
)
async def create_environment(
    project_id: CanonicalUUID, body: EnvironmentCreate, session: SessionDep, authz: AuthorizerDep
) -> Environment:
    """CU-07: agrega un ambiente al proyecto. ``projects:manage`` en el proyecto; la regla
    404/403 se aplica al proyecto padre (spec §4.1)."""
    await _load_project(session, project_id)
    await _authorize_project(authz, project_id, Permission.PROJECTS_MANAGE)
    try:
        return await _environments.create_environment(
            session,
            authz.operation_actor,
            project_id,
            name=body.name,
            description=body.description,
        )
    except ConflictError as exc:
        raise _conflict(exc) from None


@router.get(
    "/{project_id}/environments",
    response_model=list[EnvironmentOut],
    summary="Listar los ambientes de un proyecto",
    responses=problem_responses(404),
)
async def list_environments(
    project_id: CanonicalUUID, session: SessionDep, authz: AuthorizerDep
) -> list[Environment]:
    """CU-07: ambientes del proyecto, filtrados (H-23d): con asignación a todo el proyecto (o
    de instancia) se listan todos; con asignaciones solo de ambiente, únicamente esos."""
    await _load_project(session, project_id)
    if not authz.sees_project(project_id):
        await authz.deny(
            404,
            Permission.SECRETS_READ,
            resource_type="project",
            resource_id=project_id,
            project_id=project_id,
        )
    return [
        env
        for env in await _environments.list_environments(session, project_id)
        if authz.allows(Permission.SECRETS_READ, AccessContext(project_id, env.id))
    ]


@router.patch(
    "/{project_id}/environments/{environment_id}",
    response_model=EnvironmentOut,
    summary="Actualizar un ambiente",
    responses=problem_responses(403, 404, 409),
)
async def update_environment(
    project_id: CanonicalUUID,
    environment_id: CanonicalUUID,
    body: EnvironmentUpdate,
    session: SessionDep,
    authz: AuthorizerDep,
) -> Environment:
    """CU-07: actualiza nombre o descripción del ambiente. ``projects:manage`` en el proyecto."""
    environment = await _load_environment_for_management(session, authz, project_id, environment_id)
    try:
        return await _environments.update_environment(
            session, authz.operation_actor, environment, body.model_dump(exclude_unset=True)
        )
    except ConflictError as exc:
        raise _conflict(exc) from None


@router.delete(
    "/{project_id}/environments/{environment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un ambiente",
    responses=problem_responses(403, 404, 409),
)
async def delete_environment(
    project_id: CanonicalUUID,
    environment_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
) -> Response:
    """CU-07: borra el ambiente solo si no tiene secretos; si los tiene, 409 (H-39).
    ``projects:manage`` en el proyecto."""
    environment = await _load_environment_for_management(session, authz, project_id, environment_id)
    try:
        await _environments.delete_environment(session, authz.operation_actor, environment)
    except ConflictError as exc:
        raise _conflict(exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
