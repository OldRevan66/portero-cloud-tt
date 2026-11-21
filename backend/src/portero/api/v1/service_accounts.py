"""Endpoints de Aplicaciones Cliente (service accounts y sus PAT) del API REST Gateway (Cap. 6
§Autenticación de Aplicaciones Cliente, tabla "Catálogo maestro"; spec Fase 5 §2, §3.7, §4.1,
§4.4; spec núcleo §3.3; H-09, H-14, H-21, H-23a, H-42; OWASP ASVS V2.10, V4.1.3).

**Autorización (H-23a).** ``projects:manage`` con alcance de proyecto: el Administrador y el
Líder del proyecto. Mismo orden que ``api/v1/projects.py`` (spec §4):

1. Cargar el recurso: el proyecto (rutas de colección) o la service account y su proyecto (rutas
   por identificador). Si no existe o el proyecto está archivado → 404 sin registro.
2. Visible = el actor cubre el proyecto o alguno de sus ambientes (H-23d; spec §4.1).
3. ``Authorizer.require``: 404 si no es visible, 403 si lo es pero falta el permiso (H-14).

**El token se entrega una sola vez**, en la respuesta 201 de la creación. Después solo hay
metadatos y ``token_prefix`` (los últimos 8 caracteres, H-42): ni el token ni su hash vuelven a
salir del servidor.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Response, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from portero.api.deps import Authorizer, AuthorizerDep, ServiceAccountServiceDep, SessionDep
from portero.api.errors import ApiProblem, problem_responses
from portero.api.params import CanonicalUUID, PlainText
from portero.db.models import ServiceAccount
from portero.management.errors import ManagementError
from portero.management.projects import ProjectService
from portero.rbac.evaluator import AccessContext
from portero.rbac.permissions import Permission

router = APIRouter(tags=["aplicaciones cliente"])

_projects = ProjectService()

CREATE_DESCRIPTION = (
    "**El campo `token` se muestra una sola vez**, en esta respuesta: el servidor solo guarda "
    "su hash SHA-256 y no puede volver a entregarlo. Cópialo ahora a la configuración de la "
    "aplicación cliente; si se pierde, revoca la service account y crea otra."
)


# --- Esquemas ------------------------------------------------------------------------------------


class ServiceAccountCreate(BaseModel):
    """Cuerpo de ``POST /projects/{pid}/service-accounts`` (spec §2). ``extra="forbid"``."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText = Field(min_length=1, max_length=128)
    environment_id: UUID | None = None
    """Nulo = acceso de lectura a todo el proyecto; si no, solo a ese ambiente."""
    expires_at: AwareDatetime | None = None
    """Con zona horaria. Nulo = sin vencimiento (H-09)."""


class ServiceAccountOut(BaseModel):
    """Metadatos de una service account: nunca el token ni su hash."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    project_id: UUID
    environment_id: UUID | None
    token_prefix: str
    created_at: datetime
    created_by: UUID
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


class ServiceAccountCreated(ServiceAccountOut):
    """Respuesta 201: los metadatos más el ``token``, que solo aparece aquí."""

    token: str = Field(description="PAT (JWT). Se muestra una sola vez.")


# --- Auxiliares ----------------------------------------------------------------------------------


async def _authorize(
    authz: Authorizer,
    project_id: UUID,
    *,
    resource_type: str,
    resource_id: UUID | None,
) -> None:
    """Pasos 2 y 3: ``projects:manage`` en el proyecto; 404 si no lo ve, 403 si lo ve."""
    await authz.require(
        Permission.PROJECTS_MANAGE,
        AccessContext(project_id=project_id, environment_id=None),
        visible=authz.sees_project(project_id),
        resource_type=resource_type,
        resource_id=resource_id,
    )


async def _load_project(session: SessionDep, project_id: UUID) -> None:
    if await _projects.get_project(session, project_id) is None:
        raise ApiProblem(404, "resource-not-found")


async def _load_account(
    session: SessionDep, service: ServiceAccountServiceDep, service_account_id: UUID
) -> ServiceAccount:
    """La service account de un proyecto no archivado, o 404 sin registro."""
    account = await service.get_service_account(session, service_account_id)
    if account is None or await _projects.get_project(session, account.project_id) is None:
        raise ApiProblem(404, "resource-not-found")
    return account


# --- Endpoints -----------------------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/service-accounts",
    response_model=ServiceAccountCreated,
    status_code=status.HTTP_201_CREATED,
    description=CREATE_DESCRIPTION,
    summary="Crear una Aplicación Cliente",
    responses=problem_responses(403, 404, 422),
)
async def create_service_account(
    project_id: CanonicalUUID,
    body: ServiceAccountCreate,
    session: SessionDep,
    authz: AuthorizerDep,
    service: ServiceAccountServiceDep,
) -> ServiceAccountCreated:
    """Crea una Aplicación Cliente con su PAT (Cap. 6 §Autenticación de Aplicaciones Cliente).

    ``projects:manage`` en el proyecto (H-23a). Un ambiente de otro proyecto o un
    ``expires_at`` que no está en el futuro → 422.
    """
    await _load_project(session, project_id)
    await _authorize(authz, project_id, resource_type="project", resource_id=project_id)
    try:
        created = await service.create_service_account(
            session,
            authz.operation_actor,
            project_id,
            name=body.name,
            environment_id=body.environment_id,
            expires_at=body.expires_at,
        )
    except ManagementError as exc:
        raise ApiProblem(422, "semantic-error", str(exc)) from None
    metadata = ServiceAccountOut.model_validate(created.account)
    return ServiceAccountCreated(**metadata.model_dump(), token=created.token)


@router.get(
    "/projects/{project_id}/service-accounts",
    response_model=list[ServiceAccountOut],
    summary="Listar las Aplicaciones Cliente de un proyecto",
    responses=problem_responses(403, 404),
)
async def list_service_accounts(
    project_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    service: ServiceAccountServiceDep,
) -> list[ServiceAccount]:
    """Service accounts del proyecto, vigentes y revocadas, sin tokens. ``projects:manage``."""
    await _load_project(session, project_id)
    await _authorize(authz, project_id, resource_type="project", resource_id=project_id)
    return list(await service.list_service_accounts(session, project_id))


@router.get(
    "/service-accounts/{service_account_id}",
    response_model=ServiceAccountOut,
    summary="Consultar una Aplicación Cliente",
    responses=problem_responses(403, 404),
)
async def get_service_account(
    service_account_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    service: ServiceAccountServiceDep,
) -> ServiceAccount:
    """Metadatos de una service account, sin token. ``projects:manage`` en su proyecto."""
    account = await _load_account(session, service, service_account_id)
    await _authorize(
        authz, account.project_id, resource_type="service_account", resource_id=account.id
    )
    return account


@router.delete(
    "/service-accounts/{service_account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revocar una Aplicación Cliente",
    responses=problem_responses(403, 404),
)
async def revoke_service_account(
    service_account_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    service: ServiceAccountServiceDep,
) -> Response:
    """Revoca el PAT (H-21): fija ``revoked_at`` y el token deja de servir en la siguiente
    petición. Idempotente: 204 también si ya estaba revocada. ``projects:manage``."""
    account = await _load_account(session, service, service_account_id)
    await _authorize(
        authz, account.project_id, resource_type="service_account", resource_id=account.id
    )
    await service.revoke_service_account(session, authz.operation_actor, account)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
