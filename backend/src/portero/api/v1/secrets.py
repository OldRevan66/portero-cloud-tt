"""Endpoints de secretos del API REST Gateway (CU-02, CU-03, CU-04; Cap. 6, tabla "Catálogo
maestro"; spec Fase 5 §1, §2, §4.1, §5; H-11, H-13, H-14; RNF-006).

Cada ruta sigue el mismo orden (spec Fase 5 §4):

1. Cargar el recurso: el secreto (rutas por identificador) o el ambiente padre (rutas de
   colección). Si no existe, está archivado o su proyecto está archivado → 404 sin registro.
2. Decidir la visibilidad: un secreto o un ambiente es visible si el actor tiene
   ``secrets:read`` en su (proyecto, ambiente).
3. ``Authorizer.require`` con el permiso de la tabla maestra: 404 si no es visible, 403 si lo es
   pero falta el permiso (H-14). Ambas denegaciones se registran como ``access_denied``.
4. Llamar al Servicio de Gestión de Secretos, que registra la operación en su transacción
   (H-11). ``read_secret`` se confirma **antes** de que el valor salga del servidor.

Manejo del valor (H-13, RNF-006):

- ``value`` y ``new_value`` son ``SecretStr``: su ``repr`` muestra asteriscos y el manejador
  de 400 nunca repite la entrada (spec §6).
- Del ``SecretStr`` se pasa a ``bytearray`` para el Motor Criptográfico, y ese ``bytearray`` se
  borra con ``secure_zero`` (vía ``SecretService.wipe``: el API no importa ``crypto``) en un
  ``finally``.
- ``GET /value`` serializa el JSON a mano y borra el plaintext justo después. Python no permite
  borrar un ``str``: las copias inmutables (el ``str`` del cuerpo recibido y el del JSON de
  salida) viven lo menos posible y nunca se registran. Es la limitación documentada de H-13.
- ``GET /value`` es la única respuesta con un valor en claro y lleva ``Cache-Control: no-store``.
"""

import json
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from portero.api.deps import Authorizer, AuthorizerDep, SecretServiceDep, SessionDep
from portero.api.errors import ApiProblem, problem_responses
from portero.api.pagination import decode_cursor, encode_cursor
from portero.api.params import CanonicalUUID, PlainText
from portero.management.environments import EnvironmentService
from portero.management.projects import ProjectService
from portero.rbac.evaluator import AccessContext
from portero.rbac.permissions import Permission
from portero.secrets_mgmt.errors import SecretNameConflictError, SecretNotFoundError
from portero.secrets_mgmt.service import SecretMetadata, SecretService, VersionPage

router = APIRouter(tags=["secretos"])

_projects = ProjectService()
_environments = EnvironmentService()

MAX_SECRET_VALUE = 65_536
"""Largo máximo de ``value`` y ``new_value``: 64 KiB (spec Fase 5 §1, modelo ``SecretCreate``)."""

_SecretValue = Annotated[SecretStr, Field(min_length=1, max_length=MAX_SECRET_VALUE)]
_Description = Annotated[PlainText | None, Field(max_length=1024)]


# --- Esquemas ------------------------------------------------------------------------------------


class SecretCreate(BaseModel):
    """Cuerpo de ``POST .../secrets`` (CU-02). ``name`` en SCREAMING_SNAKE_CASE; ``value`` es
    ``SecretStr`` (RNF-006). ``extra="forbid"``: un campo de más → 400 (spec §1)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255, pattern=r"^[A-Z][A-Z0-9_]*$")
    value: _SecretValue
    description: _Description = None


class SecretRotate(BaseModel):
    """Cuerpo de ``POST /secrets/{id}/rotate`` (CU-04)."""

    model_config = ConfigDict(extra="forbid")

    new_value: _SecretValue


class SecretUpdate(BaseModel):
    """Cuerpo de ``PATCH /secrets/{id}``: solo la descripción. El nombre no cambia y el valor
    solo cambia rotando (CU-04)."""

    model_config = ConfigDict(extra="forbid")

    description: _Description = None


class SecretOut(BaseModel):
    """Metadatos de un secreto, nunca su valor (spec §2)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    version: int
    project_id: UUID
    environment_id: UUID
    created_at: datetime
    created_by: UUID
    updated_at: datetime


class SecretValueOut(BaseModel):
    """Única respuesta del sistema con un valor en claro (spec §2). Solo documenta el
    OpenAPI: la ruta serializa el cuerpo a mano para borrar el plaintext (H-13)."""

    id: UUID
    name: str
    value: str
    version: int


class RotationOut(BaseModel):
    """Respuesta de la rotación (spec §2): la versión nueva, sin el valor."""

    id: UUID
    version: int
    rotated_at: datetime


class SecretVersionOut(BaseModel):
    """Una versión del historial, sin valor ni material cifrado (spec §2)."""

    model_config = ConfigDict(from_attributes=True)

    version: int
    created_at: datetime
    created_by: UUID
    aead_algorithm: str


class SecretVersionPage(BaseModel):
    """Página del historial (spec §1): ``next_cursor`` nulo si no hay más."""

    items: list[SecretVersionOut]
    next_cursor: str | None


# --- Auxiliares ----------------------------------------------------------------------------------


def _not_found() -> ApiProblem:
    return ApiProblem(404, "resource-not-found")


def _conflict(exc: SecretNameConflictError) -> ApiProblem:
    """409 ``conflict``; los mensajes de ``secrets_mgmt.errors`` no llevan datos internos."""
    return ApiProblem(409, "conflict", str(exc))


def _secret_bytes(value: SecretStr) -> bytearray:
    """``SecretStr`` → ``bytearray`` UTF-8 para el Motor Criptográfico (H-13: el llamador lo
    borra con ``secure_zero``)."""
    return bytearray(value.get_secret_value(), "utf-8")


async def _authorize_environment(
    session: SessionDep,
    authz: Authorizer,
    project_id: UUID,
    environment_id: UUID,
    permission: Permission,
) -> None:
    """Rutas de colección: la regla 404/403 se aplica al ambiente padre (spec §4.1).

    El proyecto debe existir sin archivar y el ambiente debe pertenecerle; si no, 404 sin
    registro. Es visible si el actor tiene ``secrets:read`` en él.
    """
    if await _projects.get_project(session, project_id) is None:
        raise _not_found()
    if await _environments.get_environment(session, project_id, environment_id) is None:
        raise _not_found()
    ctx = AccessContext(project_id=project_id, environment_id=environment_id)
    await authz.require(
        permission,
        ctx,
        visible=authz.allows(Permission.SECRETS_READ, ctx),
        resource_type="environment",
        resource_id=environment_id,
    )


async def _load_secret(
    session: SessionDep,
    authz: Authorizer,
    secrets: SecretService,
    secret_id: UUID,
    permission: Permission,
) -> SecretMetadata:
    """Rutas por identificador (H-14): carga el secreto (404 sin registro si no existe, está
    archivado o su proyecto lo está) y exige ``permission`` en su (proyecto, ambiente)."""
    secret = await secrets.get_secret(session, secret_id)
    if secret is None:
        raise _not_found()
    ctx = AccessContext(project_id=secret.project_id, environment_id=secret.environment_id)
    await authz.require(
        permission,
        ctx,
        visible=authz.allows(Permission.SECRETS_READ, ctx),
        resource_type="secret",
        resource_id=secret_id,
    )
    return secret


def _value_body(secret: SecretMetadata, plaintext: bytearray) -> bytes:
    """JSON de ``GET /value`` construido desde el ``bytearray`` (H-13)."""
    return json.dumps(
        {
            "id": str(secret.id),
            "name": secret.name,
            "value": plaintext.decode("utf-8"),
            "version": secret.version,
        },
        ensure_ascii=False,
    ).encode("utf-8")


def _version_page(page: VersionPage) -> SecretVersionPage:
    return SecretVersionPage(
        items=[SecretVersionOut.model_validate(v) for v in page.items],
        next_cursor=None if page.next_before is None else encode_cursor(page.next_before),
    )


# --- Colección: /projects/{pid}/environments/{eid}/secrets ---------------------------------------

_COLLECTION = "/projects/{project_id}/environments/{environment_id}/secrets"


@router.post(
    _COLLECTION,
    response_model=SecretOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un secreto",
    responses=problem_responses(403, 404, 409),
)
async def create_secret(
    project_id: CanonicalUUID,
    environment_id: CanonicalUUID,
    body: SecretCreate,
    session: SessionDep,
    authz: AuthorizerDep,
    secrets: SecretServiceDep,
) -> SecretMetadata:
    """CU-02: crea un secreto con su versión 1. ``secrets:write`` en el ambiente. La respuesta
    lleva solo metadatos, nunca el valor (spec §2)."""
    await _authorize_environment(
        session, authz, project_id, environment_id, Permission.SECRETS_WRITE
    )
    value = _secret_bytes(body.value)
    try:
        ref = await secrets.create_secret(
            session,
            actor=authz.operation_actor,
            project_id=project_id,
            environment_id=environment_id,
            name=body.name,
            value=value,
            description=body.description,
        )
    except SecretNameConflictError as exc:
        raise _conflict(exc) from None
    finally:
        SecretService.wipe(value)  # H-13
    created = await secrets.get_secret(session, ref.secret_id)
    if created is None:  # archivado por otra petición entre el commit y esta lectura
        raise _not_found()
    return created


@router.get(
    _COLLECTION,
    response_model=list[SecretOut],
    summary="Listar los secretos de un ambiente",
    responses=problem_responses(404),
)
async def list_secrets(
    project_id: CanonicalUUID,
    environment_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    secrets: SecretServiceDep,
) -> list[SecretMetadata]:
    """CU-03: metadatos de los secretos activos del ambiente. ``secrets:read`` en el ambiente.
    No se registra (spec §5.2)."""
    await _authorize_environment(
        session, authz, project_id, environment_id, Permission.SECRETS_READ
    )
    return await secrets.list_secrets(session, project_id, environment_id)


# --- Por identificador: /secrets/{id} ------------------------------------------------------------


@router.get(
    "/secrets/{secret_id}",
    response_model=SecretOut,
    summary="Consultar los metadatos de un secreto",
    responses=problem_responses(404),
)
async def get_secret(
    secret_id: CanonicalUUID, session: SessionDep, authz: AuthorizerDep, secrets: SecretServiceDep
) -> SecretMetadata:
    """CU-03: metadatos de un secreto. ``secrets:read`` en su ambiente; si no le es visible,
    404 igual al de un secreto inexistente (H-14)."""
    return await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_READ)


@router.get(
    "/secrets/{secret_id}/value",
    response_model=SecretValueOut,
    responses={
        **problem_responses(404),
        200: {"description": "El valor en claro. Respuesta con `Cache-Control: no-store`."},
    },
    summary="Revelar el valor de un secreto",
)
async def reveal_secret(
    secret_id: CanonicalUUID, session: SessionDep, authz: AuthorizerDep, secrets: SecretServiceDep
) -> Response:
    """CU-03: revela el valor de la versión actual. ``secrets:read`` en su ambiente.

    ``read_secret`` se registra y confirma **antes** de responder; si el registro falla, la
    respuesta es 500 y el valor no se entrega (fail-closed, H-11). Se lee exactamente la
    versión que se cargó en el paso 1, para que ``version`` y ``value`` siempre coincidan
    aunque otra petición rote en medio. El plaintext se borra tras serializar (H-13).
    """
    secret = await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_READ)
    try:
        plaintext = await secrets.read_secret_value(
            session, secret_id, secret.version, actor=authz.operation_actor
        )
    except SecretNotFoundError:  # archivado por otra petición después del paso 1
        raise _not_found() from None
    try:
        body = _value_body(secret, plaintext)
    finally:
        SecretService.wipe(plaintext)  # Algoritmo 2 del Cap. 6; H-13
    return Response(
        content=body,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},  # ni el navegador ni un proxy lo guardan
    )


@router.patch(
    "/secrets/{secret_id}",
    response_model=SecretOut,
    summary="Actualizar la descripción de un secreto",
    responses=problem_responses(403, 404),
)
async def update_secret(
    secret_id: CanonicalUUID,
    body: SecretUpdate,
    session: SessionDep,
    authz: AuthorizerDep,
    secrets: SecretServiceDep,
) -> SecretMetadata:
    """Actualiza la descripción. ``secrets:write`` en su ambiente; registra ``update_secret``
    con los nombres de los campos cambiados (spec §5.3)."""
    await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_WRITE)
    try:
        return await secrets.update_secret(
            session, secret_id, body.model_dump(exclude_unset=True), actor=authz.operation_actor
        )
    except SecretNotFoundError:
        raise _not_found() from None


@router.post(
    "/secrets/{secret_id}/rotate",
    response_model=RotationOut,
    summary="Rotar un secreto",
    responses=problem_responses(403, 404),
)
async def rotate_secret(
    secret_id: CanonicalUUID,
    body: SecretRotate,
    session: SessionDep,
    authz: AuthorizerDep,
    secrets: SecretServiceDep,
) -> RotationOut:
    """CU-04: crea la versión N+1 con una DEK nueva. ``secrets:rotate`` en su ambiente: un
    Desarrollador que puede leer el secreto recibe 403; uno que no lo ve, 404 (H-14). La
    bitácora guarda ``{from_version, to_version}`` (spec §5.3)."""
    await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_ROTATE)
    new_value = _secret_bytes(body.new_value)
    try:
        ref = await secrets.rotate_secret(
            session, secret_id, new_value, actor=authz.operation_actor
        )
    except SecretNotFoundError:
        raise _not_found() from None
    finally:
        SecretService.wipe(new_value)  # H-13
    return RotationOut(id=ref.secret_id, version=ref.version_number, rotated_at=ref.created_at)


@router.delete(
    "/secrets/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archivar un secreto",
    responses=problem_responses(403, 404),
)
async def archive_secret(
    secret_id: CanonicalUUID, session: SessionDep, authz: AuthorizerDep, secrets: SecretServiceDep
) -> Response:
    """Archiva el secreto (borrado lógico, spec §2). ``secrets:delete`` en su ambiente. Después,
    todas las rutas por identificador responden 404 y el nombre queda libre."""
    await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_DELETE)
    try:
        await secrets.archive_secret(session, secret_id, actor=authz.operation_actor)
    except SecretNotFoundError:
        raise _not_found() from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/secrets/{secret_id}/versions",
    response_model=SecretVersionPage,
    summary="Listar las versiones de un secreto",
    responses=problem_responses(404),
)
async def list_versions(
    secret_id: CanonicalUUID,
    session: SessionDep,
    authz: AuthorizerDep,
    secrets: SecretServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=64)] = None,
) -> SecretVersionPage:
    """Historial de versiones (RF-006), de la más reciente a la más antigua, paginado por
    cursor opaco (spec §1). Nunca valores; incluye ``aead_algorithm``. ``secrets:read``."""
    before = None if cursor is None else decode_cursor(cursor)
    await _load_secret(session, authz, secrets, secret_id, Permission.SECRETS_READ)
    page = await secrets.list_versions(session, secret_id, limit=limit, before=before)
    return _version_page(page)
