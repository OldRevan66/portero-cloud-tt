"""Endpoints de usuarios, asignaciones de rol, cambio de contraseña, desbloqueo y restablecimiento
del API REST Gateway (CU-05; Cap. 6 §Gestión de usuarios, tabla "Catálogo maestro"; spec Fase 5
§2, §3.5, §3.6, §4.4; H-22, H-23a, H-37, H-73, H-78; OWASP ASVS V2.1, V2.5, V4.1.3).

**Autorización.** Toda ruta de ``/users`` (salvo ``/users/me/password``) exige ``users:manage``
de instancia: solo el Administrador (H-23a). Un usuario es un recurso de instancia y no hay nada
que ocultar, así que la denegación es siempre 403, exista o no el usuario (un 404 permitiría
enumerar cuentas). La exige la dependencia ``UsersManagerDep``, que FastAPI resuelve **antes** de
validar el cuerpo: quien no tiene el permiso recibe 403 y no aprende nada del esquema.

**Errores.** Esquema inválido, campo de más, asignación de instancia para un rol que no es
Administrador (H-22) o ambiente sin proyecto → 400. La política de contraseñas y un ambiente
que no pertenece al proyecto → 422. Correo o asignación duplicados, autodesactivación,
autodesbloqueo y restablecer la propia contraseña (H-78) → 409.

Las respuestas nunca incluyen la contraseña ni su hash.
"""

from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from portero.api.deps import (
    Authorizer,
    AuthorizerDep,
    AuthServiceDep,
    ClientInfoDep,
    CurrentActorDep,
    SessionDep,
)
from portero.api.errors import ApiProblem, problem_responses
from portero.api.params import CanonicalUUID, Email, PlainText
from portero.api.v1.auth import clear_refresh_cookie, require_human
from portero.auth.passwords import PasswordPolicyError
from portero.auth.service import INVALID_CREDENTIALS, InvalidCredentialsError
from portero.auth.tokens import TokenRejectedError
from portero.db.models import User, UserRoleAssignment
from portero.management.errors import ConflictError, ManagementError, SemanticError
from portero.management.users import UserService
from portero.rbac.evaluator import AccessContext
from portero.rbac.permissions import Permission, Role

router = APIRouter(prefix="/users", tags=["usuarios"])

_users = UserService()

_Password = Annotated[SecretStr, Field(min_length=1, max_length=1024)]
"""``SecretStr``: no aparece en ``repr`` ni en logs (RNF-006). El tope de 1024 solo evita que un
cuerpo enorme llegue a Argon2id; la política (12 a 128) la aplica el servicio y responde 422."""


# --- Esquemas ------------------------------------------------------------------------------------


class UserCreate(BaseModel):
    """Cuerpo de ``POST /users``. ``extra="forbid"``: un campo de más → 400 (spec §1)."""

    model_config = ConfigDict(extra="forbid")

    email: Email
    name: PlainText | None = Field(default=None, min_length=1, max_length=255)
    password: _Password


class UserUpdate(BaseModel):
    """Cuerpo de ``PATCH /users/{uid}``. La contraseña no cambia por aquí: solo por
    ``/users/me/password``, que reverifica la actual."""

    model_config = ConfigDict(extra="forbid")

    name: PlainText | None = Field(default=None, min_length=1, max_length=255)
    is_active: bool | None = None

    @field_validator("is_active")
    @classmethod
    def _not_null(cls, value: bool | None) -> bool:
        """Se puede omitir ``is_active``, pero no enviarlo como ``null`` (NOT NULL)."""
        if value is None:
            raise ValueError("is_active no puede ser nulo")
        return value


class UserOut(BaseModel):
    """Usuario sin contraseña, hash ni contador de fallos.

    ``locked_until`` (H-78) es el fin del bloqueo vigente, o ``null`` si no hay o ya venció: el
    Dashboard muestra "Bloqueada hasta" y el botón "Desbloquear" sin comparar con el reloj del
    navegador. Solo lo ve quien tiene ``users:manage``.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    name: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    locked_until: datetime | None

    @field_validator("locked_until")
    @classmethod
    def _only_active_lock(cls, value: datetime | None) -> datetime | None:
        """Un bloqueo vencido ya no cuenta (Cap. 6 §Política de bloqueo): se expone como nulo."""
        if value is not None and value <= datetime.now(UTC):
            return None
        return value


class AssignmentCreate(BaseModel):
    """Cuerpo de ``POST /users/{uid}/role-assignments`` (spec §2, Asignaciones)."""

    model_config = ConfigDict(extra="forbid")

    role_id: Role
    project_id: UUID | None = None
    environment_id: UUID | None = None

    @model_validator(mode="after")
    def _valid_scope(self) -> Self:
        """Forma del alcance (Cap. 5 §Tabla user_role_assignments; H-22):

        - un ambiente exige su proyecto (es también un CHECK de la BD);
        - el alcance de instancia (ambos nulos) es solo del Administrador.
        """
        if self.environment_id is not None and self.project_id is None:
            raise ValueError("environment_id requiere project_id")
        if self.project_id is None and self.role_id != Role.ADMINISTRADOR:
            raise ValueError("solo el Administrador tiene alcance de instancia")
        return self


class AssignmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    role_id: int
    project_id: UUID | None
    environment_id: UUID | None


class PasswordChange(BaseModel):
    """Cuerpo de ``POST /users/me/password`` (spec §3.6)."""

    model_config = ConfigDict(extra="forbid")

    current_password: _Password
    new_password: _Password


class PasswordReset(BaseModel):
    """Cuerpo de ``POST /users/{uid}/password-reset`` (H-78)."""

    model_config = ConfigDict(extra="forbid")

    new_password: _Password


# --- Auxiliares ----------------------------------------------------------------------------------


async def require_users_manage(authz: AuthorizerDep) -> Authorizer:
    """``users:manage`` con alcance de instancia (tabla maestra; H-23a). Sin él → 403 y
    ``access_denied`` con ``resource_type=user`` y sin proyecto."""
    await authz.require(
        Permission.USERS_MANAGE,
        AccessContext(project_id=None, environment_id=None),
        visible=True,  # recurso de instancia: no hay nada que ocultar
        resource_type="user",
        resource_id=None,
    )
    return authz


UsersManagerDep = Annotated[Authorizer, Depends(require_users_manage)]


def _problem(exc: ManagementError | PasswordPolicyError) -> ApiProblem:
    """409 para conflictos y 422 para reglas de negocio. Los mensajes no llevan datos
    internos ni la contraseña (``PasswordPolicyError`` nunca la incluye)."""
    if isinstance(exc, ConflictError):
        return ApiProblem(409, "conflict", str(exc))
    if isinstance(exc, SemanticError | PasswordPolicyError):
        return ApiProblem(422, "semantic-error", str(exc))
    raise exc  # no hay otras subclases; si apareciera una, que llegue como 500


async def _load_user(session: SessionDep, user_id: UUID) -> User:
    user = await _users.get_user(session, user_id)
    if user is None:
        raise ApiProblem(404, "resource-not-found")
    return user


# --- Cambio de contraseña (cualquier humano autenticado) ------------------------------------------


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cambiar la propia contraseña",
    responses=problem_responses(403, 422),
)
async def change_password(
    body: PasswordChange,
    actor: CurrentActorDep,
    session: SessionDep,
    auth: AuthServiceDep,
    client: ClientInfoDep,
) -> Response:
    """Cambia la contraseña propia (spec §3.6; OWASP ASVS V2.1.5–V2.1.6).

    Reverifica la contraseña actual (401 genérico si no coincide; cuenta para el bloqueo). La
    nueva pasa por la política (422). Al cambiarla se invalidan todos los tokens anteriores
    (H-37) y se borra la cookie de refresh: hay que iniciar sesión de nuevo. Solo humanos.
    """
    require_human(actor)
    try:
        await auth.change_password(
            session,
            actor.id,
            body.current_password.get_secret_value(),
            body.new_password.get_secret_value(),
            client=client,
        )
    except InvalidCredentialsError:
        raise ApiProblem(401, "authentication-failed", INVALID_CREDENTIALS) from None
    except PasswordPolicyError as exc:
        raise _problem(exc) from None
    except TokenRejectedError:  # la cuenta se desactivó durante la petición
        raise ApiProblem(401, "authentication-failed", INVALID_CREDENTIALS) from None
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_refresh_cookie(response)
    return response


# --- Usuarios ------------------------------------------------------------------------------------


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un usuario",
    responses=problem_responses(403, 409, 422),
)
async def create_user(body: UserCreate, session: SessionDep, authz: UsersManagerDep) -> User:
    """CU-05: crea una cuenta activa y sin asignaciones. La contraseña pasa por la política del
    Cap. 6 (422 si no cumple); correo repetido → 409."""
    try:
        return await _users.create_user(
            session,
            authz.operation_actor,
            email=body.email,
            name=body.name,
            password=body.password.get_secret_value(),
        )
    except (ManagementError, PasswordPolicyError) as exc:
        raise _problem(exc) from None


@router.get(
    "", response_model=list[UserOut], summary="Listar usuarios", responses=problem_responses(403)
)
async def list_users(session: SessionDep, authz: UsersManagerDep) -> list[User]:
    """CU-05: todos los usuarios, activos e inactivos."""
    return list(await _users.list_users(session))


@router.get(
    "/{user_id}",
    response_model=UserOut,
    summary="Consultar un usuario",
    responses=problem_responses(403, 404),
)
async def get_user(user_id: CanonicalUUID, session: SessionDep, authz: UsersManagerDep) -> User:
    """CU-05: un usuario."""
    return await _load_user(session, user_id)


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    summary="Actualizar un usuario",
    responses=problem_responses(403, 404, 409),
)
async def update_user(
    user_id: CanonicalUUID, body: UserUpdate, session: SessionDep, authz: UsersManagerDep
) -> User:
    """CU-05: cambia el nombre o activa/desactiva la cuenta. Desactivar invalida los tokens
    vivos del usuario (H-37); un Administrador no puede desactivarse a sí mismo (409)."""
    user = await _load_user(session, user_id)
    try:
        return await _users.update_user(
            session, authz.operation_actor, user, body.model_dump(exclude_unset=True)
        )
    except ManagementError as exc:
        raise _problem(exc) from None


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Desactivar un usuario",
    responses=problem_responses(403, 404, 409),
)
async def deactivate_user(
    user_id: CanonicalUUID, session: SessionDep, authz: UsersManagerDep
) -> Response:
    """CU-05: desactivación lógica (``is_active=false``); la fila no se borra porque la
    refieren secretos, service accounts y la bitácora. Invalida los tokens (H-37)."""
    user = await _load_user(session, user_id)
    try:
        await _users.deactivate_user(session, authz.operation_actor, user)
    except ManagementError as exc:
        raise _problem(exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{user_id}/unlock",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Desbloquear una cuenta",
    responses=problem_responses(403, 404, 409),
)
async def unlock_user(
    user_id: CanonicalUUID, session: SessionDep, authz: UsersManagerDep
) -> Response:
    """H-78: reinicia el contador de fallos y quita el bloqueo (Cap. 6 §Política de bloqueo) sin
    esperar los 15 minutos. Idempotente y no cierra sesiones. Solo el Administrador (H-23a); no
    sobre sí mismo (409)."""
    user = await _load_user(session, user_id)
    try:
        await _users.unlock_user(session, authz.operation_actor, user)
    except ManagementError as exc:
        raise _problem(exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{user_id}/password-reset",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Restablecer la contraseña de un usuario",
    responses=problem_responses(403, 404, 409, 422),
)
async def reset_password(
    user_id: CanonicalUUID, body: PasswordReset, session: SessionDep, authz: UsersManagerDep
) -> Response:
    """H-78: el Administrador fija una contraseña temporal que cumple la política (422 si no).
    Invalida todos los tokens del usuario (H-37) y quita el bloqueo. La propia se cambia con
    ``/users/me/password`` (409 aquí). La respuesta no lleva cuerpo: la contraseña nunca sale."""
    user = await _load_user(session, user_id)
    try:
        await _users.reset_password(
            session, authz.operation_actor, user, body.new_password.get_secret_value()
        )
    except (ManagementError, PasswordPolicyError) as exc:
        raise _problem(exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Asignaciones de rol -------------------------------------------------------------------------


@router.get(
    "/{user_id}/role-assignments",
    response_model=list[AssignmentOut],
    summary="Listar las asignaciones de rol de un usuario",
    responses=problem_responses(403, 404),
)
async def list_role_assignments(
    user_id: CanonicalUUID, session: SessionDep, authz: UsersManagerDep
) -> list[UserRoleAssignment]:
    """CU-05: asignaciones del usuario (instancia, proyecto o ambiente), ordenadas por rol,
    fecha de creación e ``id`` (Cap. 6 §Endpoints de gestión de usuarios y roles; H-73).

    El Cap. 6 define ``POST`` y ``DELETE`` de asignaciones pero no un listado; sin él, el
    Dashboard no conoce el ``aid`` que pide el ``DELETE``. Solo el Administrador
    (``users:manage`` de instancia, H-23a): la dependencia se resuelve antes de buscar al
    usuario, así que sin el permiso es 403 exista o no (OWASP ASVS V4.1.3). La respuesta no
    incluye datos del usuario, solo sus asignaciones."""
    user = await _load_user(session, user_id)
    return list(await _users.list_assignments(session, user.id))


@router.post(
    "/{user_id}/role-assignments",
    response_model=AssignmentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Asignar un rol",
    responses=problem_responses(403, 404, 409, 422),
)
async def assign_role(
    user_id: CanonicalUUID,
    body: AssignmentCreate,
    session: SessionDep,
    authz: UsersManagerDep,
) -> UserRoleAssignment:
    """CU-05: asigna un rol con su alcance (instancia, proyecto o ambiente). Solo el
    Administrador (H-23a). Invalida los tokens del usuario (H-37)."""
    user = await _load_user(session, user_id)
    try:
        return await _users.assign_role(
            session,
            authz.operation_actor,
            user,
            role_id=body.role_id,
            project_id=body.project_id,
            environment_id=body.environment_id,
        )
    except ManagementError as exc:
        raise _problem(exc) from None


@router.delete(
    "/{user_id}/role-assignments/{assignment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Quitar una asignación de rol",
    responses=problem_responses(403, 404, 409),
)
async def revoke_role(
    user_id: CanonicalUUID,
    assignment_id: CanonicalUUID,
    session: SessionDep,
    authz: UsersManagerDep,
) -> Response:
    """CU-05: quita una asignación del usuario (404 si no es suya). Invalida sus tokens
    (H-37). 409 si es la del último Administrador activo (H-59)."""
    assignment = await _users.get_assignment(session, user_id, assignment_id)
    if assignment is None:
        raise ApiProblem(404, "resource-not-found")
    try:
        await _users.revoke_role(session, authz.operation_actor, assignment)
    except ManagementError as exc:
        raise _problem(exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
