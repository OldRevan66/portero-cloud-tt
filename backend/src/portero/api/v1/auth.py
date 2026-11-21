"""Endpoints de autenticación del API REST Gateway: ``/api/v1/auth/login|refresh|logout|me``
(Cap. 6 §Endpoints de autenticación, §Revocación y renovación de tokens; spec Fase 5 §3.1–3.4;
CU-01; OWASP ASVS V3.4).

Los routers no tienen lógica de negocio ni tocan repositorios: validan la entrada, llaman al
Servicio de Autenticación y traducen sus resultados a respuestas, cookies y Problem Details.

**H-36: el refresh token solo viaja en la cookie** ``portero_refresh``
(``HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth``). JavaScript no puede leerla (un XSS
no roba el token de la sesión) y el navegador solo la manda a ``/refresh`` y ``/logout``. El
cuerpo lleva únicamente el access token. ``Max-Age`` es la vida del refresh: 1800 s (30 min de
inactividad), o menos cerca del tope de 12 h desde el login (H-61).
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from portero.api.deps import (
    BEARER_DETAIL,
    AuthServiceDep,
    ClientInfoDep,
    CurrentActor,
    CurrentActorDep,
    SessionDep,
    unauthorized,
)
from portero.api.errors import ApiProblem, problem_response, problem_responses
from portero.api.params import Email
from portero.auth.service import INVALID_CREDENTIALS, InvalidCredentialsError, TokenPair
from portero.auth.tokens import TokenRejectedError

router = APIRouter(prefix="/auth", tags=["autenticación"])

REFRESH_COOKIE = "portero_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"
"""El navegador solo envía la cookie a ``/api/v1/auth/*`` (``/refresh`` y ``/logout``), nunca al
resto de la API. Por eso no se usa el prefijo ``__Host-``, que exige ``Path=/`` (spec §3.1)."""

ONLY_HUMANS_DETAIL = "Esta operación es solo para usuarios."

# --- Esquemas ------------------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Cuerpo de ``POST /auth/login``. ``extra="forbid"``: un campo de más → 400 (spec §1)."""

    model_config = ConfigDict(extra="forbid")

    email: Email
    """Normalizado a minúsculas (H-45) y sin caracteres de control (H-44)."""
    password: SecretStr = Field(min_length=1, max_length=1024)
    """``SecretStr``: no aparece en ``repr`` ni en logs (RNF-006). El tope de 1024 evita que un
    cuerpo enorme llegue a Argon2id; la política (máx. 128) la aplica el servicio."""


class TokenResponse(BaseModel):
    """Respuesta de login y refresh (RFC 6749 §5.1). Sin ``refresh_token`` (H-36)."""

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105  # esquema RFC 6750
    expires_in: int
    """Vida del access token en segundos: ``exp - iat`` = 900 (Cap. 6 §Emisión del par), o
    menos si la sesión vence antes (H-61)."""


class AssignmentOut(BaseModel):
    id: UUID
    role_id: int
    role: str
    project_id: UUID | None
    environment_id: UUID | None


class MeResponse(BaseModel):
    """Respuesta de ``GET /auth/me`` (spec §3.4): datos para que el Dashboard arme su menú."""

    id: UUID
    email: str
    name: str | None
    assignments: list[AssignmentOut]


# --- Cookie --------------------------------------------------------------------------------------


def _set_refresh_cookie(response: Response, pair: TokenPair) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh.token,
        max_age=pair.refresh_expires_in,  # lo que le queda a la sesión (H-61)
        path=REFRESH_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response) -> None:
    """Borra la cookie: ``Max-Age=0`` con el mismo ``Path`` y atributos (RFC 6265 §5.3)."""
    response.delete_cookie(
        REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _token_response(pair: TokenPair) -> TokenResponse:
    return TokenResponse(access_token=pair.access.token, expires_in=pair.access_expires_in)


def require_human(actor: CurrentActor) -> None:
    """Un PAT pasa la autenticación pero no tiene "yo" humano: 403 (spec §3.4)."""
    if not actor.is_human:
        raise ApiProblem(403, "permission-denied", ONLY_HUMANS_DETAIL)


# --- Endpoints -----------------------------------------------------------------------------------


@router.post("/login", response_model=TokenResponse, summary="Iniciar sesión")
async def login(
    body: LoginRequest,
    response: Response,
    session: SessionDep,
    auth: AuthServiceDep,
    client: ClientInfoDep,
) -> TokenResponse:
    """CU-01: inicia sesión con correo y contraseña (Cap. 6 §Endpoints de autenticación).

    200 con el access token en el cuerpo y el refresh en la cookie (H-36). Cualquier rechazo
    (correo inexistente, contraseña incorrecta, cuenta inactiva o bloqueada) → 401 con el mismo
    mensaje (OWASP ASVS V2.2.1; H-08, H-24).
    """
    try:
        pair = await auth.login(
            session, body.email, body.password.get_secret_value(), client=client
        )
    except InvalidCredentialsError:
        raise ApiProblem(401, "authentication-failed", INVALID_CREDENTIALS) from None
    _set_refresh_cookie(response, pair)
    return _token_response(pair)


@router.post("/refresh", response_model=TokenResponse, summary="Renovar el access token")
async def refresh(
    request: Request,
    session: SessionDep,
    auth: AuthServiceDep,
    client: ClientInfoDep,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> Response:
    """Canjea el refresh de la cookie por un par nuevo con rotación (Cap. 6 §Renovación con
    refresh token; spec §3.2). No lee el cuerpo.

    Sin cookie, token inválido, reusado (posible robo), usuario inactivo o anterior al corte
    H-37 → 401 genérico y se borra la cookie.
    """
    if refresh_token is not None:
        try:
            pair = await auth.refresh(session, refresh_token, client=client)
        except TokenRejectedError:
            # El servicio ya registró refresh_reused si correspondía (spec Fase 5 §5.2).
            pair = None
        if pair is not None:
            ok = JSONResponse(_token_response(pair).model_dump())
            _set_refresh_cookie(ok, pair)
            return ok
    fail = problem_response(request, 401, "authentication-failed", BEARER_DETAIL)
    clear_refresh_cookie(fail)
    return fail


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cerrar sesión",
    responses=problem_responses(403),
)
async def logout(
    actor: CurrentActorDep,
    session: SessionDep,
    auth: AuthServiceDep,
    client: ClientInfoDep,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> Response:
    """Cierra la sesión (spec §3.3): revoca el ``jti`` del access token y, si la cookie trae un
    refresh válido del mismo usuario, también ese. Siempre borra la cookie. 204."""
    require_human(actor)
    await auth.logout(session, actor.token, refresh_token, client=client)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_refresh_cookie(response)
    return response


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Consultar el usuario autenticado",
    responses=problem_responses(403),
)
async def me(actor: CurrentActorDep, session: SessionDep, auth: AuthServiceDep) -> MeResponse:
    """Usuario autenticado y sus asignaciones de rol, leídas de la BD (spec §3.4)."""
    require_human(actor)
    try:
        profile = await auth.profile(session, actor.id)
    except TokenRejectedError:
        raise unauthorized() from None
    return MeResponse(
        id=profile.id,
        email=profile.email,
        name=profile.name,
        assignments=[
            AssignmentOut(
                id=a.id,
                role_id=a.role_id,
                role=a.role,
                project_id=a.project_id,
                environment_id=a.environment_id,
            )
            for a in profile.assignments
        ],
    )
