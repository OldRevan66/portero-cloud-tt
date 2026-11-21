"""Dependencias de FastAPI del API REST Gateway: sesión de BD por petición y autenticación del
portador del token (RFC 6750; Cap. 6 §Algoritmo de verificación de un JWT entrante; spec Fase 5
§3.5, §3.7 y §6).

La verificación en sí la hace el Servicio de Autenticación (``AuthService.authenticate``); aquí
solo se extrae el Bearer y se traduce el rechazo a un 401 uniforme.

La autorización por ruta (``Authorizer``) es el puente con el Módulo RBAC: carga las
asignaciones vigentes, llama a ``rbac.evaluate`` y aplica la regla 404/403 de H-14 (Algoritmo 5
del Cap. 6; spec Fase 5 §4; OWASP ASVS V4.1.3, V4.1.5).

El límite de tasa (Cap. 6 §Rate limiting; spec Fase 5 §7; OWASP API4) se aplica aquí en dos
puntos: por IP en ``enforce_ip_rate_limit`` (dependencia global de la app: autenticación y
salud) y por actor en ``get_current_actor``, justo después de validar el token (lectura de
valores y operaciones generales).
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, NoReturn
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from portero.api.errors import ApiProblem
from portero.api.rate_limit import IP_CATEGORIES, RateLimiter, classify
from portero.auth.service import AuthService
from portero.auth.tokens import TokenRejectedError, VerifiedToken
from portero.management.access import AccessService, ActorAccess
from portero.management.service_accounts import ServiceAccountService
from portero.oplog.service import ClientInfo, OperationActor
from portero.rbac.evaluator import (
    ALL_PROJECTS,
    AccessContext,
    Actor,
    AllProjects,
    ServiceScope,
    evaluate,
    visible_projects,
)
from portero.rbac.permissions import Permission
from portero.secrets_mgmt.service import SecretService

BEARER_DETAIL = "token inválido o expirado"
"""Único ``detail`` de los 401 de la dependencia Bearer (spec Fase 5 §6): no distingue token
ausente, mal firmado, expirado, revocado, de un usuario inactivo o anterior al corte H-37."""

_bearer = HTTPBearer(auto_error=False, description="Access token o PAT (RFC 6750)")


def unauthorized() -> ApiProblem:
    """401 ``authentication-failed`` con ``WWW-Authenticate: Bearer`` (RFC 6750 §3)."""
    return ApiProblem(
        401, "authentication-failed", BEARER_DETAIL, headers={"WWW-Authenticate": "Bearer"}
    )


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Una sesión de BD por petición, de la fábrica que creó el lifespan. Al terminar se cierra;
    lo no confirmado se revierte. Cada servicio controla su propia transacción."""
    async with request.app.state.sessionmaker() as session:
        yield session


def get_auth_service(request: Request) -> AuthService:
    """El Servicio de Autenticación creado en el arranque (con el ``JwtSigner``)."""
    service: AuthService = request.app.state.auth_service
    return service


def get_chain_public_key(request: Request) -> Ed25519PublicKey | None:
    """Llave pública de la firma del cierre de la bitácora, cargada en el arranque, o ``None``
    si ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY`` no está definida (H-81)."""
    key: Ed25519PublicKey | None = request.app.state.chain_public_key
    return key


ChainPublicKeyDep = Annotated[Ed25519PublicKey | None, Depends(get_chain_public_key)]


def get_client_info(request: Request) -> ClientInfo:
    """IP del cliente y ``User-Agent`` de la petición, para el Servicio de Registro de
    Operaciones (spec Fase 5 §5.3: ``ip_address = request.client.host``)."""
    return ClientInfo(
        ip_address=request.client.host if request.client is not None else None,
        user_agent=request.headers.get("user-agent"),
    )


def get_secret_service(request: Request) -> SecretService:
    """El Servicio de Gestión de Secretos creado en el arranque, con la KEK ya derivada y
    verificada (H-06)."""
    service: SecretService = request.app.state.secret_service
    return service


def get_service_account_service(request: Request) -> ServiceAccountService:
    """El Servicio de Gestión de Aplicaciones Cliente creado en el arranque, con el emisor de PAT
    del Servicio de Autenticación (H-21)."""
    service: ServiceAccountService = request.app.state.service_account_service
    return service


def get_rate_limiter(request: Request) -> RateLimiter:
    """El limitador del proceso, creado en ``create_app`` (``app.state.rate_limiter``)."""
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


async def enforce_ip_rate_limit(request: Request) -> None:
    """Dependencia global: límite por IP de las categorías de autenticación y salud (Cap. 6).

    Corre antes de las dependencias de la ruta y antes de validar el cuerpo, así que un login
    rechazado por tasa no llega a calcular Argon2id. La IP es ``request.client.host``; **no** se
    confía en ``X-Forwarded-For``, que el cliente puede falsificar si no hay un proxy de
    confianza declarado (spec §7)."""
    category = classify(request.method, request.url.path)
    if category in IP_CATEGORIES:
        ip = request.client.host if request.client is not None else "desconocida"
        get_rate_limiter(request).enforce(category, ip)


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SecretServiceDep = Annotated[SecretService, Depends(get_secret_service)]
ServiceAccountServiceDep = Annotated[ServiceAccountService, Depends(get_service_account_service)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
ClientInfoDep = Annotated[ClientInfo, Depends(get_client_info)]


@dataclass(frozen=True)
class CurrentActor:
    """Actor autenticado de la petición.

    ``actor`` es el ``Actor`` del Módulo RBAC (lo que recibe ``rbac.evaluate``). Ese tipo no
    lleva identificador, a propósito: el RBAC es una función pura. Por eso aquí se agregan
    ``id`` (el ``sub``: ``users.id`` o ``service_accounts.id``) y el token verificado, que
    necesitan logout (``jti``, ``exp``) y ``/auth/me``.
    """

    id: UUID
    actor: Actor
    token: VerifiedToken

    @property
    def is_human(self) -> bool:
        return self.actor.actor_type == "human"


async def get_current_actor(
    request: Request,
    session: SessionDep,
    auth: AuthServiceDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentActor:
    """Autentica el ``Authorization: Bearer <jwt>`` de la petición (``require_actor``).

    Acepta access tokens de humanos y PAT de Aplicaciones Cliente (``API_TOKEN_TYPES``, H-25);
    para humanos exige cuenta activa y ``iat`` no anterior a ``tokens_invalid_before`` (H-37);
    para PAT, service account existente y no revocado (H-21). Cualquier fallo → 401 genérico
    (OWASP ASVS V3.4; el motivo interno no sale del servidor).

    Con el token ya validado: fija ``actor_id`` para el log de acceso y aplica el límite por
    actor (``sub``) de su categoría (spec §7). Un token inválido no consume cupo de nadie.
    """
    if credentials is None:  # sin cabecera o con un esquema distinto de Bearer
        raise unauthorized()
    try:
        verified = await auth.authenticate(session, credentials.credentials)
    except TokenRejectedError:
        # No se registra en la bitácora (spec Fase 5 §5.2): no hay actor confiable, y tomar el
        # lock de la cadena por cada token inválido sería una vía de denegación de servicio.
        raise unauthorized() from None
    request.state.actor_id = verified.sub
    category = classify(request.method, request.url.path)
    if category not in IP_CATEGORIES:
        get_rate_limiter(request).enforce(category, str(verified.sub))
    scope = (
        ServiceScope(verified.scope.project_id, verified.scope.environment_id)
        if verified.scope is not None
        else None
    )
    return CurrentActor(
        id=verified.sub, actor=Actor(actor_type=verified.actor_type, scope=scope), token=verified
    )


CurrentActorDep = Annotated[CurrentActor, Depends(get_current_actor)]


# --- Autorización (Algoritmo 5 del Cap. 6; H-14, H-23) ------------------------------------------


@dataclass(frozen=True)
class Authorizer:
    """Puente API → Módulo RBAC para una petición.

    Uso en cada ruta por identificador (spec Fase 5 §4): primero se carga el recurso para
    conocer su proyecto y ambiente; si no existe (o está archivado) → 404 sin registro. Después
    ``require`` aplica la regla 404/403 generalizada de H-14:

    1. El actor no puede ejercer el permiso y el recurso **no le es visible** → 404
       ``resource-not-found``, con el mismo cuerpo que un recurso inexistente.
    2. No puede ejercerlo, pero el recurso sí le es visible → 403 ``permission-denied``.
    3. Puede → la ruta continúa.

    Las asignaciones se leen de la BD en cada petición (``LoadAssignments``); el claim ``roles``
    del JWT no autoriza nada. La denegación es por omisión (OWASP ASVS V4.1.5) y la decisión se
    toma en el servidor en cada petición (OWASP ASVS V4.1.3).
    """

    current: CurrentActor
    access: ActorAccess
    session: AsyncSession
    service: AccessService

    @property
    def operation_actor(self) -> OperationActor:
        """El actor tal como lo registra el Servicio de Registro de Operaciones."""
        return self.access.operation_actor

    def allows(self, permission: Permission, ctx: AccessContext) -> bool:
        """``rbac.evaluate`` con las asignaciones vigentes del actor (Algoritmo 5)."""
        return evaluate(self.current.actor, permission, ctx, self.access.assignments)

    def visible_projects(self) -> AllProjects | frozenset[UUID]:
        """Proyectos que el actor puede ver (spec Fase 5 §4.2; H-23c, H-23d)."""
        return visible_projects(self.current.actor, self.access.assignments)

    def audit_scope(self) -> AllProjects | frozenset[UUID]:
        """Proyectos cuya bitácora puede leer el actor (spec Fase 5 §4.3; H-23b).

        - ``audit:read`` de instancia (Administrador) → ``ALL_PROJECTS``.
        - Si no, los proyectos de sus asignaciones donde ``evaluate`` concede ``audit:read`` con
          alcance de proyecto (el Líder Técnico en sus proyectos).
        - Conjunto vacío = sin ``audit:read`` en ningún contexto (Desarrollador, service account).
        """
        if self.allows(Permission.AUDIT_READ, AccessContext(None, None)):
            return ALL_PROJECTS
        return frozenset(
            a.project_id
            for a in self.access.assignments
            if a.project_id is not None
            and self.allows(Permission.AUDIT_READ, AccessContext(a.project_id, None))
        )

    def sees_project(self, project_id: UUID) -> bool:
        """¿Cubre el actor el proyecto o alguno de sus ambientes? (H-23d)."""
        visibles = self.visible_projects()
        return visibles is ALL_PROJECTS or project_id in visibles

    async def require(
        self,
        permission: Permission,
        ctx: AccessContext,
        *,
        visible: bool,
        resource_type: str,
        resource_id: UUID | None,
    ) -> None:
        """Exige ``permission`` en ``ctx``; si falta, 403 o 404 según ``visible`` (H-14)."""
        if self.allows(permission, ctx):
            return
        await self.deny(
            403 if visible else 404,
            permission,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=ctx.project_id,
            environment_id=ctx.environment_id,
        )

    async def deny(
        self,
        status: int,
        permission: Permission,
        *,
        resource_type: str,
        resource_id: UUID | None,
        project_id: UUID | None,
        environment_id: UUID | None = None,
    ) -> NoReturn:
        """Registra ``access_denied`` en su propia transacción y lanza el 403 o 404 (spec Fase
        5 §5.2, §5.4). El detalle del 403 nombra el permiso, nunca el recurso ni los roles; el
        del 404 es el genérico, idéntico al de un recurso inexistente."""
        await self.service.record_denial(
            self.session,
            self.operation_actor,
            permission=permission.value,
            status=status,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
            environment_id=environment_id,
        )
        if status == 403:
            raise ApiProblem(403, "permission-denied", f"Falta el permiso {permission.value}.")
        raise ApiProblem(404, "resource-not-found")


async def get_authorizer(
    current: CurrentActorDep, session: SessionDep, client: ClientInfoDep
) -> Authorizer:
    """Dependencia de autorización: autentica (``get_current_actor``) y carga las asignaciones
    vigentes del actor para esta petición."""
    service = AccessService()
    access = await service.load(session, current.id, current.actor, client)
    return Authorizer(current=current, access=access, session=session, service=service)


AuthorizerDep = Annotated[Authorizer, Depends(get_authorizer)]
