"""Punto de entrada: construye la aplicación FastAPI e incluye los routers del API REST Gateway.

Se usa una fábrica (``create_app``) en lugar de una instancia global para que la configuración
se valide al arrancar y para que las pruebas inyecten su propia ``Settings`` sin leer ``.env``.
Arranque: ``uvicorn --factory portero.main:create_app``.

El trabajo costoso y los secretos se cargan en el **lifespan** (al arrancar el servidor), no en
``create_app``: la KEK (H-06), la clave de firma de JWT y el hash señuelo (H-32). Si algo falla,
el servidor no llega a atender peticiones.
"""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from portero.api.deps import enforce_ip_rate_limit
from portero.api.errors import TraceIdMiddleware, problem_responses, register_error_handlers
from portero.api.middleware import (
    AccessLogMiddleware,
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
    configure_logging,
)
from portero.api.rate_limit import RateLimiter
from portero.api.v1.auth import router as auth_router
from portero.api.v1.health import router as health_router
from portero.api.v1.operations import router as operations_router
from portero.api.v1.projects import router as projects_router
from portero.api.v1.secrets import router as secrets_router
from portero.api.v1.service_accounts import router as service_accounts_router
from portero.api.v1.users import router as users_router
from portero.auth.passwords import prepare_decoy_hash
from portero.auth.service import AuthService
from portero.config import Settings
from portero.crypto.engine import CryptoEngine
from portero.crypto.kek import PARAMETROS_KEK_PRODUCCION, KdfParams
from portero.crypto.signing import JwtSigner, load_ed25519_public_key_pem
from portero.db.session import create_engine, create_sessionmaker
from portero.management.service_accounts import ServiceAccountService
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

API_PREFIX = "/api/v1"

API_DESCRIPTION = (
    "API REST de Portero Cloud, gestor de secretos para equipos de desarrollo. Autenticación con "
    "`Authorization: Bearer <token>` (access token de un usuario o PAT de una Aplicación "
    "Cliente). Los errores siguen RFC 9457 (`application/problem+json`) e incluyen un "
    "`trace_id`. Límites de tasa por minuto: autenticación 10 por IP, lectura de valores 60 por "
    "actor, resto 100 por actor y salud 600 por IP."
)

OPENAPI_TAGS = [
    {"name": "salud", "description": "Sondas para orquestadores de contenedores."},
    {"name": "autenticación", "description": "Login, renovación y cierre de sesión (CU-01)."},
    {"name": "proyectos", "description": "Proyectos y ambientes (CU-07)."},
    {"name": "secretos", "description": "Crear, consultar, revelar y rotar (CU-02 a CU-04)."},
    {"name": "usuarios", "description": "Usuarios y asignaciones de rol (CU-05)."},
    {"name": "aplicaciones cliente", "description": "Service accounts y sus PAT."},
    {"name": "operaciones", "description": "Bitácora con cadena de hashes (CU-06)."},
]


def _lifespan(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession] | None,
    kek_params: KdfParams,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """Arranque y cierre del proceso (spec núcleo §1.6; spec Fase 5 §3.8).

    Al arrancar, en orden:
    1. Motor de BD y fábrica de sesiones (salvo que se inyecte una fábrica, como en pruebas).
    2. ``JwtSigner`` desde ``PORTERO_JWT_PRIVATE_KEY``: un PEM inválido lanza
       ``SigningKeyError`` y el proceso no arranca. Igual con la llave pública de la firma del
       cierre, ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY``, si está definida (H-81). La privada nunca
       se carga aquí.
    3. KEK con ``load_key_manager``: deriva la activa y comprueba su verificador. Una passphrase
       incorrecta lanza ``KekPassphraseError`` y el proceso aborta (H-06).
    4. Hash señuelo de H-08, para que el primer login con un correo inexistente no tarde el
       doble (H-32).
    5. Servicios con estado: Autenticación (con el ``JwtSigner``), Gestión de Secretos (con la
       KEK) y Aplicaciones Cliente (con el emisor de PAT del Servicio de Autenticación).

    Al cerrar: ``KeyManager.close()`` borra la KEK de la memoria y se libera el motor.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = None
        factory = sessionmaker
        if factory is None:
            engine = create_engine(settings)
            factory = create_sessionmaker(engine)
        try:
            signer = JwtSigner.from_pem(settings.jwt_private_key.get_secret_value().encode())
            chain_public_key = (
                load_ed25519_public_key_pem(
                    settings.oplog_signing_public_key.encode(), "PORTERO_OPLOG_SIGNING_PUBLIC_KEY"
                )
                if settings.oplog_signing_public_key is not None
                else None
            )
            async with factory() as session:
                key_manager = await load_key_manager(
                    session,
                    settings.kek_passphrase.get_secret_value().encode(),
                    new_params=kek_params,
                )
            try:
                prepare_decoy_hash()
                app.state.sessionmaker = factory
                app.state.key_manager = key_manager
                app.state.chain_public_key = chain_public_key
                auth_service = AuthService(signer, settings.jwt_issuer)
                app.state.auth_service = auth_service
                app.state.secret_service = SecretService(CryptoEngine(key_manager))
                app.state.service_account_service = ServiceAccountService(
                    auth_service.issue_personal_access_token
                )
                yield
            finally:
                key_manager.close()
                app.state.key_manager = None
                app.state.secret_service = None
        finally:
            if engine is not None:
                await engine.dispose()

    return lifespan


def _install_openapi(app: FastAPI) -> None:
    """Documento OpenAPI sin el 422 que FastAPI agrega por omisión a toda ruta con parámetros.

    Ese 422 describe ``HTTPValidationError``, que esta API nunca responde: los errores de
    esquema son 400 ``validation-error`` (spec Fase 5 §1). El 422 ``semantic-error`` real lo
    declaran solo las rutas que lo producen, con ``problem_responses``."""

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = get_openapi(
                title=app.title,
                version=app.version,
                description=app.description,
                routes=app.routes,
                tags=app.openapi_tags,
            )
            for operations in schema.get("paths", {}).values():
                for operation in operations.values():
                    default = operation.get("responses", {}).get("422", {})
                    if default.get("description") == "Validation Error":
                        del operation["responses"]["422"]
            for name in ("HTTPValidationError", "ValidationError"):
                schema.get("components", {}).get("schemas", {}).pop(name, None)
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]


def create_app(
    settings: Settings | None = None,
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    kek_params: KdfParams = PARAMETROS_KEK_PRODUCCION,
) -> FastAPI:
    """Crea la aplicación de Portero Cloud.

    Si no se recibe ``settings``, se leen del entorno; si falta una variable obligatoria,
    ``Settings()`` lanza ``ValidationError`` y el servidor no arranca.

    ``sessionmaker`` y ``kek_params`` existen **solo para las pruebas**: una fábrica atada a una
    transacción que se revierte y parámetros Argon2id reducidos. En producción se omiten: el
    lifespan crea el motor desde ``PORTERO_DATABASE_URL`` y la KEK usa los parámetros del Cap. 6.
    """
    if settings is None:
        settings = Settings()  # los valores vienen del entorno

    app = FastAPI(
        title="Portero Cloud",
        version="0.1.0",
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        # Límite por IP de autenticación y salud, antes de cualquier otra dependencia (spec §7).
        dependencies=[Depends(enforce_ip_rate_limit)],
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        # Cap. 6 §OpenAPI: el documento vive bajo el prefijo versionado.
        openapi_url=f"{API_PREFIX}/openapi.json" if settings.docs_enabled else None,
        lifespan=_lifespan(settings, sessionmaker, kek_params),
    )
    app.state.settings = settings
    app.state.rate_limiter = RateLimiter(auth_limit=settings.rate_limit_auth_per_minute)
    configure_logging(settings.log_level)

    register_error_handlers(app)
    # ``add_middleware`` envuelve por fuera: el último agregado es el más externo. Orden de
    # afuera hacia adentro: trace_id → cabeceras → log → tamaño del cuerpo → CORS → app.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TraceIdMiddleware)

    # Errores comunes a toda ruta en el OpenAPI; cada ruta agrega los suyos (403, 404, 409...).
    common = problem_responses(400, 401, 413, 429, 500)
    app.include_router(health_router, prefix=API_PREFIX, responses=problem_responses(429))
    for router in (
        auth_router,
        projects_router,
        secrets_router,
        users_router,
        service_accounts_router,
        operations_router,
    ):
        app.include_router(router, prefix=API_PREFIX, responses=common)
    _install_openapi(app)
    return app
