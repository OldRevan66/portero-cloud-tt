"""Fixtures del API REST Gateway: la aplicación real (``create_app`` con su lifespan) contra
db-test, con httpx ``ASGITransport``.

``ASGITransport`` no ejecuta el lifespan de la aplicación; por eso el fixture ``app`` entra a
``app.router.lifespan_context`` a mano: así se deriva la KEK, se carga el ``JwtSigner`` y se
prepara el hash señuelo igual que al arrancar uvicorn.

El cliente usa ``https://test``: el jar de cookies de httpx no envía una cookie ``Secure`` por
``http``, igual que un navegador.
"""

import hashlib
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from http.cookies import SimpleCookie
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from portero.auth.passwords import hash_password
from portero.auth.tokens import issue_access_token, issue_service_token
from portero.config import Settings
from portero.crypto.engine import CryptoEngine
from portero.crypto.kek import KdfParams
from portero.crypto.signing import JwtSigner
from portero.db.models import (
    AuditLog,
    Environment,
    Project,
    ServiceAccount,
    User,
    UserRoleAssignment,
)
from portero.main import create_app
from portero.rbac.permissions import Role
from portero.secrets_mgmt.service import SecretService

CONTRASENA = "marcador-prueba-clave-larga"  # noqa: S105  # marcador de prueba, no un secreto
COOKIE_REFRESH = "portero_refresh"
RUTA_COOKIE = "/api/v1/auth"
TIPO_ERROR = "https://portero-cloud.example/errors/"
CAMPOS_PROBLEMA = {"type", "title", "status", "detail", "instance", "trace_id"}


@pytest.fixture
async def db_session(
    fabrica_app: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Sobrescribe el ``db_session`` general: aquí la prueba siembra datos en la **misma**
    conexión que usa la app, para que ésta los vea sin confirmarlos de verdad."""
    async with fabrica_app() as session:
        yield session


@pytest.fixture
async def app(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
) -> AsyncIterator[FastAPI]:
    """Aplicación real con su lifespan; KEK con parámetros Argon2 REDUCIDOS (solo pruebas)."""
    aplicacion = create_app(
        settings_app, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas
    )
    async with aplicacion.router.lifespan_context(aplicacion):
        yield aplicacion


@pytest.fixture
async def cliente(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        yield c


@pytest.fixture
async def cliente_sin_relanzar(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Cliente que recibe el 500 en lugar de la excepción. Starlette vuelve a lanzar la
    excepción no controlada después de responder (igual que en
    ``tests/unit/api/test_errors.py``)."""
    transporte = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transporte, base_url="https://test") as c:
        yield c


@pytest.fixture
def signer_app(settings_app: Settings) -> JwtSigner:
    """El mismo firmante que carga la app (misma clave, mismo ``kid``), para emitir tokens que
    la app acepte, p. ej. un PAT."""
    return JwtSigner.from_pem(settings_app.jwt_private_key.get_secret_value().encode())


# --- Datos ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Asignacion:
    role_id: int
    project_id: UUID | None = None
    environment_id: UUID | None = None


async def crear_usuario(
    session: AsyncSession,
    email: str = "ana@example.com",
    *,
    name: str = "Ana",
    asignaciones: Sequence[Asignacion] = (Asignacion(role_id=1),),
) -> User:
    """Usuario activo con la contraseña ``CONTRASENA`` hasheada de verdad (Argon2id)."""
    user = User(email=email, password_hash=hash_password(CONTRASENA), name=name)
    session.add(user)
    await session.flush()
    for a in asignaciones:
        session.add(
            UserRoleAssignment(
                user_id=user.id,
                role_id=a.role_id,
                project_id=a.project_id,
                environment_id=a.environment_id,
            )
        )
    await session.commit()
    return user


@pytest.fixture
async def usuario(db_session: AsyncSession) -> User:
    return await crear_usuario(db_session)


# --- Auxiliares HTTP -----------------------------------------------------------------------------


async def login(
    cliente: AsyncClient, email: str = "ana@example.com", password: str = CONTRASENA
) -> httpx.Response:
    return await cliente.post("/api/v1/auth/login", json={"email": email, "password": password})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def cookie_refresh(response: httpx.Response) -> SimpleCookie:
    """La cookie ``portero_refresh`` de las cabeceras ``Set-Cookie`` de la respuesta."""
    for valor in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(valor)
        if COOKIE_REFRESH in cookie:
            return cookie
    raise AssertionError("la respuesta no trae Set-Cookie de portero_refresh")


def valor_refresh(response: httpx.Response) -> str:
    return cookie_refresh(response)[COOKIE_REFRESH].value


def atributos_refresh(response: httpx.Response) -> dict[str, str]:
    """Atributos de la cookie de refresh con nombres y valores en minúsculas (Starlette escribe
    ``SameSite=strict``; RFC 6265 no distingue mayúsculas en los atributos)."""
    morsel = cookie_refresh(response)[COOKIE_REFRESH]
    return {k.lower(): str(v).lower() for k, v in morsel.items() if v not in ("", None)}


def assert_problema(response: httpx.Response, status: int, tipo: str) -> dict[str, object]:
    """Comprueba un Problem Details (RFC 9457) y devuelve su cuerpo."""
    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/problem+json")
    cuerpo = response.json()
    assert CAMPOS_PROBLEMA <= set(cuerpo)
    assert cuerpo["type"] == TIPO_ERROR + tipo
    assert cuerpo["status"] == status
    return cuerpo


# --- Escenario de autorización (compartido por las pruebas del API) -------------------------------
#
# Proyectos A y B con sus tres ambientes, y cinco usuarios: Administrador global, Líder de A,
# Desarrollador de A/dev, Líder de B y Desarrollador de B/dev. Los access tokens se emiten directo
# con el firmante de la app (el login se prueba aparte), para no pagar un Argon2id por usuario
# y por prueba.

AMBIENTES = ("development", "staging", "production")


@dataclass(frozen=True)
class Proyecto:
    id: UUID
    ambientes: dict[str, UUID]  # nombre → id

    @property
    def dev(self) -> UUID:
        return self.ambientes["development"]

    @property
    def prod(self) -> UUID:
        return self.ambientes["production"]


@dataclass(frozen=True)
class Escenario:
    a: Proyecto
    b: Proyecto
    ids: dict[str, UUID]  # usuario → users.id
    tokens: dict[str, str]  # usuario → access token

    def h(self, usuario: str) -> dict[str, str]:
        """Cabecera ``Authorization`` del usuario."""
        return bearer(self.tokens[usuario])


async def _crear_usuario_sin_login(
    session: AsyncSession, nombre: str, asignaciones: Sequence[tuple[int, UUID | None, UUID | None]]
) -> User:
    user = User(
        email=f"{nombre}@example.com",
        password_hash="marcador-no-es-un-hash",  # noqa: S106  # no se usa: no hay login
        name=nombre,
    )
    session.add(user)
    await session.flush()
    for role_id, project_id, environment_id in asignaciones:
        session.add(
            UserRoleAssignment(
                user_id=user.id,
                role_id=role_id,
                project_id=project_id,
                environment_id=environment_id,
            )
        )
    await session.flush()
    return user


async def _crear_proyecto(session: AsyncSession, nombre: str, creador: UUID) -> Proyecto:
    proyecto = Project(name=nombre, created_by=creador)
    session.add(proyecto)
    await session.flush()
    ambientes = {}
    for nombre_amb in AMBIENTES:
        env = Environment(project_id=proyecto.id, name=nombre_amb)
        session.add(env)
        await session.flush()
        ambientes[nombre_amb] = env.id
    return Proyecto(proyecto.id, ambientes)


@pytest.fixture
async def escenario(
    db_session: AsyncSession, signer_app: JwtSigner, settings_app: Settings
) -> Escenario:
    admin = await _crear_usuario_sin_login(db_session, "admin", [(Role.ADMINISTRADOR, None, None)])
    a = await _crear_proyecto(db_session, "proyecto-a", admin.id)
    b = await _crear_proyecto(db_session, "proyecto-b", admin.id)
    usuarios = {
        "admin": admin,
        "lider_a": await _crear_usuario_sin_login(
            db_session, "lider_a", [(Role.LIDER_TECNICO, a.id, None)]
        ),
        "dev_a": await _crear_usuario_sin_login(
            db_session, "dev_a", [(Role.DESARROLLADOR, a.id, a.dev)]
        ),
        "lider_b": await _crear_usuario_sin_login(
            db_session, "lider_b", [(Role.LIDER_TECNICO, b.id, None)]
        ),
        "dev_b": await _crear_usuario_sin_login(
            db_session, "dev_b", [(Role.DESARROLLADOR, b.id, b.dev)]
        ),
    }
    await db_session.commit()
    tokens = {
        nombre: issue_access_token(
            signer_app, user_id=u.id, roles=[], issuer=settings_app.jwt_issuer
        ).token
        for nombre, u in usuarios.items()
    }
    return Escenario(a, b, {n: u.id for n, u in usuarios.items()}, tokens)


@pytest.fixture
def servicio_app(app: FastAPI) -> SecretService:
    """Servicio de Gestión de Secretos con la KEK que derivó la app al arrancar."""
    return SecretService(CryptoEngine(app.state.key_manager))


async def pat_de_a_dev(
    db_session: AsyncSession, signer: JwtSigner, settings: Settings, esc: Escenario
) -> str:
    """Service account de A/dev con su PAT; solo se guarda SHA-256(token) (spec núcleo §3.3)."""
    cuenta_id = uuid4()
    pat = issue_service_token(
        signer,
        service_account_id=cuenta_id,
        project_id=esc.a.id,
        environment_id=esc.a.dev,
        expires_at=None,
        issuer=settings.jwt_issuer,
    )
    db_session.add(
        ServiceAccount(
            id=cuenta_id,
            name="ci-prueba",
            project_id=esc.a.id,
            environment_id=esc.a.dev,
            token_hash=hashlib.sha256(pat.token.encode()).hexdigest(),
            token_prefix=pat.token[-8:],  # H-42
            created_by=esc.ids["admin"],
        )
    )
    await db_session.commit()
    return pat.token


# --- Bitácora ------------------------------------------------------------------------------------


async def ultimo_registro(db_session: AsyncSession) -> AuditLog:
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(1)
        .execution_options(populate_existing=True)
    )
    fila = await db_session.scalar(stmt)
    assert fila is not None, "no se registró ninguna operación"
    return fila


async def contar_registros(db_session: AsyncSession) -> int:
    return await db_session.scalar(select(func.count()).select_from(AuditLog)) or 0


async def assert_denegacion(
    db_session: AsyncSession,
    *,
    actor_id: UUID,
    permiso: str,
    status: int,
    project_id: UUID | None,
    resource_type: str = "project",
) -> None:
    """La fila ``access_denied`` de la última petición (spec Fase 5 §5.2–5.4)."""
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == ("access_denied", "failure")
    assert fila.actor_type == "human"
    assert fila.actor_user_id == actor_id
    assert fila.resource_type == resource_type
    assert fila.project_id == project_id
    assert fila.details == {"permission": permiso, "status": status}


async def assert_escritura(
    db_session: AsyncSession,
    *,
    verbo: str,
    actor_id: UUID,
    resource_type: str,
    resource_id: UUID,
    project_id: UUID,
    environment_id: UUID | None = None,
) -> AuditLog:
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == (verbo, "success")
    assert fila.actor_type == "human"
    assert fila.actor_user_id == actor_id
    assert (fila.resource_type, fila.resource_id) == (resource_type, resource_id)
    assert fila.project_id == project_id
    assert fila.environment_id == environment_id
    return fila
