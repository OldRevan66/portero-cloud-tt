"""Fixtures de integración contra PostgreSQL de pruebas (``docker compose up -d db-test``).

Requisitos: la migración aplicada en db-test
(``PORTERO_DATABASE_URL=<URL de abajo> uv run alembic upgrade head``).

Aislamiento: cada prueba corre dentro de una transacción que se revierte al final. La sesión se
une a esa transacción con ``join_transaction_mode="create_savepoint"``, así que los ``commit`` y
``rollback`` del código bajo prueba operan sobre *savepoints* y nada queda en la base. La única
excepción es la prueba de rotaciones concurrentes, que necesita datos confirmados (ver su
docstring).

Las credenciales de db-test son desechables (``docker-compose.yml``), no son secretos.
"""

import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from portero.config import Settings
from portero.crypto.engine import CryptoEngine
from portero.crypto.kek import KdfParams, KeyManager
from portero.crypto.signing import generate_private_key_pem
from portero.db.models import Environment, Project, User
from portero.oplog.service import OperationActor
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

TEST_DATABASE_URL = os.environ.get(
    "PORTERO_TEST_DATABASE_URL",
    "postgresql+asyncpg://portero:test@localhost:5433/portero_test",
)

# Passphrase de la KEK en pruebas. Marcador obvio: no es un secreto real.
PASSPHRASE_PRUEBA = b"marcador-de-prueba-passphrase-kek"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Marca como ``integration`` todo lo que está en ``tests/integration/``."""
    for item in items:
        if "integration" in item.path.parts:
            item.add_marker(pytest.mark.integration)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Motor por prueba sin pool: pytest-asyncio usa un ciclo de eventos por prueba y asyncpg
    no permite reutilizar conexiones entre ciclos."""
    eng = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, hide_parameters=True)
    yield eng
    await eng.dispose()


@pytest.fixture
async def db_session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Sesión dentro de una transacción que se revierte al terminar la prueba."""
    async with engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(
            bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            await session.close()
            await trans.rollback()


@dataclass(frozen=True)
class Alcance:
    """Usuario, proyecto y ambiente mínimos para crear secretos."""

    user_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID


async def crear_alcance(session: AsyncSession, sufijo: str = "") -> Alcance:
    """Inserta un usuario, un proyecto y un ambiente. ``password_hash`` es un marcador."""
    sufijo = sufijo or uuid.uuid4().hex[:8]
    user = User(
        email=f"prueba-{sufijo}@example.com",
        password_hash="marcador-no-es-un-hash",  # noqa: S106
        name="Usuario de prueba",
    )
    session.add(user)
    await session.flush()
    project = Project(name=f"proyecto-{sufijo}", created_by=user.id)
    session.add(project)
    await session.flush()
    env = Environment(project_id=project.id, name="development")
    session.add(env)
    await session.commit()
    return Alcance(user.id, project.id, env.id)


def actor_humano(user_id: uuid.UUID) -> OperationActor:
    """Actor de las escrituras en las pruebas del servicio: ``create_secret`` y
    ``rotate_secret`` registran la operación y usan su ``actor_user_id`` como ``created_by``."""
    return OperationActor("human", "prueba@example.com", user_id)


LECTOR_PRUEBA = OperationActor("human", "pruebas:lector", None)
"""Actor de las lecturas de verificación en las pruebas del servicio. ``read_secret_value`` exige
un actor (H-11); sin ``actor_user_id`` no depende de que exista un usuario."""


@pytest.fixture
async def alcance(db_session: AsyncSession) -> Alcance:
    return await crear_alcance(db_session)


@pytest.fixture
async def key_manager(
    db_session: AsyncSession, parametros_argon2_solo_pruebas: KdfParams
) -> AsyncIterator[KeyManager]:
    """KEK de pruebas con parámetros Argon2 REDUCIDOS (``parametros_argon2_solo_pruebas``)."""
    km = await load_key_manager(
        db_session, PASSPHRASE_PRUEBA, new_params=parametros_argon2_solo_pruebas
    )
    yield km
    km.close()


@pytest.fixture
def servicio(key_manager: KeyManager) -> SecretService:
    return SecretService(CryptoEngine(key_manager))


# --- Aplicación completa (API REST Gateway, sesión 8) ---------------------------------------------


@pytest.fixture
async def conexion_app(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """Conexión con una transacción externa que se revierte al final.

    La app y la prueba comparten esta conexión: lo que siembra la prueba lo ve la app, y lo que
    la app confirma (``AuthService``, ``load_key_manager``) queda en *savepoints* que se
    descartan con el rollback. Las peticiones de httpx son secuenciales, así que nunca hay dos
    sesiones usando la conexión a la vez.
    """
    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            yield conn
        finally:
            await trans.rollback()


@pytest.fixture
def fabrica_app(conexion_app: AsyncConnection) -> async_sessionmaker[AsyncSession]:
    """Fábrica de sesiones que se inyecta en ``create_app(sessionmaker=...)``."""
    return async_sessionmaker(
        bind=conexion_app, join_transaction_mode="create_savepoint", expire_on_commit=False
    )


@pytest.fixture
def settings_app(settings: Settings) -> Settings:
    """``Settings`` de prueba completas: passphrase de la KEK de pruebas y una clave Ed25519
    generada al vuelo (nunca una clave real ni el ``.env``)."""
    return settings.model_copy(
        update={
            "database_url": SecretStr(TEST_DATABASE_URL),
            "kek_passphrase": SecretStr(PASSPHRASE_PRUEBA.decode()),
            "jwt_private_key": SecretStr(generate_private_key_pem().decode()),
        }
    )
