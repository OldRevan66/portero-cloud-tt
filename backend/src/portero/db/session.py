"""Motor y fábrica de sesiones asíncronas de SQLAlchemy hacia PostgreSQL 16 con asyncpg
(Cap. 6 §Stack backend).
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from portero.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Crea el motor a partir de ``PORTERO_DATABASE_URL`` (``postgresql+asyncpg://...``).

    ``hide_parameters`` evita que los valores de una sentencia fallida (p. ej. el ciphertext o
    un hash) aparezcan en el texto de la excepción ni en los logs (OWASP ASVS V7.1.1).
    """
    return create_async_engine(
        settings.database_url.get_secret_value(), pool_pre_ping=True, hide_parameters=True
    )


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Fábrica de sesiones. ``expire_on_commit=False``: tras ``commit`` los objetos siguen
    legibles sin otra consulta (en modo asíncrono una recarga implícita fallaría)."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def ping(session: AsyncSession) -> None:
    """``SELECT 1``: comprueba que la BD responde (``GET /api/v1/health/ready``, spec Fase 5
    §3.8). Si no responde, propaga la excepción de SQLAlchemy o del controlador."""
    await session.execute(text("SELECT 1"))
