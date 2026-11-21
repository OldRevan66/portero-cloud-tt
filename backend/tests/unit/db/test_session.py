"""Configuración del motor y de la fábrica de sesiones (sin conectarse a la base)."""

from portero.config import Settings
from portero.db.session import create_engine, create_sessionmaker


async def test_motor_asyncpg_sin_parametros_en_errores(settings: Settings) -> None:
    engine = create_engine(settings)
    try:
        assert engine.url.drivername == "postgresql+asyncpg"  # Cap. 6
        # Ningún valor de una sentencia en excepciones ni logs.
        assert engine.sync_engine.hide_parameters
        fabrica = create_sessionmaker(engine)
        assert fabrica.kw["expire_on_commit"] is False
    finally:
        await engine.dispose()
