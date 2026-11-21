"""Fixtures compartidas por todas las pruebas."""

import os

import pytest

from portero.config import Settings
from portero.crypto.kek import KdfParams


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Configuración de prueba con marcadores obvios.

    Nunca lee el ``.env`` real y descarta cualquier ``PORTERO_*`` del entorno del sistema,
    para que el resultado de las pruebas no dependa de la máquina.
    """
    for nombre in list(os.environ):
        if nombre.upper().startswith("PORTERO_"):
            monkeypatch.delenv(nombre)
    return Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://portero:test@localhost:5433/portero_test",
        kek_passphrase="marcador-de-prueba-no-es-secreto",  # noqa: S106
        jwt_private_key="marcador-de-prueba-no-es-una-clave",  # noqa: S106
        jwt_issuer="https://portero.example.test",
    )


@pytest.fixture
def parametros_argon2_solo_pruebas() -> KdfParams:
    """Parámetros de Argon2id REDUCIDOS para derivar la KEK. SOLO PRUEBAS.

    Producción usa m=131072 KiB, t=4, p=1 (Cap. 6, tabla de algoritmos; spec §1.2), lo que tarda
    del orden de un segundo por derivación. Aquí se baja a 1 MiB y una pasada para que la suite
    sea rápida. Nunca se usan fuera de ``tests/``: el código de producción toma por omisión
    ``PARAMETROS_KEK_PRODUCCION``, y ``test_parametros_de_produccion_son_los_del_cap6`` fija esos
    valores para que esta fixture no se cuele como valor por omisión.
    """
    return KdfParams(memory_cost_kib=1024, time_cost=1, parallelism=1)
