"""Dos rotaciones simultáneas del mismo secreto terminan en las versiones 2 y 3, sin error (H-10).

Excepción al aislamiento por transacción revertida: dos rotaciones reales necesitan dos
conexiones, y una conexión no ve lo que otra no ha confirmado. Por eso esta prueba **confirma**
sus datos y los borra en el teardown con ``TRUNCATE ... CASCADE`` (todas las tablas salvo
``roles``, que es catálogo de la migración). También limpia al inicio, por si una ejecución
anterior se interrumpió.

Superposición determinista: una tercera sesión toma el bloqueo ``FOR UPDATE`` del secreto
antes de lanzar las dos rotaciones; la prueba espera en ``pg_stat_activity`` a que ambas estén
bloqueadas y solo entonces lo suelta. Sin el ``FOR UPDATE`` del servicio, ambas calcularían
N+1 = 2 y la segunda fallaría por ``UNIQUE (secret_id, version_number)``.
"""

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from tests.integration.conftest import LECTOR_PRUEBA, PASSPHRASE_PRUEBA, actor_humano, crear_alcance

from portero.crypto.engine import CryptoEngine
from portero.crypto.kek import KdfParams
from portero.db.models import Secret, SecretVersion
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

_TRUNCATE = text(
    "TRUNCATE secret_versions, secrets, service_accounts, user_role_assignments, "
    "environments, projects, audit_logs, revoked_tokens, users, kek_versions CASCADE"
)
_ESPERANDO_BLOQUEO = text(
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
)


@pytest.fixture
async def sesiones(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Fábrica de sesiones con datos confirmados; limpia antes y después."""
    async with engine.begin() as conn:
        await conn.execute(_TRUNCATE)
    yield async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.execute(_TRUNCATE)


async def _esperar_bloqueadas(fabrica: async_sessionmaker[AsyncSession], n: int) -> None:
    async with fabrica() as s:
        for _ in range(200):  # hasta ~10 s
            if (await s.scalar(_ESPERANDO_BLOQUEO) or 0) >= n:
                return
            await s.rollback()  # nueva instantánea de pg_stat_activity
            await asyncio.sleep(0.05)
    pytest.fail(f"las {n} rotaciones no llegaron a esperar el bloqueo")


async def test_dos_rotaciones_concurrentes_dan_versiones_2_y_3(
    sesiones: async_sessionmaker[AsyncSession], parametros_argon2_solo_pruebas: KdfParams
) -> None:
    async with sesiones() as s:
        km = await load_key_manager(s, PASSPHRASE_PRUEBA, new_params=parametros_argon2_solo_pruebas)
    try:
        servicio = SecretService(CryptoEngine(km))
        async with sesiones() as s:
            alcance = await crear_alcance(s)
            ref = await servicio.create_secret(
                s,
                project_id=alcance.project_id,
                environment_id=alcance.environment_id,
                name="DB_PASSWORD",
                value=bytearray(b"marcador-de-prueba-v1"),
                actor=actor_humano(alcance.user_id),
            )
        secret_id = ref.secret_id
        valores = {
            "A": b"marcador-de-prueba-rotacion-A",
            "B": b"marcador-de-prueba-rotacion-B",
        }

        async def rotar(etiqueta: str) -> tuple[str, int]:
            async with sesiones() as s:
                r = await servicio.rotate_secret(
                    s, secret_id, bytearray(valores[etiqueta]), actor=actor_humano(alcance.user_id)
                )
                return etiqueta, r.version_number

        async with sesiones() as bloqueo:
            await bloqueo.execute(select(Secret.id).where(Secret.id == secret_id).with_for_update())
            tareas = [asyncio.create_task(rotar("A")), asyncio.create_task(rotar("B"))]
            await _esperar_bloqueadas(sesiones, 2)
            await bloqueo.rollback()  # suelta el bloqueo: compiten A y B
            resultados = dict(await asyncio.gather(*tareas))

        assert sorted(resultados.values()) == [2, 3]

        async with sesiones() as s:
            numeros = (
                await s.scalars(
                    select(SecretVersion.version_number)
                    .where(SecretVersion.secret_id == secret_id)
                    .order_by(SecretVersion.version_number)
                )
            ).all()
            assert list(numeros) == [1, 2, 3]
            secreto = await s.get(Secret, secret_id)
            v3 = await s.scalar(
                select(SecretVersion.id).where(
                    SecretVersion.secret_id == secret_id, SecretVersion.version_number == 3
                )
            )
            assert secreto is not None and secreto.current_version_id == v3
            # Cada versión descifra al valor de la rotación que la creó.
            for etiqueta, numero in resultados.items():
                assert (
                    await servicio.read_secret_value(s, secret_id, numero, actor=LECTOR_PRUEBA)
                    == valores[etiqueta]
                )
            ultimo = next(e for e, n in resultados.items() if n == 3)
            assert (
                await servicio.read_secret_value(s, secret_id, actor=LECTOR_PRUEBA)
                == valores[ultimo]
            )
    finally:
        km.close()


async def test_sin_datos_residuales(engine: AsyncEngine) -> None:
    """Comprueba que la prueba concurrente limpió lo que confirmó."""
    async with engine.connect() as conn:
        for tabla in ("users", "secrets", "secret_versions", "kek_versions"):
            assert await conn.scalar(text(f"SELECT count(*) FROM {tabla}")) == 0  # noqa: S608
        assert await conn.scalar(text("SELECT count(*) FROM roles")) == 3
