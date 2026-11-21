"""Borrar un ambiente mientras otra transacción le crea una service account (H-49, H-41).

Igual que ``test_rotacion_concurrente.py``: dos transacciones reales necesitan dos conexiones,
así que la prueba **confirma** sus datos y los borra con ``TRUNCATE ... CASCADE`` antes y después.

Superposición determinista: la sesión 1 inserta la service account sin confirmar (el INSERT
toma ``FOR KEY SHARE`` sobre la fila del ambiente por la FK). Se lanza el borrado y la prueba
espera en ``pg_stat_activity`` a que quede bloqueado; entonces la sesión 1 confirma.

- Con el ``FOR UPDATE`` del ambiente al inicio de ``delete_environment``, el borrado espera
  **antes** de comprobar, ve la service account ya confirmada y responde 409.
- Sin él, el borrado comprueba primero (no ve nada sin confirmar), espera en el ``DELETE`` y
  después el CASCADE borra la service account recién creada sin ``revoke_service_account`` en la
  bitácora: justo lo que H-41 quiso impedir.
"""

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from tests.integration.conftest import actor_humano, crear_alcance

from portero.db.models import Environment, ServiceAccount
from portero.management.environments import EnvironmentService
from portero.management.errors import EnvironmentHasServiceAccountsError

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


async def _esperar_bloqueada(fabrica: async_sessionmaker[AsyncSession]) -> None:
    async with fabrica() as s:
        for _ in range(200):  # hasta ~10 s
            if (await s.scalar(_ESPERANDO_BLOQUEO) or 0) >= 1:
                return
            await s.rollback()  # nueva instantánea de pg_stat_activity
            await asyncio.sleep(0.05)
    pytest.fail("el borrado del ambiente no llegó a esperar el bloqueo")


async def test_service_account_creada_durante_el_borrado_no_cae_por_cascade(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    async with sesiones() as s:
        alcance = await crear_alcance(s)
    actor = actor_humano(alcance.user_id)

    async with sesiones() as creadora, sesiones() as borradora:
        creadora.add(
            ServiceAccount(
                name="ci-concurrente",
                project_id=alcance.project_id,
                environment_id=alcance.environment_id,
                token_hash="0" * 64,
                token_prefix="marcador",  # noqa: S106  # marcador de prueba, no un token
                created_by=alcance.user_id,
            )
        )
        await creadora.flush()  # INSERT sin confirmar: FOR KEY SHARE sobre el ambiente

        ambiente = await borradora.get(Environment, alcance.environment_id)
        assert ambiente is not None
        borrado = asyncio.create_task(
            EnvironmentService().delete_environment(borradora, actor, ambiente)
        )
        await _esperar_bloqueada(sesiones)
        await creadora.commit()

        with pytest.raises(EnvironmentHasServiceAccountsError):
            await borrado

    async with sesiones() as s:
        cuentas = await s.scalar(select(func.count()).select_from(ServiceAccount))
        ambiente_sigue = await s.get(Environment, alcance.environment_id)
    assert cuentas == 1
    assert ambiente_sigue is not None
