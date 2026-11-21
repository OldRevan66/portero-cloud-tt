"""Dos Administradores se quitan el rol al mismo tiempo: no deben quedar cero (H-59).

Igual que ``test_borrado_ambiente_concurrente.py``: dos transacciones reales necesitan dos
conexiones, así que la prueba **confirma** sus datos y los borra con ``TRUNCATE ... CASCADE``
antes y después.

Superposición determinista: la sesión 1 reproduce los pasos de ``UserService.revoke_role`` hasta
antes del ``commit`` (toma el bloqueo de Administradores y borra la asignación de A sin
confirmar). Se lanza el ``revoke_role`` de B en la sesión 2 y la prueba espera en
``pg_stat_activity`` a que quede bloqueado; entonces la sesión 1 confirma.

- Con el bloqueo, la sesión 2 espera **antes** de contar, ve que A ya no es Administrador y
  responde 409: queda B.
- Sin él, la sesión 2 cuenta a A (su borrado no está confirmado), borra la asignación de B y
  ambas confirman: cero Administradores.
"""

import asyncio
from collections.abc import AsyncIterator
from uuid import UUID

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from tests.integration.conftest import actor_humano

from portero.db.models import User, UserRoleAssignment
from portero.db.repositories.user import UserRepository
from portero.management.errors import LastActiveAdministratorError
from portero.management.users import UserService
from portero.rbac.permissions import Role

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


async def _crear_admin(session: AsyncSession, nombre: str) -> tuple[UUID, UUID]:
    """Usuario activo con una asignación de instancia de Administrador: (usuario, asignación)."""
    user = User(
        email=f"{nombre}@example.com",
        password_hash="marcador-no-es-un-hash",  # noqa: S106
        name=nombre,
    )
    session.add(user)
    await session.flush()
    asignacion = UserRoleAssignment(user_id=user.id, role_id=Role.ADMINISTRADOR)
    session.add(asignacion)
    await session.commit()
    return user.id, asignacion.id


async def _esperar_bloqueada(fabrica: async_sessionmaker[AsyncSession]) -> None:
    async with fabrica() as s:
        for _ in range(200):  # hasta ~10 s
            if (await s.scalar(_ESPERANDO_BLOQUEO) or 0) >= 1:
                return
            await s.rollback()  # nueva instantánea de pg_stat_activity
            await asyncio.sleep(0.05)
    pytest.fail("la segunda revocación no llegó a esperar el bloqueo")


async def test_dos_admins_que_se_quitan_el_rol_a_la_vez_no_dejan_cero(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    async with sesiones() as s:
        _, asignacion_a = await _crear_admin(s, "admin-a")
        admin_b, asignacion_b = await _crear_admin(s, "admin-b")

    async with sesiones() as primera, sesiones() as segunda:
        repo = UserRepository(primera)
        await repo.lock_administrators()
        propia_a = await primera.get(UserRoleAssignment, asignacion_a)
        assert propia_a is not None
        await repo.delete_assignment(propia_a)  # sin confirmar: A sigue contando para otros

        propia_b = await segunda.get(UserRoleAssignment, asignacion_b)
        assert propia_b is not None
        revocacion = asyncio.create_task(
            UserService().revoke_role(segunda, actor_humano(admin_b), propia_b)
        )
        await _esperar_bloqueada(sesiones)
        await primera.commit()

        with pytest.raises(LastActiveAdministratorError):
            await revocacion

    async with sesiones() as s:
        restantes = await s.scalar(
            select(func.count())
            .select_from(UserRoleAssignment)
            .where(UserRoleAssignment.role_id == Role.ADMINISTRADOR)
        )
        sigue_b = await s.get(UserRoleAssignment, asignacion_b)
    assert restantes == 1
    assert sigue_b is not None
