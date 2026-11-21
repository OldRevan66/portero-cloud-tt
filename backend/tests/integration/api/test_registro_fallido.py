"""Si el Servicio de Registro de Operaciones falla, la operación no ocurre (H-11, H-47; spec Fase 5
§5.4; OWASP ASVS V7.3.3, V7.4.1).

H-47: la cobertura de línea no revelaba que ninguna prueba ejercía las ramas de reversión de los
Servicios de Gestión, de ``logout`` y del registro de ``access_denied``. Cada caso fuerza que
``OperationLogService.record`` falle solo para el verbo de la operación y comprueba dos cosas:

1. la respuesta es 500 ``internal-error`` (no un 2xx ni un 403/404 sin rastro);
2. el cambio no quedó en la BD: escritura y registro se confirman juntos o no se confirman.
"""

from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import Escenario, assert_problema, bearer, login

from portero.db.models import (
    AuditLog,
    Environment,
    Project,
    RevokedToken,
    ServiceAccount,
    User,
    UserRoleAssignment,
)
from portero.oplog.service import OperationEvent, OperationLogService


@pytest.fixture
def falla_el_registro(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Hace que ``record`` falle solo para ``verbo``; los demás verbos se registran normal."""
    original = OperationLogService.record

    def activar(verbo: str) -> None:
        async def record_que_falla(
            self: OperationLogService, session: AsyncSession, event: OperationEvent
        ) -> AuditLog:
            if event.verb == verbo:
                raise RuntimeError("falla simulada del Servicio de Registro de Operaciones")
            return await original(self, session, event)

        monkeypatch.setattr(OperationLogService, "record", record_que_falla)

    return activar


async def _fresco(session: AsyncSession, modelo: type[Any], ident: UUID) -> Any:
    """La fila tal como está en la BD, sin la copia en memoria de la sesión."""
    stmt = select(modelo).where(modelo.id == ident).execution_options(populate_existing=True)
    return await session.scalar(stmt)


async def _contar(session: AsyncSession, verbo: str) -> int:
    total = await session.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.verb == verbo)
    )
    return int(total or 0)


async def _asignacion_de(session: AsyncSession, user_id: UUID) -> UUID:
    ident = await session.scalar(
        select(UserRoleAssignment.id).where(UserRoleAssignment.user_id == user_id)
    )
    assert ident is not None
    return ident


Peticion = Callable[[AsyncClient, Escenario], Awaitable[Any]]


async def test_access_denied_sin_registro_no_responde_403(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    # Toda denegación deja rastro (spec §5.4): si no se puede registrar, tampoco se responde
    # 403/404 como si nada; el cliente recibe 500 y el proyecto no cambia.
    falla_el_registro("access_denied")

    respuesta = await cliente_sin_relanzar.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"description": "intento"},
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert await _contar(db_session, "access_denied") == 0
    proyecto = await _fresco(db_session, Project, escenario.a.id)
    assert proyecto.description is None


async def test_update_project_sin_registro_no_cambia_el_proyecto(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("update_project")

    respuesta = await cliente_sin_relanzar.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"description": "nueva"},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert (await _fresco(db_session, Project, escenario.a.id)).description is None


async def test_update_environment_sin_registro_no_cambia_el_ambiente(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("update_environment")

    respuesta = await cliente_sin_relanzar.patch(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.a.dev}",
        json={"description": "nueva"},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert (await _fresco(db_session, Environment, escenario.a.dev)).description is None


async def test_update_user_sin_registro_no_cambia_el_usuario(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("update_user")

    respuesta = await cliente_sin_relanzar.patch(
        f"/api/v1/users/{escenario.ids['dev_a']}",
        json={"name": "Otro nombre"},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert (await _fresco(db_session, User, escenario.ids["dev_a"])).name == "dev_a"


async def test_deactivate_user_sin_registro_no_desactiva_ni_corta_tokens(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("deactivate_user")

    respuesta = await cliente_sin_relanzar.delete(
        f"/api/v1/users/{escenario.ids['dev_a']}", headers=escenario.h("admin")
    )

    assert_problema(respuesta, 500, "internal-error")
    usuario = await _fresco(db_session, User, escenario.ids["dev_a"])
    assert usuario.is_active
    assert usuario.tokens_invalid_before is None


async def test_assign_role_sin_registro_no_crea_la_asignacion(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("assign_role")

    respuesta = await cliente_sin_relanzar.post(
        f"/api/v1/users/{escenario.ids['dev_b']}/role-assignments",
        json={"role_id": 3, "project_id": str(escenario.a.id), "environment_id": None},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 500, "internal-error")
    total = await db_session.scalar(
        select(func.count())
        .select_from(UserRoleAssignment)
        .where(UserRoleAssignment.user_id == escenario.ids["dev_b"])
    )
    assert total == 1
    assert (await _fresco(db_session, User, escenario.ids["dev_b"])).tokens_invalid_before is None


async def test_revoke_role_sin_registro_conserva_la_asignacion(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    asignacion = await _asignacion_de(db_session, escenario.ids["dev_a"])
    falla_el_registro("revoke_role")

    respuesta = await cliente_sin_relanzar.delete(
        f"/api/v1/users/{escenario.ids['dev_a']}/role-assignments/{asignacion}",
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert await _fresco(db_session, UserRoleAssignment, asignacion) is not None
    assert (await _fresco(db_session, User, escenario.ids["dev_a"])).tokens_invalid_before is None


async def test_create_service_account_sin_registro_no_crea_la_cuenta_ni_entrega_token(
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    falla_el_registro("create_service_account")

    respuesta = await cliente_sin_relanzar.post(
        f"/api/v1/projects/{escenario.a.id}/service-accounts",
        json={"name": "ci"},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 500, "internal-error")
    assert "token" not in respuesta.json()
    assert await db_session.scalar(select(func.count()).select_from(ServiceAccount)) == 0


async def test_revoke_service_account_sin_registro_no_revoca(
    cliente: AsyncClient,
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    falla_el_registro: Callable[[str], None],
) -> None:
    creada = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/service-accounts",
        json={"name": "ci"},
        headers=escenario.h("lider_a"),
    )
    assert creada.status_code == 201
    cuenta = UUID(creada.json()["id"])
    falla_el_registro("revoke_service_account")

    respuesta = await cliente_sin_relanzar.delete(
        f"/api/v1/service-accounts/{cuenta}", headers=escenario.h("lider_a")
    )

    assert_problema(respuesta, 500, "internal-error")
    assert (await _fresco(db_session, ServiceAccount, cuenta)).revoked_at is None


async def test_logout_sin_registro_no_revoca_el_access(
    cliente_sin_relanzar: AsyncClient,
    db_session: AsyncSession,
    usuario: User,
    falla_el_registro: Callable[[str], None],
) -> None:
    access = (await login(cliente_sin_relanzar)).json()["access_token"]
    falla_el_registro("logout")

    respuesta = await cliente_sin_relanzar.post("/api/v1/auth/logout", headers=bearer(access))

    assert_problema(respuesta, 500, "internal-error")
    assert await db_session.scalar(select(func.count()).select_from(RevokedToken)) == 0
    me = await cliente_sin_relanzar.get("/api/v1/auth/me", headers=bearer(access))
    assert me.status_code == 200
