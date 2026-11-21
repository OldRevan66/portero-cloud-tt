"""El último Administrador activo (CU-05; spec Fase 5 §2, Usuarios y Asignaciones; H-38).

Invariante: la instancia conserva siempre al menos un usuario **activo** con una asignación de
instancia de Administrador. Sin él nadie tiene ``users:manage`` y la instancia queda sin
gestión desde la API: solo se recupera con ``portero create-admin`` en el servidor (H-38).

Toda operación que lo rompería responde 409 ``conflict`` y no cambia nada, sea cual sea la vía:
``PATCH {"is_active": false}``, ``DELETE /users/{uid}`` o quitar la asignación.
"""

from uuid import UUID

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    Escenario,
    _crear_usuario_sin_login,
    assert_problema,
    bearer,
)

from portero.auth.tokens import issue_access_token
from portero.config import Settings
from portero.crypto.signing import JwtSigner
from portero.db.models import User, UserRoleAssignment
from portero.rbac.permissions import Role

API = "/api/v1"


async def _asignacion_admin(db_session: AsyncSession, user_id: UUID) -> UUID:
    asignacion = await db_session.scalar(
        select(UserRoleAssignment.id).where(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.role_id == Role.ADMINISTRADOR,
            UserRoleAssignment.project_id.is_(None),
        )
    )
    assert asignacion is not None
    return asignacion


async def _admins_activos(db_session: AsyncSession) -> int:
    filas = await db_session.scalars(
        select(User.id)
        .join(UserRoleAssignment, UserRoleAssignment.user_id == User.id)
        .where(
            User.is_active.is_(True),
            UserRoleAssignment.role_id == Role.ADMINISTRADOR,
            UserRoleAssignment.project_id.is_(None),
        )
        .execution_options(populate_existing=True)
    )
    return len(set(filas))


async def _segundo_admin(
    db_session: AsyncSession, signer: JwtSigner, settings: Settings, *, activo: bool = True
) -> tuple[UUID, dict[str, str]]:
    """Otro Administrador de instancia con su access token."""
    user = await _crear_usuario_sin_login(db_session, "admin2", [(Role.ADMINISTRADOR, None, None)])
    user.is_active = activo
    await db_session.commit()
    token = issue_access_token(signer, user_id=user.id, roles=[], issuer=settings.jwt_issuer)
    return user.id, bearer(token.token)


def _quitar_asignacion(user_id: UUID, asignacion: UUID) -> str:
    return f"{API}/users/{user_id}/role-assignments/{asignacion}"


# --- Un solo Administrador -----------------------------------------------------------------------


async def test_unico_admin_no_se_desactiva_por_patch(
    cliente: AsyncClient, db_session: AsyncSession, escenario: Escenario
) -> None:
    admin = escenario.ids["admin"]

    respuesta = await cliente.patch(
        f"{API}/users/{admin}", json={"is_active": False}, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")
    assert await _admins_activos(db_session) == 1


async def test_unico_admin_no_se_desactiva_por_delete(
    cliente: AsyncClient, db_session: AsyncSession, escenario: Escenario
) -> None:
    admin = escenario.ids["admin"]

    respuesta = await cliente.delete(f"{API}/users/{admin}", headers=escenario.h("admin"))

    assert_problema(respuesta, 409, "conflict")
    assert await _admins_activos(db_session) == 1


async def test_unico_admin_no_se_quita_su_asignacion(
    cliente: AsyncClient, db_session: AsyncSession, escenario: Escenario
) -> None:
    admin = escenario.ids["admin"]
    asignacion = await _asignacion_admin(db_session, admin)

    respuesta = await cliente.delete(
        _quitar_asignacion(admin, asignacion), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")
    assert await _admins_activos(db_session) == 1


# --- Dos Administradores -------------------------------------------------------------------------


async def test_tras_desactivar_al_otro_admin_el_restante_no_se_quita_el_rol(
    cliente: AsyncClient,
    db_session: AsyncSession,
    escenario: Escenario,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    admin = escenario.ids["admin"]
    admin2, h_admin2 = await _segundo_admin(db_session, signer_app, settings_app)

    desactivar = await cliente.delete(f"{API}/users/{admin2}", headers=escenario.h("admin"))
    assert desactivar.status_code == 204
    # El desactivado ya no puede actuar (H-37): queda un solo Administrador activo.
    me = await cliente.get(f"{API}/auth/me", headers=h_admin2)
    assert_problema(me, 401, "authentication-failed")

    asignacion = await _asignacion_admin(db_session, admin)
    quitar = await cliente.delete(
        _quitar_asignacion(admin, asignacion), headers=escenario.h("admin")
    )
    assert_problema(quitar, 409, "conflict")
    desactivarse = await cliente.patch(
        f"{API}/users/{admin}", json={"is_active": False}, headers=escenario.h("admin")
    )
    assert_problema(desactivarse, 409, "conflict")
    assert await _admins_activos(db_session) == 1


async def test_tras_quitar_el_rol_al_otro_admin_el_restante_no_se_quita_el_suyo(
    cliente: AsyncClient,
    db_session: AsyncSession,
    escenario: Escenario,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    admin = escenario.ids["admin"]
    admin2, h_admin2 = await _segundo_admin(db_session, signer_app, settings_app)

    quitar_al_otro = await cliente.delete(
        _quitar_asignacion(admin, await _asignacion_admin(db_session, admin)), headers=h_admin2
    )
    assert quitar_al_otro.status_code == 204

    quitarse = await cliente.delete(
        _quitar_asignacion(admin2, await _asignacion_admin(db_session, admin2)),
        headers=h_admin2,
    )
    assert_problema(quitarse, 409, "conflict")
    assert await _admins_activos(db_session) == 1


async def test_un_admin_inactivo_no_cuenta_como_respaldo(
    cliente: AsyncClient,
    db_session: AsyncSession,
    escenario: Escenario,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    """Un Administrador desactivado conserva su asignación, pero no puede iniciar sesión: no
    cuenta para el invariante."""
    admin = escenario.ids["admin"]
    await _segundo_admin(db_session, signer_app, settings_app, activo=False)
    asignacion = await _asignacion_admin(db_session, admin)

    respuesta = await cliente.delete(
        _quitar_asignacion(admin, asignacion), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")
    assert await _admins_activos(db_session) == 1


async def test_con_otro_admin_activo_si_se_puede_quitar_el_rol_propio(
    cliente: AsyncClient,
    db_session: AsyncSession,
    escenario: Escenario,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    """Control: la regla no bloquea de más. Con otro Administrador activo, quitarse el rol es
    válido (204)."""
    admin = escenario.ids["admin"]
    await _segundo_admin(db_session, signer_app, settings_app)
    asignacion = await _asignacion_admin(db_session, admin)

    respuesta = await cliente.delete(
        _quitar_asignacion(admin, asignacion), headers=escenario.h("admin")
    )

    assert respuesta.status_code == 204
    assert await _admins_activos(db_session) == 1
