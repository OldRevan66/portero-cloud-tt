"""Cableado del Servicio de Autenticación con el Servicio de Registro de Operaciones, por HTTP
contra la app real (spec Fase 5 §5.2–5.4; H-11, H-12; RF-016, RF-018).

Cada evento de CU-01 deja su fila en ``audit_logs`` con el verbo del catálogo y su ``result``.
La prueba lee la bitácora con el ``db_session`` que comparte la conexión de la app.
"""

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    COOKIE_REFRESH,
    bearer,
    crear_usuario,
    login,
    valor_refresh,
)

from portero.db.models import AuditLog, User

CONTRASENA_EQUIVOCADA = "marcador-prueba-clave-equivocada"  # noqa: S105


async def _ultimo(db_session: AsyncSession) -> AuditLog:
    # populate_existing relee la fila sin expirar los demás objetos (p. ej. el usuario del
    # fixture, cuyo id se compara después).
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(1)
        .execution_options(populate_existing=True)
    )
    fila = await db_session.scalar(stmt)
    assert fila is not None, "no se registró ninguna operación"
    return fila


async def _contar(db_session: AsyncSession) -> int:
    return await db_session.scalar(select(func.count()).select_from(AuditLog)) or 0


def _texto_de_la_fila(fila: AuditLog) -> str:
    return " ".join(str(getattr(fila, c.key)) for c in AuditLog.__table__.columns)


# --- login ---------------------------------------------------------------------------------------


async def test_login_exitoso_registra_login(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    assert (await login(cliente)).status_code == 200

    fila = await _ultimo(db_session)

    assert (fila.verb, fila.result) == ("login", "success")
    assert fila.actor_type == "human"
    assert fila.actor_user_id == usuario.id
    assert fila.actor_ref == usuario.email
    assert (fila.resource_type, fila.resource_id) == ("user", usuario.id)
    assert str(fila.ip_address) == "127.0.0.1"
    assert fila.user_agent is not None and "python-httpx" in fila.user_agent
    assert fila.project_id is None and fila.environment_id is None


async def test_login_con_correo_inexistente_registra_login_failed_sin_actor(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    respuesta = await login(cliente, email="nadie@example.com")

    assert respuesta.status_code == 401
    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("login_failed", "failure")
    assert fila.actor_type == "human"
    assert fila.actor_user_id is None
    assert fila.actor_ref == "nadie@example.com"
    assert fila.details == {"reason": "no_existe"}
    assert "no_existe" not in respuesta.text


async def test_login_con_contrasena_incorrecta_registra_sin_la_contrasena(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    respuesta = await login(cliente, password=CONTRASENA_EQUIVOCADA)

    assert respuesta.status_code == 401
    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("login_failed", "failure")
    assert fila.actor_user_id == usuario.id
    assert fila.details == {"reason": "hash"}
    assert CONTRASENA_EQUIVOCADA not in _texto_de_la_fila(fila)


async def test_login_con_cuenta_inactiva_registra_login_failed(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    """La fila queda aunque la respuesta sea 401 (spec §5.4)."""
    inactivo = await crear_usuario(db_session, "inactivo@example.com")
    inactivo.is_active = False
    await db_session.commit()

    assert (await login(cliente, email="inactivo@example.com")).status_code == 401

    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("login_failed", "failure")
    assert fila.actor_user_id == inactivo.id
    assert fila.details == {"reason": "inactiva"}


# --- refresh -------------------------------------------------------------------------------------


async def test_refresh_registra_refresh(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    await login(cliente)

    assert (await cliente.post("/api/v1/auth/refresh")).status_code == 200

    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("refresh", "success")
    assert fila.actor_user_id == usuario.id
    assert (fila.resource_type, fila.resource_id) == ("user", usuario.id)


async def test_refresh_reutilizado_registra_refresh_reused(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    """Posible robo de token (spec §3.2; OWASP JWT Cheat Sheet): queda con el dueño del token."""
    viejo = valor_refresh(await login(cliente))
    assert (await cliente.post("/api/v1/auth/refresh")).status_code == 200
    cliente.cookies.clear()

    respuesta = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={viejo}"}
    )

    assert respuesta.status_code == 401
    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("refresh_reused", "failure")
    assert fila.actor_user_id == usuario.id
    assert viejo not in _texto_de_la_fila(fila)


# --- logout --------------------------------------------------------------------------------------


async def test_logout_registra_logout(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    access = (await login(cliente)).json()["access_token"]

    assert (await cliente.post("/api/v1/auth/logout", headers=bearer(access))).status_code == 204

    fila = await _ultimo(db_session)
    assert (fila.verb, fila.result) == ("logout", "success")
    assert fila.actor_user_id == usuario.id
    assert access not in _texto_de_la_fila(fila)


# --- Lo que no se registra -----------------------------------------------------------------------


async def test_401_de_la_dependencia_bearer_no_se_registra(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    """Sin actor confiable no hay registro; así tomar el lock de la cadena no se vuelve una vía
    de denegación de servicio (spec §5.2)."""
    antes = await _contar(db_session)

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer("no.es.un.jwt"))

    assert respuesta.status_code == 401
    db_session.expire_all()
    assert await _contar(db_session) == antes


# --- Integridad de la cadena tras el flujo completo ----------------------------------------------


async def test_la_cadena_queda_integra_tras_login_refresh_y_logout(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    await login(cliente)
    access = (await cliente.post("/api/v1/auth/refresh")).json()["access_token"]
    await cliente.post("/api/v1/auth/logout", headers=bearer(access))
    from portero.oplog.service import OperationLogService  # aquí, para no tapar las demás fallas

    db_session.expire_all()
    verbos = list(
        await db_session.scalars(select(AuditLog.verb).order_by(AuditLog.id.desc()).limit(3))
    )

    resultado = await OperationLogService().verify_chain(db_session)

    assert verbos == ["logout", "refresh", "login"]
    assert resultado.ok is True
    assert resultado.broken == []
