"""Pruebas de ``UserRepository`` y ``RevokedTokenRepository`` contra db-test (Capa de
Persistencia, Cap. 5; spec núcleo §3.1, spec Fase 5 §3.2–§3.5; H-03, H-37).

Los repositorios no hacen ``commit``; aquí basta ``flush`` para que las escrituras lleguen a la
base dentro de la transacción de la prueba, que se revierte al final.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from tests.integration.conftest import Alcance

from portero.db.models import RevokedToken, User, UserRoleAssignment
from portero.db.repositories.user import RevokedTokenRepository, UserRepository

ADMINISTRADOR = 1
DESARROLLADOR = 3


def _ahora() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


async def _crear_usuario(session: AsyncSession, **campos: object) -> User:
    datos: dict[str, object] = {
        "email": f"usuario-{uuid.uuid4().hex[:8]}@example.com",
        "password_hash": "marcador-no-es-un-hash",
        "name": "Usuario de prueba",
    }
    datos.update(campos)
    user = User(**datos)
    session.add(user)
    await session.flush()
    return user


@pytest.fixture
def sentencias(engine: AsyncEngine) -> Iterator[list[str]]:
    """SQL que emite el motor durante la prueba (para comprobar el ``FOR UPDATE``)."""
    capturadas: list[str] = []

    def _capturar(_conn: object, _cursor: object, statement: str, *_args: object) -> None:
        capturadas.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _capturar)
    yield capturadas
    event.remove(engine.sync_engine, "before_cursor_execute", _capturar)


# --- UserRepository: búsqueda ---------------------------------------------------------------------


async def test_buscar_por_correo_con_for_update(
    db_session: AsyncSession, sentencias: list[str]
) -> None:
    user = await _crear_usuario(db_session, email="ana@example.com")
    sentencias.clear()

    encontrado = await UserRepository(db_session).get_by_email_for_update("ana@example.com")

    assert encontrado is not None
    assert encontrado.id == user.id
    selects = [s for s in sentencias if s.lstrip().upper().startswith("SELECT")]
    assert selects, "no se emitió ningún SELECT"
    assert "FOR UPDATE" in selects[-1].upper()


async def test_buscar_correo_inexistente_devuelve_none(db_session: AsyncSession) -> None:
    assert await UserRepository(db_session).get_by_email_for_update("nadie@example.com") is None


async def test_buscar_por_id(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)
    repo = UserRepository(db_session)

    assert (await repo.get_by_id(user.id)) is not None
    assert await repo.get_by_id(uuid.uuid4()) is None


# --- UserRepository: fallos, bloqueo y éxito (spec núcleo §3.1) -----------------------------------


async def test_registrar_fallo_incrementa_el_contador(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)
    repo = UserRepository(db_session)

    assert await repo.increment_failed_attempts(user) == 1
    assert await repo.increment_failed_attempts(user) == 2

    await db_session.refresh(user)
    assert user.failed_login_attempts == 2


async def test_fijar_locked_until(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)
    hasta = _ahora() + timedelta(minutes=15)

    await UserRepository(db_session).lock_until(user, hasta)

    await db_session.refresh(user)
    assert user.locked_until == hasta


async def test_exito_reinicia_contador_y_bloqueo_y_fija_last_login(
    db_session: AsyncSession,
) -> None:
    user = await _crear_usuario(
        db_session, failed_login_attempts=4, locked_until=_ahora() - timedelta(minutes=1)
    )
    ahora = _ahora()

    await UserRepository(db_session).register_successful_login(user, ahora)

    await db_session.refresh(user)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
    assert user.last_login_at == ahora


async def test_actualizar_hash_de_contrasena(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)

    await UserRepository(db_session).update_password_hash(user, "otro-marcador-de-hash")

    await db_session.refresh(user)
    assert user.password_hash == "otro-marcador-de-hash"  # noqa: S105  # marcador, no un hash


# --- UserRepository: asignaciones de rol ----------------------------------------------------------


async def test_cargar_asignaciones_de_un_usuario(
    db_session: AsyncSession, alcance: Alcance
) -> None:
    user = await _crear_usuario(db_session)
    otro = await _crear_usuario(db_session)
    db_session.add_all(
        [
            UserRoleAssignment(user_id=user.id, role_id=ADMINISTRADOR),
            UserRoleAssignment(
                user_id=user.id, role_id=DESARROLLADOR, project_id=alcance.project_id
            ),
            UserRoleAssignment(user_id=otro.id, role_id=DESARROLLADOR),
        ]
    )
    await db_session.flush()
    repo = UserRepository(db_session)

    asignaciones = await repo.get_assignments(user.id)

    assert {(a.role_id, a.project_id, a.environment_id) for a in asignaciones} == {
        (ADMINISTRADOR, None, None),
        (DESARROLLADOR, alcance.project_id, None),
    }
    assert await repo.get_role_names(user.id) == ["Administrador", "Desarrollador"]


async def test_usuario_sin_asignaciones(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)
    repo = UserRepository(db_session)

    assert list(await repo.get_assignments(user.id)) == []
    assert await repo.get_role_names(user.id) == []


async def test_nombres_de_rol_sin_repetir(db_session: AsyncSession, alcance: Alcance) -> None:
    # Dos asignaciones del mismo rol en alcances distintos dan un solo nombre en el claim roles.
    user = await _crear_usuario(db_session)
    db_session.add_all(
        [
            UserRoleAssignment(
                user_id=user.id, role_id=DESARROLLADOR, project_id=alcance.project_id
            ),
            UserRoleAssignment(
                user_id=user.id,
                role_id=DESARROLLADOR,
                project_id=alcance.project_id,
                environment_id=alcance.environment_id,
            ),
        ]
    )
    await db_session.flush()

    assert await UserRepository(db_session).get_role_names(user.id) == ["Desarrollador"]


# --- UserRepository: tokens_invalid_before (H-37) -------------------------------------------------


async def test_fijar_tokens_invalid_before(db_session: AsyncSession) -> None:
    user = await _crear_usuario(db_session)
    corte = _ahora() + timedelta(seconds=1)

    await UserRepository(db_session).set_tokens_invalid_before(user.id, corte)

    await db_session.refresh(user)
    assert user.tokens_invalid_before == corte


async def test_tokens_invalid_before_conserva_el_mayor(db_session: AsyncSession) -> None:
    # Spec Fase 5 §3.5: si dos eventos coinciden, se conserva el mayor de los T.
    mayor = _ahora() + timedelta(seconds=5)
    user = await _crear_usuario(db_session, tokens_invalid_before=mayor)

    await UserRepository(db_session).set_tokens_invalid_before(
        user.id, mayor - timedelta(seconds=3)
    )

    await db_session.refresh(user)
    assert user.tokens_invalid_before == mayor


# --- RevokedTokenRepository (RF-015; H-03) --------------------------------------------------------


async def _fila_revocada(session: AsyncSession, jti: uuid.UUID) -> RevokedToken | None:
    return (
        await session.execute(select(RevokedToken).where(RevokedToken.token_jti == jti))
    ).scalar_one_or_none()


@pytest.mark.parametrize("token_type", ["access", "refresh"])
async def test_revocar_token_humano(db_session: AsyncSession, token_type: str) -> None:
    user = await _crear_usuario(db_session)
    repo = RevokedTokenRepository(db_session)
    jti = uuid.uuid4()
    expira = _ahora() + timedelta(minutes=15)

    assert await repo.is_revoked(jti) is False
    assert await repo.revoke(jti, token_type, expira, user_id=user.id) is True
    assert await repo.is_revoked(jti) is True

    fila = await _fila_revocada(db_session, jti)
    assert fila is not None
    assert (fila.token_type, fila.user_id, fila.expires_at) == (token_type, user.id, expira)
    assert fila.revoked_by is None  # rotación o logout: sin actor administrativo (H-03)


async def test_revocar_sin_usuario(db_session: AsyncSession) -> None:
    # H-03: user_id y revoked_by son nullable.
    repo = RevokedTokenRepository(db_session)
    jti = uuid.uuid4()

    assert await repo.revoke(jti, "refresh", _ahora() + timedelta(days=7)) is True

    fila = await _fila_revocada(db_session, jti)
    assert fila is not None
    assert fila.user_id is None
    assert fila.revoked_by is None


async def test_revocar_dos_veces_no_falla_y_devuelve_false(db_session: AsyncSession) -> None:
    # INSERT ... ON CONFLICT DO NOTHING: logout idempotente y detección de reuso del refresh.
    user = await _crear_usuario(db_session)
    repo = RevokedTokenRepository(db_session)
    jti = uuid.uuid4()
    expira = _ahora() + timedelta(days=7)

    assert await repo.revoke(jti, "refresh", expira, user_id=user.id) is True
    assert await repo.revoke(jti, "refresh", expira, user_id=user.id) is False
    assert await repo.is_revoked(jti) is True
