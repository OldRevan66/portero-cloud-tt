"""Desbloqueo y restablecimiento son fail-closed (H-78, H-86; H-11; OWASP ASVS V7.1).

Si el Servicio de Registro de Operaciones no puede registrar ``unlock_user`` o
``reset_password``, la operación entera se revierte: la cuenta sigue bloqueada, el hash de la
contraseña no cambia y no se fija el corte H-37. Así ningún cambio sobre una cuenta queda sin su
registro en la bitácora.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import actor_humano

from portero.db.models import AuditLog, User
from portero.management.users import UserService
from portero.oplog.service import OperationEvent, OperationLogService

CONTRASENA_TEMPORAL = "marcador-temporal-de-prueba-h86"  # cumple la política; no es un secreto
HASH_ORIGINAL = "marcador-no-es-un-hash"


class FalloDelRegistroError(Exception):
    """Falla simulada del Servicio de Registro de Operaciones."""


class RegistroQueFalla(OperationLogService):
    """Bitácora que falla siempre: toda escritura que dependa de ella debe revertirse."""

    async def record(self, session: AsyncSession, event: OperationEvent) -> AuditLog:
        raise FalloDelRegistroError(event.verb)


async def _usuario(session: AsyncSession, **campos: object) -> User:
    datos: dict[str, object] = {
        "email": f"usuario-{uuid.uuid4().hex[:8]}@example.com",
        "password_hash": HASH_ORIGINAL,
        "name": "Usuario de prueba",
    }
    datos.update(campos)
    user = User(**datos)
    session.add(user)
    await session.commit()
    return user


async def _registros(session: AsyncSession, verb: str) -> int:
    total = await session.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.verb == verb)
    )
    return total or 0


async def _bloqueado(session: AsyncSession) -> tuple[User, User, datetime]:
    admin = await _usuario(session)
    hasta = datetime.now(UTC) + timedelta(minutes=10)
    objetivo = await _usuario(session, failed_login_attempts=5, locked_until=hasta)
    return admin, objetivo, hasta


async def test_si_falla_el_registro_la_cuenta_sigue_bloqueada(db_session: AsyncSession) -> None:
    admin, objetivo, hasta = await _bloqueado(db_session)
    servicio = UserService(RegistroQueFalla())

    with pytest.raises(FalloDelRegistroError):
        await servicio.unlock_user(db_session, actor_humano(admin.id), objetivo)

    await db_session.refresh(objetivo)
    assert objetivo.failed_login_attempts == 5
    assert objetivo.locked_until == hasta
    assert await _registros(db_session, "unlock_user") == 0


async def test_si_falla_el_registro_no_cambia_la_contrasena_ni_se_cortan_sesiones(
    db_session: AsyncSession,
) -> None:
    admin, objetivo, hasta = await _bloqueado(db_session)
    servicio = UserService(RegistroQueFalla())

    with pytest.raises(FalloDelRegistroError):
        await servicio.reset_password(
            db_session, actor_humano(admin.id), objetivo, CONTRASENA_TEMPORAL
        )

    await db_session.refresh(objetivo)
    assert objetivo.password_hash == HASH_ORIGINAL
    assert objetivo.tokens_invalid_before is None
    assert objetivo.locked_until == hasta
    assert objetivo.failed_login_attempts == 5
    assert await _registros(db_session, "reset_password") == 0
