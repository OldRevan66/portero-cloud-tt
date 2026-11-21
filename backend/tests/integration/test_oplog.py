"""Pruebas del Servicio de Registro de Operaciones contra PostgreSQL (spec núcleo §5; spec Fase 5
§5.1–5.4; H-11, H-12; RF-018; OWASP ASVS V7.3.3).

Todas usan ``db_session`` (transacción revertida al final) salvo la de concurrencia, que necesita
datos confirmados: 20 sesiones reales no ven lo que otra no ha confirmado. Esa prueba limpia
``audit_logs`` con ``TRUNCATE`` antes y después, como ``test_rotacion_concurrente.py``.
"""

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from portero.db.models import AuditLog, User
from portero.oplog.chain import GENESIS_HASH, canonical_json, compute_hash
from portero.oplog.service import ForbiddenDetailError, OperationEvent, OperationLogService

VALOR_MARCADOR = "marcador-de-prueba-no-debe-guardarse"  # noqa: S105


def _evento(n: int = 0, **cambios: object) -> OperationEvent:
    """Evento de instancia mínimo, sin actor humano (no exige una fila en ``users``)."""
    datos: dict[str, object] = {
        "actor_type": "service",
        "actor_ref": f"sa:prueba-{n}",
        "verb": "create_project",
        "result": "success",
        "resource_type": "project",
    }
    datos.update(cambios)
    return OperationEvent(**datos)  # type: ignore[arg-type]


async def _ultimo(session: AsyncSession) -> AuditLog | None:
    return await session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))


async def _contar(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(AuditLog)) or 0


def _campos(fila: AuditLog) -> dict[str, object]:
    return {
        "event_timestamp": fila.event_timestamp,
        "actor_user_id": fila.actor_user_id,
        "actor_type": fila.actor_type,
        "actor_ref": fila.actor_ref,
        "verb": fila.verb,
        "resource_type": fila.resource_type,
        "resource_id": fila.resource_id,
        "result": fila.result,
        "ip_address": fila.ip_address,
        "user_agent": fila.user_agent,
        "project_id": fila.project_id,
        "environment_id": fila.environment_id,
        "details": fila.details,
    }


@pytest.fixture
def oplog() -> OperationLogService:
    return OperationLogService()


# --- record() ------------------------------------------------------------------------------------


async def test_record_encadena_con_el_ultimo_registro(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    previo = await _ultimo(db_session)
    esperado_anterior = previo.current_hash if previo else GENESIS_HASH

    primero = await oplog.record(db_session, _evento(1))
    segundo = await oplog.record(db_session, _evento(2))
    await db_session.commit()

    assert primero.previous_hash == esperado_anterior
    assert segundo.previous_hash == primero.current_hash


async def test_current_hash_coincide_con_la_fila_leida_de_la_bd(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    """El viaje por ``timestamptz``, ``INET`` y JSONB no cambia el JSON canónico."""
    await oplog.record(
        db_session,
        _evento(1, ip_address="10.0.0.7", user_agent="cliente/1.0", details={"b": 2, "a": 1}),
    )
    await db_session.commit()
    db_session.expunge_all()

    fila = await _ultimo(db_session)

    assert fila is not None
    assert fila.previous_hash is not None
    assert fila.current_hash == compute_hash(fila.previous_hash, canonical_json(_campos(fila)))


async def test_verify_chain_sobre_registros_intactos_es_ok(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    for i in range(3):
        await oplog.record(db_session, _evento(i, details={"fields": ["name"]}))
    await db_session.commit()
    db_session.expunge_all()

    resultado = await oplog.verify_chain(db_session)

    assert resultado.ok is True
    assert resultado.broken == []
    assert resultado.total >= 3


async def test_user_agent_se_trunca_a_512(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    fila = await oplog.record(db_session, _evento(user_agent="x" * 600))

    assert fila.user_agent == "x" * 512


async def test_ip_que_no_es_ip_se_guarda_como_null(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    """P. ej. el ``"testclient"`` de Starlette: ``INET`` no lo aceptaría."""
    fila = await oplog.record(db_session, _evento(ip_address="testclient"))

    assert fila.ip_address is None


# --- Misma transacción que el cambio (H-11) ------------------------------------------------------


async def test_el_registro_se_revierte_junto_con_el_cambio(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    antes = await _contar(db_session)
    user = User(
        email="revertido@example.com",
        password_hash="marcador-no-es-un-hash",  # noqa: S106
        name="Revertido",
    )
    db_session.add(user)
    await db_session.flush()
    await oplog.record(
        db_session,
        OperationEvent(
            actor_type="human",
            actor_ref="admin@example.com",
            verb="create_user",
            result="success",
            resource_type="user",
            resource_id=user.id,
        ),
    )

    await db_session.rollback()

    assert await _contar(db_session) == antes
    revertido = select(User).where(User.email == "revertido@example.com")
    assert await db_session.scalar(revertido) is None


# --- Validación de eventos (H-12) ----------------------------------------------------------------


@pytest.mark.parametrize(
    "details",
    [
        {"value": VALOR_MARCADOR},
        {"password": VALOR_MARCADOR},
        {"token": VALOR_MARCADOR},
        {"token_hash": VALOR_MARCADOR},
        {"password_hash": VALOR_MARCADOR},
        {"x": {"password": VALOR_MARCADOR}},
        {"fields": [{"value": VALOR_MARCADOR}]},
    ],
)
async def test_details_con_llave_prohibida_se_rechaza_sin_insertar(
    db_session: AsyncSession, oplog: OperationLogService, details: dict[str, object]
) -> None:
    antes = await _contar(db_session)

    with pytest.raises(ForbiddenDetailError) as info:
        await oplog.record(db_session, _evento(details=details))

    assert VALOR_MARCADOR not in str(info.value)
    assert await _contar(db_session) == antes


@pytest.mark.parametrize(
    "cambio",
    [
        {"verb": "user_created"},
        {"verb": "login_success"},
        {"result": "ok"},
        {"actor_type": "cli"},
    ],
)
async def test_evento_fuera_del_catalogo_se_rechaza(
    db_session: AsyncSession, oplog: OperationLogService, cambio: dict[str, object]
) -> None:
    antes = await _contar(db_session)

    with pytest.raises(ValueError):
        await oplog.record(db_session, _evento(**cambio))

    assert await _contar(db_session) == antes


# --- Detección de alteraciones -------------------------------------------------------------------


async def test_verify_chain_detecta_un_update_directo(
    db_session: AsyncSession, oplog: OperationLogService
) -> None:
    filas = [await oplog.record(db_session, _evento(i)) for i in range(3)]
    await db_session.commit()
    alterada = filas[1].id

    await db_session.execute(
        text("UPDATE audit_logs SET actor_ref = 'sa:alterado' WHERE id = :id"), {"id": alterada}
    )
    await db_session.commit()
    db_session.expunge_all()

    resultado = await oplog.verify_chain(db_session)

    assert resultado.ok is False
    assert resultado.broken[0] == alterada


# --- Concurrencia (H-11) -------------------------------------------------------------------------


@pytest.fixture
async def sesiones_confirmadas(
    engine: AsyncEngine,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Fábrica de sesiones con datos confirmados; vacía ``audit_logs`` (y ``chain_signatures``,
    que la referencia, H-81) antes y después."""
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE chain_signatures, audit_logs"))
    yield async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE chain_signatures, audit_logs"))


async def test_20_inserciones_concurrentes_forman_una_cadena_lineal(
    sesiones_confirmadas: async_sessionmaker[AsyncSession], oplog: OperationLogService
) -> None:
    """Sin ``pg_advisory_xact_lock``, varias transacciones leerían el mismo último hash y la
    cadena se bifurcaría (comprobado con una prueba de mutación)."""

    async def registrar(i: int) -> None:
        async with sesiones_confirmadas() as s:
            await oplog.record(s, _evento(i))
            await s.commit()

    await asyncio.gather(*(registrar(i) for i in range(20)))

    async with sesiones_confirmadas() as s:
        filas = list(await s.scalars(select(AuditLog).order_by(AuditLog.id)))
        resultado = await oplog.verify_chain(s)

    assert len(filas) == 20
    assert len({f.previous_hash for f in filas}) == 20, "la cadena se bifurcó"
    assert filas[0].previous_hash == GENESIS_HASH
    for anterior, actual in zip(filas, filas[1:], strict=False):
        assert actual.previous_hash == anterior.current_hash
    assert resultado.ok is True
    assert resultado.total == 20
