"""Firma diaria del cierre de la cadena contra PostgreSQL (H-81; H-46; OWASP ASVS V7.3.3).

Todas usan ``db_session`` (transacción revertida al final). Cada llave se genera en la prueba.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from portero.crypto.signing import public_key_thumbprint
from portero.db.models import AuditLog, ChainSignature
from portero.oplog.service import (
    ChainNotIntactError,
    EmptyChainError,
    OperationActor,
    OperationEvent,
    OperationLogService,
)

ADMIN = OperationActor("human", "pruebas:admin", None)


def _evento(n: int) -> OperationEvent:
    return OperationEvent(
        actor_type="service",
        actor_ref=f"sa:firma-{n}",
        verb="create_project",
        result="success",
        resource_type="project",
    )


@pytest.fixture
def oplog() -> OperationLogService:
    return OperationLogService()


@pytest.fixture
def llave() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


async def _sembrar(session: AsyncSession, oplog: OperationLogService, n: int = 3) -> list[int]:
    filas = [await oplog.record(session, _evento(i)) for i in range(n)]
    await session.commit()
    return [f.id for f in filas]


async def _ultimo(session: AsyncSession) -> AuditLog:
    fila = await session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    assert fila is not None
    return fila


async def _contar_firmas(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(ChainSignature)) or 0


async def test_sign_chain_firma_el_ultimo_registro_y_lo_registra(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    ids = await _sembrar(db_session, oplog)
    cierre = await _ultimo(db_session)

    firma = await oplog.sign_chain(db_session, llave)

    assert (firma.last_audit_id, firma.last_hash) == (ids[-1], cierre.current_hash)
    assert firma.public_key_thumbprint == public_key_thumbprint(llave.public_key())
    assert len(firma.signature) == 64
    evento = await _ultimo(db_session)
    assert (evento.verb, evento.result, evento.actor_ref) == (
        "sign_chain",
        "success",
        "cli:sign-chain",
    )
    assert (evento.resource_type, evento.resource_id) == ("chain_signature", firma.id)
    assert evento.details == {"last_audit_id": ids[-1], "last_hash": cierre.current_hash}


async def test_verify_chain_reporta_la_firma_valida(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await _sembrar(db_session, oplog)
    firma = await oplog.sign_chain(db_session, llave)
    db_session.expunge_all()

    reporte = await oplog.verify_chain(db_session, public_key=llave.public_key())

    assert reporte.ok is True
    assert reporte.signing_configured is True
    assert reporte.signatures_total >= 1
    assert (reporte.invalid_signatures, reporte.missing_signatures) == ([], [])
    assert reporte.last_signed_audit_id == firma.last_audit_id
    assert reporte.last_signed_at == firma.created_at


async def test_sin_llave_publica_la_verificacion_no_revisa_firmas(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await _sembrar(db_session, oplog)
    await oplog.sign_chain(db_session, llave)

    reporte = await oplog.verify_chain(db_session)

    assert reporte.ok is True
    assert reporte.signing_configured is False
    assert reporte.last_signed_at is None


async def test_la_siguiente_firma_cubre_el_evento_de_la_anterior(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await _sembrar(db_session, oplog)
    await oplog.sign_chain(db_session, llave)
    evento_anterior = await _ultimo(db_session)

    segunda = await oplog.sign_chain(db_session, llave)

    assert segunda.last_audit_id == evento_anterior.id


async def test_no_firma_una_cadena_alterada(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    """Firmar una cadena alterada la "lavaría": se niega y deja un ``sign_chain`` fallido."""
    ids = await _sembrar(db_session, oplog)
    await db_session.execute(
        text("UPDATE audit_logs SET actor_ref = 'sa:alterado' WHERE id = :id"), {"id": ids[1]}
    )
    await db_session.commit()
    db_session.expunge_all()
    firmas_antes = await _contar_firmas(db_session)

    with pytest.raises(ChainNotIntactError) as exc:
        await oplog.sign_chain(db_session, llave)

    assert ids[1] in exc.value.report.broken
    assert await _contar_firmas(db_session) == firmas_antes
    evento = await _ultimo(db_session)
    assert (evento.verb, evento.result) == ("sign_chain", "failure")
    assert evento.details is not None and evento.details["broken_count"] >= 1


async def test_no_firma_una_bitacora_vacia(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await db_session.execute(text("TRUNCATE chain_signatures, audit_logs"))

    with pytest.raises(EmptyChainError):
        await oplog.sign_chain(db_session, llave)

    assert await _contar_firmas(db_session) == 0


async def test_borrar_una_fila_firmada_lo_impide_la_fk(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    """``ON DELETE RESTRICT``: para truncar lo firmado hay que borrar antes la firma."""
    await _sembrar(db_session, oplog)
    firma = await oplog.sign_chain(db_session, llave)

    with pytest.raises(IntegrityError):
        async with db_session.begin_nested():
            await db_session.execute(delete(AuditLog).where(AuditLog.id == firma.last_audit_id))


async def test_borrar_la_firma_sin_tocar_la_cadena_se_detecta(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    """El ``sign_chain`` de la bitácora apunta a una firma que ya no existe (H-81)."""
    await _sembrar(db_session, oplog)
    firma = await oplog.sign_chain(db_session, llave)
    firma_id = firma.id
    await db_session.execute(delete(ChainSignature).where(ChainSignature.id == firma_id))
    await db_session.commit()
    db_session.expunge_all()

    reporte = await oplog.verify_chain(db_session, public_key=llave.public_key())

    assert reporte.ok is False
    assert str(firma_id) in reporte.missing_signatures


async def test_truncar_lo_firmado_se_detecta(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    """Contraparte en BD de la prueba de H-46. Quien tiene PostgreSQL esquiva la FK cambiando
    ``last_audit_id`` de la firma a un registro anterior y borra el final: la firma ya no
    cuadra con la fila a la que apunta."""
    ids = await _sembrar(db_session, oplog, n=4)
    firma = await oplog.sign_chain(db_session, llave)
    await db_session.execute(
        text("UPDATE chain_signatures SET last_audit_id = :antes WHERE id = :id"),
        {"antes": ids[1], "id": firma.id},
    )
    await db_session.execute(delete(AuditLog).where(AuditLog.id > ids[1]))
    await db_session.commit()
    db_session.expunge_all()

    reporte = await oplog.verify_chain(db_session, public_key=llave.public_key())

    assert reporte.ok is False
    assert str(firma.id) in reporte.invalid_signatures


async def test_otra_llave_publica_invalida_las_firmas(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await _sembrar(db_session, oplog)
    firma = await oplog.sign_chain(db_session, llave)

    otra = Ed25519PrivateKey.generate().public_key()
    reporte = await oplog.verify_chain(db_session, public_key=otra)

    assert reporte.ok is False
    assert str(firma.id) in reporte.invalid_signatures


async def test_verify_and_record_lleva_el_conteo_de_firmas(
    db_session: AsyncSession, oplog: OperationLogService, llave: Ed25519PrivateKey
) -> None:
    await _sembrar(db_session, oplog)
    await oplog.sign_chain(db_session, llave)

    reporte = await oplog.verify_and_record(db_session, ADMIN, public_key=llave.public_key())

    evento = await _ultimo(db_session)
    assert evento.verb == "verify_chain"
    assert evento.details is not None
    assert evento.details["signatures_total"] == reporte.signatures_total
    assert evento.details["invalid_signatures_count"] == 0
    assert evento.details["missing_signatures_count"] == 0
