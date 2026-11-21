"""Rotación de la KEK contra PostgreSQL (spec §1.6, H-07; H-05; H-06; H-40; NIST SP 800-57).

Escenario: 3 secretos con 2 versiones cada uno (6 DEKs envueltas bajo la KEK versión 1). Rotar
crea la versión 2 activa, desactiva la 1 y re-envuelve las 6 DEKs en **una sola transacción**:
cambian ``wrapped_dek`` y ``kek_version_id``; ``ciphertext``, ``nonce`` y ``auth_tag`` no. Si algo
falla a la mitad, no cambia nada. La operación queda en la bitácora (verbo ``rotate_kek``).
"""

import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import LECTOR_PRUEBA, PASSPHRASE_PRUEBA, Alcance, actor_humano

from portero.crypto.engine import CryptoEngine
from portero.crypto.errors import KekPassphraseError
from portero.crypto.kek import KdfParams, KeyManager
from portero.db.models import AuditLog, KekVersion, SecretVersion
from portero.oplog.service import OperationEvent, OperationLogService
from portero.secrets_mgmt.errors import KekRotationError
from portero.secrets_mgmt.kek_rotation import KekRotationResult, rotate_kek
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

# Marcadores de prueba, no son secretos reales.
PASSPHRASE_NUEVA = b"marcador-de-prueba-passphrase-kek-nueva"
PASSPHRASE_TERCERA = b"marcador-de-prueba-passphrase-kek-tercera"


@dataclass(frozen=True)
class Fila:
    """Columnas de ``secret_versions`` que la rotación debe o no debe tocar."""

    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes | None
    wrapped_dek: bytes
    kek_version_id: uuid.UUID


Clave = tuple[uuid.UUID, int]  # (secret_id, version_number)


async def _filas(session: AsyncSession) -> dict[Clave, Fila]:
    """Todas las filas de ``secret_versions`` leídas de la BD (no de la caché de la sesión)."""
    stmt = select(SecretVersion).execution_options(populate_existing=True)
    return {
        (v.secret_id, v.version_number): Fila(
            v.ciphertext, v.nonce, v.auth_tag, v.wrapped_dek, v.kek_version_id
        )
        for v in (await session.execute(stmt)).scalars()
    }


async def _versiones_kek(session: AsyncSession) -> list[KekVersion]:
    stmt = (
        select(KekVersion)
        .order_by(KekVersion.version_number)
        .execution_options(populate_existing=True)
    )
    return list((await session.execute(stmt)).scalars())


async def _registros_rotate_kek(session: AsyncSession) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.verb == "rotate_kek").order_by(AuditLog.id)
    return list((await session.execute(stmt)).scalars())


@dataclass(frozen=True)
class Sembrado:
    valores: dict[Clave, bytes]
    antes: dict[Clave, Fila]
    kek_v1: uuid.UUID


@pytest.fixture
async def sembrado(
    db_session: AsyncSession, servicio: SecretService, key_manager: KeyManager, alcance: Alcance
) -> Sembrado:
    """3 secretos × 2 versiones bajo la KEK versión 1 (``PASSPHRASE_PRUEBA``)."""
    valores: dict[Clave, bytes] = {}
    for i in range(3):
        v1 = f"marcador-de-prueba-secreto-{i}-v1".encode()
        v2 = f"marcador-de-prueba-secreto-{i}-v2".encode()
        ref = await servicio.create_secret(
            db_session,
            project_id=alcance.project_id,
            environment_id=alcance.environment_id,
            name=f"SECRETO_{i}",
            value=bytearray(v1),
            actor=actor_humano(alcance.user_id),
        )
        await servicio.rotate_secret(
            db_session, ref.secret_id, bytearray(v2), actor=actor_humano(alcance.user_id)
        )
        valores[(ref.secret_id, 1)] = v1
        valores[(ref.secret_id, 2)] = v2
    antes = await _filas(db_session)
    assert set(antes) == set(valores), "db-test debe estar vacía fuera de esta prueba"
    assert {f.kek_version_id for f in antes.values()} == {key_manager.active_version_id}
    return Sembrado(valores, antes, key_manager.active_version_id)


async def _rotar(
    session: AsyncSession,
    params: KdfParams,
    actual: bytes = PASSPHRASE_PRUEBA,
    nueva: bytes = PASSPHRASE_NUEVA,
    oplog: OperationLogService | None = None,
) -> KekRotationResult:
    return await rotate_kek(
        session,
        current_passphrase=actual,
        new_passphrase=nueva,
        new_params=params,
        oplog=oplog or OperationLogService(),
    )


async def _todo_descifra(session: AsyncSession, passphrase: bytes, sembrado: Sembrado) -> None:
    km = await load_key_manager(session, passphrase)
    try:
        servicio = SecretService(CryptoEngine(km))
        for (secret_id, version), valor in sembrado.valores.items():
            assert (
                await servicio.read_secret_value(session, secret_id, version, actor=LECTOR_PRUEBA)
                == valor
            )
    finally:
        km.close()


async def _sin_cambios(session: AsyncSession, sembrado: Sembrado) -> None:
    """Estado idéntico al sembrado: una sola KEK activa (la 1), mismas filas y sin registro."""
    versiones = await _versiones_kek(session)
    assert [(v.id, v.version_number, v.deactivated_at) for v in versiones] == [
        (sembrado.kek_v1, 1, None)
    ]
    assert await _filas(session) == sembrado.antes
    assert await _registros_rotate_kek(session) == []
    await _todo_descifra(session, PASSPHRASE_PRUEBA, sembrado)


# --- Camino feliz -----------------------------------------------------------------------------


async def test_rotar_crea_la_version_2_y_reenvuelve_todas_las_deks(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    resultado = await _rotar(db_session, parametros_argon2_solo_pruebas)

    assert (resultado.from_version, resultado.to_version) == (1, 2)
    assert resultado.rewrapped_deks == 6

    v1, v2 = await _versiones_kek(db_session)
    assert v1.id == sembrado.kek_v1
    assert v1.deactivated_at is not None
    assert v2.id == resultado.new_kek_version_id
    assert v2.version_number == 2
    assert v2.deactivated_at is None
    assert v2.verifier is not None

    despues = await _filas(db_session)
    assert set(despues) == set(sembrado.antes)
    for clave, antes in sembrado.antes.items():
        fila = despues[clave]
        assert fila.ciphertext == antes.ciphertext
        assert fila.nonce == antes.nonce
        assert fila.auth_tag == antes.auth_tag
        assert fila.wrapped_dek != antes.wrapped_dek
        assert fila.kek_version_id == v2.id


async def test_la_passphrase_vieja_ya_no_arranca_y_la_nueva_descifra_todo(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await _rotar(db_session, parametros_argon2_solo_pruebas)

    with pytest.raises(KekPassphraseError):
        await load_key_manager(db_session, PASSPHRASE_PRUEBA)
    await _todo_descifra(db_session, PASSPHRASE_NUEVA, sembrado)


async def test_rotar_dos_veces_lleva_a_la_version_3(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await _rotar(db_session, parametros_argon2_solo_pruebas)
    resultado = await _rotar(
        db_session, parametros_argon2_solo_pruebas, PASSPHRASE_NUEVA, PASSPHRASE_TERCERA
    )

    assert (resultado.from_version, resultado.to_version) == (2, 3)
    versiones = await _versiones_kek(db_session)
    assert [v.deactivated_at is None for v in versiones] == [False, False, True]
    assert {f.kek_version_id for f in (await _filas(db_session)).values()} == {versiones[2].id}
    await _todo_descifra(db_session, PASSPHRASE_TERCERA, sembrado)


async def test_registra_rotate_kek_como_operacion_del_cli(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    resultado = await _rotar(db_session, parametros_argon2_solo_pruebas)

    [registro] = await _registros_rotate_kek(db_session)
    assert registro.actor_type == "human"
    assert registro.actor_user_id is None
    assert registro.actor_ref == "cli:rotate-kek"
    assert registro.result == "success"
    assert registro.resource_type == "kek_version"
    assert registro.resource_id == resultado.new_kek_version_id
    assert registro.project_id is None
    assert registro.environment_id is None
    assert registro.ip_address is None
    assert registro.details == {"from_version": 1, "to_version": 2, "rewrapped_deks": 6}
    assert (await OperationLogService().verify_chain(db_session)).ok


async def test_la_transaccion_bloquea_escrituras_en_secret_versions(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    """H-40: mientras se re-envuelve, nadie puede insertar una versión con la KEK vieja.

    El registro de la bitácora ocurre dentro de la transacción, justo antes del ``commit``; ahí
    se revisa ``pg_locks``.
    """
    modos: list[str] = []

    class OplogQueRevisaLocks(OperationLogService):
        async def record(self, session: AsyncSession, event: OperationEvent) -> AuditLog:
            filas = await session.execute(
                text(
                    "SELECT mode FROM pg_locks WHERE pid = pg_backend_pid() "
                    "AND relation = 'secret_versions'::regclass AND granted"
                )
            )
            modos.extend(filas.scalars())
            return await super().record(session, event)

    await _rotar(db_session, parametros_argon2_solo_pruebas, oplog=OplogQueRevisaLocks())

    assert "ExclusiveLock" in modos


# --- Fallos: no cambia nada -------------------------------------------------------------------


async def test_si_falla_a_la_mitad_no_cambia_nada(
    db_session: AsyncSession,
    sembrado: Sembrado,
    parametros_argon2_solo_pruebas: KdfParams,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Una sola transacción: un error en la cuarta DEK revierte las tres ya re-envueltas, la
    versión 2 y la desactivación de la 1."""
    original = CryptoEngine.rewrap_dek
    llamadas = 0

    def falla_en_la_cuarta(self: CryptoEngine, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal llamadas
        llamadas += 1
        if llamadas == 4:
            raise RuntimeError("fallo simulado a la mitad de la rotación")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(CryptoEngine, "rewrap_dek", falla_en_la_cuarta)

    with pytest.raises(RuntimeError, match="fallo simulado"):
        await _rotar(db_session, parametros_argon2_solo_pruebas)

    assert llamadas == 4
    await _sin_cambios(db_session, sembrado)


async def test_passphrase_actual_incorrecta_no_cambia_nada(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    with pytest.raises(KekPassphraseError):
        await _rotar(
            db_session, parametros_argon2_solo_pruebas, actual=b"marcador-de-prueba-equivocada"
        )

    await _sin_cambios(db_session, sembrado)


async def test_passphrase_nueva_igual_a_la_actual_se_rechaza(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    with pytest.raises(KekRotationError, match="distinta") as info:
        await _rotar(db_session, parametros_argon2_solo_pruebas, nueva=PASSPHRASE_PRUEBA)

    assert PASSPHRASE_PRUEBA.decode() not in str(info.value)
    await _sin_cambios(db_session, sembrado)


async def test_passphrase_nueva_vacia_se_rechaza(
    db_session: AsyncSession, sembrado: Sembrado, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    with pytest.raises(KekRotationError, match="vacía"):
        await _rotar(db_session, parametros_argon2_solo_pruebas, nueva=b"")

    await _sin_cambios(db_session, sembrado)


async def test_sin_kek_activa_no_hay_nada_que_rotar(
    db_session: AsyncSession, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    assert await _versiones_kek(db_session) == [], "db-test debe estar vacía fuera de esta prueba"

    with pytest.raises(KekRotationError, match="no hay KEK activa"):
        await _rotar(db_session, parametros_argon2_solo_pruebas)

    assert await _versiones_kek(db_session) == []
