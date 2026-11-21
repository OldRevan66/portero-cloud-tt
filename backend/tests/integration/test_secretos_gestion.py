"""Servicio de Gestión de Secretos: escrituras con registro de operaciones (H-11), consultas de
metadatos, historial paginado y archivado (CU-02 a CU-04; spec Fase 5 §2, §5.3, §5.4).

Complementa ``test_secretos.py`` (cifrado, rotación, H-05/H-10) con el resto de la gestión.
"""

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import LECTOR_PRUEBA, Alcance, actor_humano

from portero.crypto.engine import CryptoEngine
from portero.crypto.kek import KeyManager
from portero.db.models import AuditLog, Secret, SecretVersion
from portero.oplog.service import OperationEvent, OperationLogService
from portero.secrets_mgmt.errors import SecretNotFoundError
from portero.secrets_mgmt.service import SecretService

VALOR = b"marcador-de-prueba-gestion-v1"
VALOR_2 = b"marcador-de-prueba-gestion-v2"


class FalloDelRegistroError(Exception):
    """Falla simulada del Servicio de Registro de Operaciones."""


class RegistroQueFalla(OperationLogService):
    """Bitácora que falla siempre: toda escritura que dependa de ella debe revertirse."""

    async def record(self, session: AsyncSession, event: OperationEvent) -> AuditLog:
        raise FalloDelRegistroError(event.verb)


async def _crear(servicio: SecretService, session: AsyncSession, alcance: Alcance) -> uuid.UUID:
    ref = await servicio.create_secret(
        session,
        actor=actor_humano(alcance.user_id),
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        name="DB_PASSWORD",
        value=bytearray(VALOR),
        description="original",
    )
    return ref.secret_id


async def _verbos(session: AsyncSession) -> list[str]:
    return list(await session.scalars(select(AuditLog.verb).order_by(AuditLog.id)))


async def _contar(session: AsyncSession, modelo: type[Secret] | type[SecretVersion]) -> int:
    return await session.scalar(select(func.count()).select_from(modelo)) or 0


# --- Registro en la misma transacción (H-11) -----------------------------------------------------


async def test_cada_escritura_y_lectura_queda_registrada(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    actor = actor_humano(alcance.user_id)
    secret_id = await _crear(servicio, db_session, alcance)
    await servicio.rotate_secret(db_session, secret_id, bytearray(VALOR_2), actor=actor)
    await servicio.update_secret(db_session, secret_id, {"description": "nueva"}, actor=actor)
    valor = await servicio.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA)
    await servicio.archive_secret(db_session, secret_id, actor=actor)

    assert valor == VALOR_2
    assert await _verbos(db_session) == [
        "create_secret",
        "rotate_secret",
        "update_secret",
        "read_secret",
        "archive_secret",
    ]
    filas = list(await db_session.scalars(select(AuditLog).order_by(AuditLog.id)))
    assert all(f.resource_id == secret_id for f in filas)
    assert all(f.project_id == alcance.project_id for f in filas)
    assert all(f.environment_id == alcance.environment_id for f in filas)
    assert filas[1].details == {"from_version": 1, "to_version": 2}
    assert filas[2].details == {"fields": ["description"]}


async def test_si_falla_el_registro_no_se_crea_el_secreto(
    key_manager: KeyManager, db_session: AsyncSession, alcance: Alcance
) -> None:
    servicio = SecretService(CryptoEngine(key_manager), RegistroQueFalla())

    with pytest.raises(FalloDelRegistroError):
        await _crear(servicio, db_session, alcance)

    assert await _contar(db_session, Secret) == 0
    assert await _contar(db_session, SecretVersion) == 0


async def test_si_falla_el_registro_no_cambian_rotacion_descripcion_ni_archivado(
    servicio: SecretService,
    key_manager: KeyManager,
    db_session: AsyncSession,
    alcance: Alcance,
) -> None:
    secret_id = await _crear(servicio, db_session, alcance)
    con_fallo = SecretService(CryptoEngine(key_manager), RegistroQueFalla())
    actor = actor_humano(alcance.user_id)

    with pytest.raises(FalloDelRegistroError):
        await con_fallo.rotate_secret(db_session, secret_id, bytearray(VALOR_2), actor=actor)
    with pytest.raises(FalloDelRegistroError):
        await con_fallo.update_secret(db_session, secret_id, {"description": "x"}, actor=actor)
    with pytest.raises(FalloDelRegistroError):
        await con_fallo.archive_secret(db_session, secret_id, actor=actor)

    metadatos = await servicio.get_secret(db_session, secret_id)
    assert metadatos is not None  # sigue activo
    assert (metadatos.version, metadatos.description) == (1, "original")
    assert await _contar(db_session, SecretVersion) == 1


async def test_si_falla_el_registro_de_la_lectura_no_se_entrega_el_valor(
    servicio: SecretService,
    key_manager: KeyManager,
    db_session: AsyncSession,
    alcance: Alcance,
) -> None:
    """Fail-closed (H-11): sin registro de ``read_secret`` no hay valor."""
    secret_id = await _crear(servicio, db_session, alcance)
    con_fallo = SecretService(CryptoEngine(key_manager), RegistroQueFalla())

    with pytest.raises(FalloDelRegistroError) as exc:
        await con_fallo.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA)

    assert VALOR.decode() not in str(exc.value)
    assert "read_secret" not in await _verbos(db_session)


@pytest.mark.parametrize("operacion", ["crear", "rotar"])
async def test_un_actor_sin_usuario_no_escribe_secretos(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance, operacion: str
) -> None:
    """``created_by`` es NOT NULL: solo un humano escribe (un service account solo lee)."""
    secret_id = await _crear(servicio, db_session, alcance)

    with pytest.raises(ValueError, match="actor humano"):
        if operacion == "crear":
            await servicio.create_secret(
                db_session,
                actor=LECTOR_PRUEBA,
                project_id=alcance.project_id,
                environment_id=alcance.environment_id,
                name="OTRO",
                value=bytearray(VALOR),
            )
        else:
            await servicio.rotate_secret(
                db_session, secret_id, bytearray(VALOR_2), actor=LECTOR_PRUEBA
            )


# --- Metadatos, historial y archivado ------------------------------------------------------------


async def test_metadatos_y_listado_sin_valores(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await _crear(servicio, db_session, alcance)
    await servicio.rotate_secret(
        db_session, secret_id, bytearray(VALOR_2), actor=actor_humano(alcance.user_id)
    )

    metadatos = await servicio.get_secret(db_session, secret_id)
    listado = await servicio.list_secrets(db_session, alcance.project_id, alcance.environment_id)

    assert metadatos is not None
    assert (metadatos.name, metadatos.version, metadatos.created_by) == (
        "DB_PASSWORD",
        2,
        alcance.user_id,
    )
    assert listado == [metadatos]
    assert not hasattr(metadatos, "value")


async def test_historial_paginado_de_la_mas_reciente_a_la_mas_antigua(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await _crear(servicio, db_session, alcance)
    actor = actor_humano(alcance.user_id)
    for valor in (VALOR_2, VALOR):
        await servicio.rotate_secret(db_session, secret_id, bytearray(valor), actor=actor)

    primera = await servicio.list_versions(db_session, secret_id, limit=2, before=None)
    segunda = await servicio.list_versions(
        db_session, secret_id, limit=2, before=primera.next_before
    )

    assert [v.version for v in primera.items] == [3, 2]
    assert primera.next_before == 2
    assert [v.version for v in segunda.items] == [1]
    assert segunda.next_before is None
    assert {v.aead_algorithm for v in primera.items + segunda.items} == {"aes-256-gcm"}


async def test_archivar_oculta_el_secreto_y_conserva_sus_versiones(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await _crear(servicio, db_session, alcance)

    await servicio.archive_secret(db_session, secret_id, actor=actor_humano(alcance.user_id))

    assert await servicio.get_secret(db_session, secret_id) is None
    assert await servicio.list_secrets(db_session, alcance.project_id, alcance.environment_id) == []
    assert await _contar(db_session, SecretVersion) == 1  # las versiones se conservan
    with pytest.raises(SecretNotFoundError):
        await servicio.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA)


@pytest.mark.parametrize("estado", ["inexistente", "archivado"])
async def test_actualizar_o_archivar_lo_que_no_esta_activo_no_se_encuentra(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance, estado: str
) -> None:
    actor = actor_humano(alcance.user_id)
    secret_id = uuid.uuid4()
    if estado == "archivado":
        secret_id = await _crear(servicio, db_session, alcance)
        await servicio.archive_secret(db_session, secret_id, actor=actor)
    antes = await _verbos(db_session)

    with pytest.raises(SecretNotFoundError):
        await servicio.update_secret(db_session, secret_id, {"description": "x"}, actor=actor)
    with pytest.raises(SecretNotFoundError):
        await servicio.archive_secret(db_session, secret_id, actor=actor)

    assert await _verbos(db_session) == antes  # nada que registrar


async def test_actualizar_sin_cambios_registra_lista_vacia(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await _crear(servicio, db_session, alcance)

    metadatos = await servicio.update_secret(
        db_session, secret_id, {"description": "original"}, actor=actor_humano(alcance.user_id)
    )

    assert metadatos.description == "original"
    ultimo = await db_session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    assert ultimo is not None
    assert (ultimo.verb, ultimo.details) == ("update_secret", {"fields": []})


def test_wipe_borra_el_valor() -> None:
    """``SecretService.wipe`` es ``secure_zero`` para el API REST Gateway (H-13)."""
    valor = bytearray(VALOR)

    SecretService.wipe(valor)

    assert valor == bytearray(len(VALOR))
