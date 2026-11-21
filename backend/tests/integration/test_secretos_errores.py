"""Caminos de error del Servicio de Gestión de Secretos y del arranque de la KEK (H-27).

Cada prueba fuerza un fallo concreto y comprueba que el material sensible se borra antes de
propagar la excepción (Algoritmo 4 del Cap. 6; OWASP ASVS V6.2.1: los módulos criptográficos
fallan de forma segura), o que el error se propaga sin disfrazarse de otro.
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import LECTOR_PRUEBA, PASSPHRASE_PRUEBA, Alcance, actor_humano

from portero.crypto.engine import CiphertextBundle, CryptoEngine, SecretContext
from portero.crypto.kek import KdfParams, KekVersionStore, KeyManager
from portero.db.models import Secret
from portero.secrets_mgmt.errors import SecretNameConflictError, SecretNotFoundError
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

# Valor de prueba. No es un secreto real.
VALOR = b"marcador-de-prueba-valor-errores"


class FalloSimuladoError(Exception):
    """Fallo del ``commit`` provocado por la prueba (p. ej. la conexión se cae)."""


async def _commit_que_falla() -> None:
    raise FalloSimuladoError("commit fallido (simulado)")


async def test_commit_fallido_tras_descifrar_borra_el_valor(
    key_manager: KeyManager,
    db_session: AsyncSession,
    alcance: Alcance,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si el ``commit`` que cierra la lectura falla, el valor ya descifrado no se entregará:
    debe quedar en ceros antes de propagar la excepción (``service.py``, CU-03)."""
    motor = CryptoEngine(key_manager)
    servicio = SecretService(motor)
    ref = await servicio.create_secret(
        db_session,
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        name="DB_PASSWORD",
        value=bytearray(VALOR),
        actor=actor_humano(alcance.user_id),
    )

    descifrados: list[bytearray] = []
    original = motor.decrypt_secret

    def espia(bundle: CiphertextBundle, *, ctx: SecretContext) -> bytearray:
        valor = original(bundle, ctx=ctx)
        descifrados.append(valor)
        return valor

    monkeypatch.setattr(motor, "decrypt_secret", espia)
    monkeypatch.setattr(db_session, "commit", _commit_que_falla)

    with pytest.raises(FalloSimuladoError) as exc:
        await servicio.read_secret_value(db_session, ref.secret_id, actor=LECTOR_PRUEBA)

    assert len(descifrados) == 1
    assert descifrados[0] == bytearray(len(VALOR))  # mismo largo, todo en ceros
    assert VALOR.decode() not in str(exc.value)


async def test_secreto_sin_version_actual_no_se_encuentra(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    """Un secreto con ``current_version_id`` nulo (estado intermedio de CU-02 que nunca debe
    confirmarse) se trata como inexistente, sin intentar descifrar nada."""
    secreto = Secret(
        id=uuid.uuid4(),
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        name="SIN_VERSION",
        created_by=alcance.user_id,
    )
    db_session.add(secreto)
    await db_session.flush()

    with pytest.raises(SecretNotFoundError):
        await servicio.read_secret_value(db_session, secreto.id, actor=LECTOR_PRUEBA)


async def test_integrity_error_ajeno_al_nombre_se_propaga(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    """Solo la violación del índice de nombre activo se traduce a ``SecretNameConflictError``.
    Otra violación (aquí, ``created_by`` inexistente) se propaga tal cual, sin disfrazarse de
    conflicto de nombre."""
    with pytest.raises(IntegrityError) as exc:
        await servicio.create_secret(
            db_session,
            project_id=alcance.project_id,
            environment_id=alcance.environment_id,
            name="DB_PASSWORD",
            value=bytearray(VALOR),
            actor=actor_humano(uuid.uuid4()),
        )

    assert not isinstance(exc.value, SecretNameConflictError)
    assert VALOR.decode() not in str(exc.value)


async def test_commit_fallido_del_primer_arranque_borra_la_kek(
    db_session: AsyncSession,
    parametros_argon2_solo_pruebas: KdfParams,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si no se puede confirmar la versión 1 de ``kek_versions``, la KEK recién derivada se
    borra de memoria y el ``KeyManager`` queda inutilizable (``kek_store.py``, spec §1.6)."""
    creados: list[KeyManager] = []
    original = KeyManager.bootstrap

    async def espia(
        store: KekVersionStore, passphrase: bytes, *, new_params: KdfParams
    ) -> KeyManager:
        km = await original(store, passphrase, new_params=new_params)
        creados.append(km)
        return km

    monkeypatch.setattr(KeyManager, "bootstrap", staticmethod(espia))
    monkeypatch.setattr(db_session, "commit", _commit_que_falla)

    with pytest.raises(FalloSimuladoError):
        await load_key_manager(
            db_session, PASSPHRASE_PRUEBA, new_params=parametros_argon2_solo_pruebas
        )

    assert len(creados) == 1
    km = creados[0]
    assert km._kek == bytearray(len(km._kek))  # borrada (Algoritmo 4)
    with pytest.raises(KeyError):
        km.get_kek(km.active_version_id)
