"""Servicio de Gestión de Secretos contra PostgreSQL: crear, leer y rotar (CU-02..CU-04; H-10),
intercambio de filas (H-05) y passphrase incorrecta al arrancar (H-06).
"""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import (
    LECTOR_PRUEBA,
    PASSPHRASE_PRUEBA,
    Alcance,
    actor_humano,
    crear_alcance,
)

from portero.crypto.engine import CryptoEngine
from portero.crypto.errors import CryptoIntegrityError, KekPassphraseError
from portero.crypto.kek import KdfParams, KeyManager
from portero.db.models import KekVersion, Secret, SecretVersion
from portero.db.repositories.secret import SecretRepository
from portero.secrets_mgmt.errors import (
    EnvironmentNotInProjectError,
    SecretNameConflictError,
    SecretNotFoundError,
)
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

# Valores de prueba fáciles de buscar en la base. No son secretos reales.
VALOR_1 = b"marcador-de-prueba-valor-v1"
VALOR_2 = b"marcador-de-prueba-valor-v2"


async def crear(
    servicio: SecretService,
    session: AsyncSession,
    alcance: Alcance,
    nombre: str = "DB_PASSWORD",
    valor: bytes = VALOR_1,
) -> uuid.UUID:
    ref = await servicio.create_secret(
        session,
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        name=nombre,
        value=bytearray(valor),
        actor=actor_humano(alcance.user_id),
    )
    return ref.secret_id


async def test_crear_leer_rotar_y_leer_ambas_versiones(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    ref1 = await servicio.create_secret(
        db_session,
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        name="DB_PASSWORD",
        value=bytearray(VALOR_1),
        actor=actor_humano(alcance.user_id),
        description="contraseña de la base",
        metadata={"equipo": "backend"},
    )
    assert ref1.version_number == 1
    assert (
        await servicio.read_secret_value(db_session, ref1.secret_id, actor=LECTOR_PRUEBA) == VALOR_1
    )

    ref2 = await servicio.rotate_secret(
        db_session, ref1.secret_id, bytearray(VALOR_2), actor=actor_humano(alcance.user_id)
    )
    assert ref2.secret_id == ref1.secret_id
    assert ref2.version_number == 2

    assert (
        await servicio.read_secret_value(db_session, ref1.secret_id, 1, actor=LECTOR_PRUEBA)
        == VALOR_1
    )
    assert (
        await servicio.read_secret_value(db_session, ref1.secret_id, 2, actor=LECTOR_PRUEBA)
        == VALOR_2
    )
    assert (
        await servicio.read_secret_value(db_session, ref1.secret_id, actor=LECTOR_PRUEBA) == VALOR_2
    )

    secreto = await db_session.get(Secret, ref1.secret_id)
    assert secreto is not None
    assert secreto.current_version_id == ref2.version_id
    assert secreto.metadata_ == {"equipo": "backend"}


async def test_lo_guardado_esta_cifrado_y_cada_version_tiene_su_dek(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance, key_manager: KeyManager
) -> None:
    secret_id = await crear(servicio, db_session, alcance)
    await servicio.rotate_secret(
        db_session, secret_id, bytearray(VALOR_1), actor=actor_humano(alcance.user_id)
    )

    filas = (
        await db_session.scalars(
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret_id)
            .order_by(SecretVersion.version_number)
        )
    ).all()
    assert [f.version_number for f in filas] == [1, 2]
    for f in filas:
        assert VALOR_1 not in f.ciphertext
        assert f.aead_algorithm == f.wrap_algorithm == "aes-256-gcm"
        assert f.kek_version_id == key_manager.active_version_id
        assert len(f.nonce) == 12 and f.auth_tag is not None and len(f.auth_tag) == 16
        assert len(f.wrapped_dek) == 60
    # Mismo valor en ambas versiones, pero DEK y ciphertext distintos (RF-006).
    assert filas[0].wrapped_dek != filas[1].wrapped_dek
    assert filas[0].ciphertext != filas[1].ciphertext


async def test_rotar_no_modifica_versiones_anteriores(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await crear(servicio, db_session, alcance)
    sql = text(
        "SELECT ciphertext, nonce, auth_tag, wrapped_dek FROM secret_versions "
        "WHERE secret_id = :s AND version_number = 1"
    )
    antes = (await db_session.execute(sql, {"s": secret_id})).one()

    await servicio.rotate_secret(
        db_session, secret_id, bytearray(VALOR_2), actor=actor_humano(alcance.user_id)
    )

    assert (await db_session.execute(sql, {"s": secret_id})).one() == antes


async def _intercambiar_valor_cifrado(
    session: AsyncSession, origen: uuid.UUID, destino: uuid.UUID
) -> None:
    """Simula a un atacante con escritura en la BD: copia el bundle de la fila ``origen`` a
    ``destino`` (H-05)."""
    await session.execute(
        text(
            "UPDATE secret_versions AS d SET ciphertext = o.ciphertext, nonce = o.nonce, "
            "auth_tag = o.auth_tag, wrapped_dek = o.wrapped_dek "
            "FROM secret_versions AS o WHERE o.id = :o AND d.id = :d"
        ),
        {"o": origen, "d": destino},
    )
    session.expire_all()  # la sesión no debe usar las filas que tenía en memoria


async def test_intercambiar_ciphertext_entre_secretos_falla(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    a = await crear(servicio, db_session, alcance, "SECRETO_A", VALOR_1)
    b = await crear(servicio, db_session, alcance, "SECRETO_B", VALOR_2)
    sa, sb = await db_session.get(Secret, a), await db_session.get(Secret, b)
    assert sa is not None and sb is not None
    assert sa.current_version_id is not None and sb.current_version_id is not None

    await _intercambiar_valor_cifrado(db_session, sb.current_version_id, sa.current_version_id)

    with pytest.raises(CryptoIntegrityError) as exc:
        await servicio.read_secret_value(db_session, a, actor=LECTOR_PRUEBA)
    assert VALOR_2.decode() not in str(exc.value)
    # B, que no se tocó, sigue legible.
    assert await servicio.read_secret_value(db_session, b, actor=LECTOR_PRUEBA) == VALOR_2


async def test_intercambiar_ciphertext_entre_versiones_falla(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await crear(servicio, db_session, alcance, valor=VALOR_1)
    v2 = await servicio.rotate_secret(
        db_session, secret_id, bytearray(VALOR_2), actor=actor_humano(alcance.user_id)
    )
    v1_id = await db_session.scalar(
        select(SecretVersion.id).where(
            SecretVersion.secret_id == secret_id, SecretVersion.version_number == 1
        )
    )
    assert v1_id is not None

    # Revertir al valor viejo copiando la v1 sobre la v2 actual.
    await _intercambiar_valor_cifrado(db_session, v1_id, v2.version_id)

    with pytest.raises(CryptoIntegrityError):
        await servicio.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA)


async def test_fila_sin_tag_falla(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await crear(servicio, db_session, alcance)
    await db_session.execute(
        text("UPDATE secret_versions SET auth_tag = NULL WHERE secret_id = :s"), {"s": secret_id}
    )
    db_session.expire_all()

    with pytest.raises(CryptoIntegrityError):
        await servicio.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA)


async def test_passphrase_incorrecta_aborta_el_arranque(
    db_session: AsyncSession,
    key_manager: KeyManager,
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    # key_manager ya creó la versión 1 con la passphrase de prueba (H-06).
    with pytest.raises(KekPassphraseError, match="^passphrase de KEK incorrecta$"):
        await load_key_manager(
            db_session,
            b"marcador-de-prueba-passphrase-equivocada",
            new_params=parametros_argon2_solo_pruebas,
        )

    versiones = (await db_session.scalars(select(KekVersion))).all()
    assert [v.id for v in versiones] == [key_manager.active_version_id]


async def test_misma_passphrase_recupera_la_kek_y_descifra(
    servicio: SecretService,
    db_session: AsyncSession,
    alcance: Alcance,
    key_manager: KeyManager,
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    # Simula un reinicio del proceso: KEK derivada de nuevo desde kek_versions.
    secret_id = await crear(servicio, db_session, alcance)
    km2 = await load_key_manager(
        db_session, PASSPHRASE_PRUEBA, new_params=parametros_argon2_solo_pruebas
    )
    try:
        servicio2 = SecretService(CryptoEngine(km2))
        assert km2.active_version_id == key_manager.active_version_id
        assert (
            await servicio2.read_secret_value(db_session, secret_id, actor=LECTOR_PRUEBA) == VALOR_1
        )
    finally:
        km2.close()


async def test_nombre_duplicado_en_el_ambiente(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    await crear(servicio, db_session, alcance, "API_KEY")
    with pytest.raises(SecretNameConflictError):
        await crear(servicio, db_session, alcance, "API_KEY")


async def test_nombre_de_secreto_archivado_se_puede_reusar(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    # Índice único parcial WHERE archived_at IS NULL (Cap. 5).
    viejo = await crear(servicio, db_session, alcance, "API_KEY")
    await db_session.execute(
        text("UPDATE secrets SET archived_at = now() WHERE id = :id"), {"id": viejo}
    )
    db_session.expire_all()

    nuevo = await crear(servicio, db_session, alcance, "API_KEY", VALOR_2)

    assert nuevo != viejo
    with pytest.raises(SecretNotFoundError):
        await servicio.read_secret_value(db_session, viejo, actor=LECTOR_PRUEBA)
    with pytest.raises(SecretNotFoundError):
        await servicio.rotate_secret(
            db_session, viejo, bytearray(VALOR_1), actor=actor_humano(alcance.user_id)
        )


async def test_ambiente_de_otro_proyecto_se_rechaza(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    otro = await crear_alcance(db_session)
    with pytest.raises(EnvironmentNotInProjectError):
        await servicio.create_secret(
            db_session,
            project_id=alcance.project_id,
            environment_id=otro.environment_id,
            name="X",
            value=bytearray(VALOR_1),
            actor=actor_humano(alcance.user_id),
        )


async def test_secreto_o_version_inexistente(
    servicio: SecretService, db_session: AsyncSession, alcance: Alcance
) -> None:
    secret_id = await crear(servicio, db_session, alcance)
    with pytest.raises(SecretNotFoundError):
        await servicio.read_secret_value(db_session, uuid.uuid4(), actor=LECTOR_PRUEBA)
    with pytest.raises(SecretNotFoundError):
        await servicio.read_secret_value(db_session, secret_id, 2, actor=LECTOR_PRUEBA)
    with pytest.raises(SecretNotFoundError):
        await servicio.rotate_secret(
            db_session, uuid.uuid4(), bytearray(VALOR_1), actor=actor_humano(alcance.user_id)
        )


async def test_carrera_de_nombres_la_detiene_el_indice_unico(
    servicio: SecretService,
    db_session: AsyncSession,
    alcance: Alcance,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simula que otra creación ganó la carrera entre la verificación (paso 6 de CU-02) y el
    # INSERT: la verificación dice "libre" y el índice único parcial debe impedir el duplicado.
    await crear(servicio, db_session, alcance, "API_KEY")

    async def siempre_libre(*_: object) -> bool:
        return False

    monkeypatch.setattr(SecretRepository, "active_name_exists", siempre_libre)

    with pytest.raises(SecretNameConflictError):
        await crear(servicio, db_session, alcance, "API_KEY")
