"""Pruebas puras de la firma del cierre de la cadena (H-81; H-46; OWASP ASVS V7.3.3).

Sin BD: el mensaje firmado y ``verify_checkpoints`` sobre filas de ``chain_signatures`` en
memoria. La cadena de ejemplo se arma con ``_cadena`` de ``test_hash_chain``.
"""

import dataclasses
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.oplog.test_hash_chain import _cadena

from portero.crypto.signing import public_key_thumbprint, sign_detached
from portero.oplog.chain import ChainRow, verify_chain
from portero.oplog.checkpoint import (
    CHECKPOINT_DOMAIN,
    CheckpointVerification,
    SignatureRow,
    checkpoint_message,
    verify_checkpoints,
)

INSTANTE = datetime(2026, 10, 29, 23, 0, 0, 123456, tzinfo=UTC)
HASH = "ab" * 32


def _firmar(
    clave: Ed25519PrivateKey,
    fila: ChainRow,
    *,
    instante: datetime = INSTANTE,
    firma_id: UUID | None = None,
) -> SignatureRow:
    """Lo que hará ``sign-chain``: firma el cierre en ``fila``."""
    huella = public_key_thumbprint(clave.public_key())
    mensaje = checkpoint_message(
        created_at=instante,
        last_audit_id=fila.id,
        last_hash=fila.current_hash,
        public_key_thumbprint=huella,
    )
    return SignatureRow(
        id=firma_id or uuid4(),
        created_at=instante,
        last_audit_id=fila.id,
        last_hash=fila.current_hash,
        signature=sign_detached(clave, mensaje),
        public_key_thumbprint=huella,
    )


def _verificar(
    filas: list[ChainRow],
    firmas: list[SignatureRow],
    clave: Ed25519PrivateKey | None,
    registradas: list[UUID] | None = None,
) -> CheckpointVerification:
    cadena = verify_chain(filas)
    return verify_checkpoints(
        firmas,
        stored_hashes={f.id: f.current_hash for f in filas},
        broken=cadena.broken,
        recorded_signature_ids=[f.id for f in firmas] if registradas is None else registradas,
        public_key=clave.public_key() if clave is not None else None,
    )


@pytest.fixture
def clave() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


# --- Mensaje firmado -----------------------------------------------------------------------------


def test_el_mensaje_es_la_etiqueta_de_dominio_mas_json_canonico() -> None:
    mensaje = checkpoint_message(
        created_at=INSTANTE, last_audit_id=42, last_hash=HASH, public_key_thumbprint="huella"
    )

    assert CHECKPOINT_DOMAIN == b"portero-cloud/oplog-checkpoint/v1\n"
    assert mensaje == CHECKPOINT_DOMAIN + (
        b'{"created_at":"2026-10-29T23:00:00.123456+00:00","last_audit_id":42,'
        b'"last_hash":"' + HASH.encode() + b'","public_key_thumbprint":"huella"}'
    )


def test_el_mensaje_no_depende_de_la_zona_horaria() -> None:
    """La BD devuelve ``timestamptz`` en otra zona: el mensaje debe ser el mismo."""
    otra_zona = INSTANTE.astimezone(timezone(timedelta(hours=-6)))

    def mensaje(instante: datetime) -> bytes:
        return checkpoint_message(
            created_at=instante, last_audit_id=1, last_hash=HASH, public_key_thumbprint="h"
        )

    assert mensaje(otra_zona) == mensaje(INSTANTE)


def test_fecha_sin_zona_horaria_se_rechaza() -> None:
    with pytest.raises(ValueError, match="zona horaria"):
        checkpoint_message(
            created_at=datetime(2026, 10, 29),  # noqa: DTZ001
            last_audit_id=1,
            last_hash=HASH,
            public_key_thumbprint="h",
        )


# --- Verificación de las firmas ------------------------------------------------------------------


def test_sin_llave_publica_la_firma_no_esta_configurada(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(3)

    resultado = _verificar(filas, [_firmar(clave, filas[-1])], None)

    assert resultado.signing_configured is False
    assert resultado.invalid == []
    assert resultado.last_signed_at is None


def test_sin_firmas_no_hay_ultima_firma(clave: Ed25519PrivateKey) -> None:
    resultado = _verificar(_cadena(3), [], clave)

    assert resultado.signing_configured is True
    assert resultado.total == 0
    assert resultado.invalid == []
    assert resultado.last_signed_at is None
    assert resultado.last_signed_audit_id is None


def test_firma_valida_reporta_su_fecha_y_su_registro(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(5)

    resultado = _verificar(filas, [_firmar(clave, filas[2])], clave)

    assert resultado.total == 1
    assert resultado.invalid == []
    assert resultado.missing == []
    assert resultado.last_signed_at == INSTANTE
    assert resultado.last_signed_audit_id == 3


def test_la_ultima_firma_valida_es_la_mas_reciente(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(5)
    firmas = [
        _firmar(clave, filas[1]),
        _firmar(clave, filas[3], instante=INSTANTE + timedelta(days=1)),
    ]

    resultado = _verificar(filas, firmas, clave)

    assert resultado.last_signed_audit_id == 4
    assert resultado.last_signed_at == INSTANTE + timedelta(days=1)


def test_firma_alterada_es_invalida(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(3)
    firma = _firmar(clave, filas[-1])
    alterada = bytearray(firma.signature)
    alterada[10] ^= 0x01
    firma = dataclasses.replace(firma, signature=bytes(alterada))

    resultado = _verificar(filas, [firma], clave)

    assert resultado.invalid == [str(firma.id)]
    assert resultado.last_signed_at is None


def test_fecha_alterada_invalida_la_firma(clave: Ed25519PrivateKey) -> None:
    """``created_at`` entra en el mensaje: no se puede hacer pasar una firma vieja por reciente."""
    filas = _cadena(3)
    firma = _firmar(clave, filas[-1])
    firma = dataclasses.replace(firma, created_at=INSTANTE + timedelta(days=3))

    assert _verificar(filas, [firma], clave).invalid == [str(firma.id)]


def test_last_hash_que_no_coincide_con_la_fila_es_invalido(clave: Ed25519PrivateKey) -> None:
    """La firma es auténtica, pero la fila ``last_audit_id`` ya no tiene ese ``current_hash``:
    alguien reescribió y recalculó la cadena (el caso de H-46 que pasaba la verificación)."""
    filas = _cadena(5)
    firma = _firmar(clave, filas[2])
    reescrita = [dataclasses.replace(f, current_hash="cd" * 32) if f.id == 3 else f for f in filas]

    resultado = verify_checkpoints(
        [firma],
        stored_hashes={f.id: f.current_hash for f in reescrita},
        broken=[],
        recorded_signature_ids=[firma.id],
        public_key=clave.public_key(),
    )

    assert resultado.invalid == [str(firma.id)]


def test_la_fila_firmada_rota_invalida_la_firma(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(5)
    firma = _firmar(clave, filas[2])

    resultado = verify_checkpoints(
        [firma],
        stored_hashes={f.id: f.current_hash for f in filas},
        broken=[3],
        recorded_signature_ids=[firma.id],
        public_key=clave.public_key(),
    )

    assert resultado.invalid == [str(firma.id)]


def test_truncar_el_final_ya_firmado_se_detecta(clave: Ed25519PrivateKey) -> None:
    """Contraparte de ``test_truncar_el_final_pasa_la_verificacion_pero_cambia_el_ancla`` (H-46):
    sin firma el truncado pasa; con una firma sobre el registro 5, borrar los registros 4 y 5
    deja la firma sin su fila y la verificación lo reporta."""
    filas = _cadena(5)
    firma = _firmar(clave, filas[-1])
    truncado = filas[:3]

    assert verify_chain(truncado).ok is True  # la cadena sola no lo ve (H-46)
    resultado = _verificar(truncado, [firma], clave)

    assert resultado.invalid == [str(firma.id)]


def test_firma_de_otra_llave_es_invalida_no_se_omite(clave: Ed25519PrivateKey) -> None:
    """Omitirla permitiría desactivar el ancla cambiando el thumbprint en la BD."""
    filas = _cadena(3)
    firma = _firmar(Ed25519PrivateKey.generate(), filas[-1])

    resultado = _verificar(filas, [firma], clave)

    assert resultado.invalid == [str(firma.id)]


def test_thumbprint_cambiado_en_la_bd_es_invalido(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(3)
    firma = dataclasses.replace(_firmar(clave, filas[-1]), public_key_thumbprint="x" * 43)

    assert _verificar(filas, [firma], clave).invalid == [str(firma.id)]


def test_firma_registrada_en_la_bitacora_que_ya_no_existe_es_faltante(
    clave: Ed25519PrivateKey,
) -> None:
    """Cada ``sign_chain`` exitoso deja el id de su firma en ``resource_id``. Si la fila de
    ``chain_signatures`` desaparece sin tocar la cadena, la verificación cruzada lo reporta."""
    filas = _cadena(3)
    borrada = uuid4()

    resultado = _verificar(filas, [], clave, registradas=[borrada])

    assert resultado.missing == [str(borrada)]


def test_una_firma_invalida_no_tapa_la_ultima_valida(clave: Ed25519PrivateKey) -> None:
    filas = _cadena(5)
    valida = _firmar(clave, filas[1])
    invalida = dataclasses.replace(
        _firmar(clave, filas[3], instante=INSTANTE + timedelta(days=1)), last_hash="ef" * 32
    )

    resultado = _verificar(filas, [valida, invalida], clave)

    assert resultado.invalid == [str(invalida.id)]
    assert resultado.last_signed_audit_id == 2
