"""Pruebas de la firma Ed25519 desacoplada del Motor Criptográfico para el cierre de la cadena de
la bitácora (H-81; RFC 8032; NIST SP 800-57 Pt. 1 §5.2: llave dedicada).

La única clave fija es la del vector oficial TEST 1 de RFC 8032 §7.1 (pública, no es un secreto).
Las demás se generan en cada prueba.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from portero.crypto.errors import SigningKeyError
from portero.crypto.signing import (
    generate_private_key_pem,
    load_ed25519_private_key_pem,
    load_ed25519_public_key_pem,
    public_key_pem,
    public_key_thumbprint,
    sign_detached,
    verify_detached,
)

# RFC 8032 §7.1, TEST 1 (mensaje vacío).
TEST1_SK = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST1_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
VARIABLE = "PORTERO_OPLOG_SIGNING_PRIVATE_KEY"


def _clave_test1() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST1_SK))


def test_sign_detached_reproduce_el_vector_test1_de_rfc8032() -> None:
    assert sign_detached(_clave_test1(), b"").hex() == TEST1_SIG


def test_verify_detached_acepta_la_firma_del_vector() -> None:
    publica = _clave_test1().public_key()

    assert verify_detached(publica, b"", bytes.fromhex(TEST1_SIG)) is True


def test_verify_detached_rechaza_una_firma_alterada() -> None:
    publica = _clave_test1().public_key()
    firma = bytearray(bytes.fromhex(TEST1_SIG))
    firma[0] ^= 0x01

    assert verify_detached(publica, b"", bytes(firma)) is False


def test_verify_detached_rechaza_otro_mensaje() -> None:
    clave = Ed25519PrivateKey.generate()
    firma = sign_detached(clave, b"mensaje original")

    assert verify_detached(clave.public_key(), b"mensaje alterado", firma) is False


def test_verify_detached_rechaza_la_firma_de_otra_clave() -> None:
    firma = sign_detached(Ed25519PrivateKey.generate(), b"m")

    assert verify_detached(Ed25519PrivateKey.generate().public_key(), b"m", firma) is False


def test_verify_detached_rechaza_una_firma_de_largo_invalido() -> None:
    """Una columna alterada en la BD puede traer cualquier cosa: nunca lanza, devuelve False."""
    publica = _clave_test1().public_key()

    assert verify_detached(publica, b"", b"corta") is False


def test_las_claves_pem_van_y_vuelven() -> None:
    pem_privada = generate_private_key_pem()
    privada = load_ed25519_private_key_pem(pem_privada, VARIABLE)
    publica = load_ed25519_public_key_pem(public_key_pem(privada.public_key()), VARIABLE)

    firma = sign_detached(privada, b"cierre")

    assert verify_detached(publica, b"cierre", firma) is True
    assert public_key_pem(publica).startswith(b"-----BEGIN PUBLIC KEY-----")


def test_thumbprint_es_el_kid_rfc7638_y_mide_43_caracteres() -> None:
    publica = _clave_test1().public_key()

    huella = public_key_thumbprint(publica)

    assert len(huella) == 43
    assert huella == public_key_thumbprint(_clave_test1().public_key())
    assert huella != public_key_thumbprint(Ed25519PrivateKey.generate().public_key())


@pytest.mark.parametrize("pem", [b"", b"no-es-un-pem", b"-----BEGIN PRIVATE KEY-----\nxx\n"])
def test_pem_privado_invalido_se_rechaza_sin_incluirlo(pem: bytes) -> None:
    with pytest.raises(SigningKeyError) as exc:
        load_ed25519_private_key_pem(pem, VARIABLE)

    assert VARIABLE in str(exc.value)
    if pem:
        assert pem.decode() not in str(exc.value)


def test_pem_publico_invalido_se_rechaza() -> None:
    with pytest.raises(SigningKeyError) as exc:
        load_ed25519_public_key_pem(b"no-es-un-pem", "PORTERO_OPLOG_SIGNING_PUBLIC_KEY")

    assert "PORTERO_OPLOG_SIGNING_PUBLIC_KEY" in str(exc.value)


def test_clave_que_no_es_ed25519_se_rechaza() -> None:
    otra = ec.generate_private_key(ec.SECP256R1())
    pem_privada = otra.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pem_publica = otra.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    with pytest.raises(SigningKeyError):
        load_ed25519_private_key_pem(pem_privada, VARIABLE)
    with pytest.raises(SigningKeyError):
        load_ed25519_public_key_pem(pem_publica, VARIABLE)
