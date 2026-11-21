"""Pruebas de la custodia de la clave Ed25519 y de la firma/verificación de JWT
("PKI interno" del diagrama de componentes; Cap. 6 §Estructura del JWT; RFC 8037; spec §3.2).

Cada prueba genera sus propias claves: no hay claves privadas commiteadas. La única clave fija es
la del ejemplo público del Apéndice A de RFC 8037 (vector oficial, no es un secreto).
"""

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from portero.crypto.errors import CryptoError, SigningKeyError, TokenVerificationError
from portero.crypto.signing import JwtSigner, generate_private_key_pem

AUD = "portero-cloud"
ISS = "https://portero.example.test"
REQUERIDOS = ["iss", "sub", "aud", "iat", "jti"]

# RFC 8037 §A.1 (clave de ejemplo) y §A.3 (thumbprint JWK, RFC 7638).
RFC8037_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def _b64url_decode(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _pem(clave: Ed25519PrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    return clave.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.fixture
def signer() -> JwtSigner:
    return JwtSigner.from_pem(generate_private_key_pem())


def _payload() -> dict[str, object]:
    return {"iss": ISS, "sub": "s", "aud": AUD, "iat": 1, "jti": "j"}


# --- Carga de la clave --------------------------------------------------------------------------


def test_kid_es_el_thumbprint_rfc7638_del_vector_de_rfc8037() -> None:
    clave = Ed25519PrivateKey.from_private_bytes(_b64url_decode(RFC8037_D))

    assert JwtSigner.from_pem(_pem(clave)).kid == RFC8037_THUMBPRINT


def test_kid_es_estable_y_depende_de_la_clave() -> None:
    pem = generate_private_key_pem()

    assert JwtSigner.from_pem(pem).kid == JwtSigner.from_pem(pem).kid
    assert JwtSigner.from_pem(pem).kid != JwtSigner.from_pem(generate_private_key_pem()).kid


@pytest.mark.parametrize(
    "pem",
    [
        b"marcador-de-prueba-no-es-una-clave",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        b"",
    ],
    ids=["texto", "pem-corrupto", "vacio"],
)
def test_pem_invalido_se_rechaza_sin_incluirlo_en_el_mensaje(pem: bytes) -> None:
    with pytest.raises(SigningKeyError) as exc:
        JwtSigner.from_pem(pem)

    assert isinstance(exc.value, CryptoError)
    assert "marcador" not in str(exc.value)
    assert "AAAA" not in str(exc.value)


def test_clave_que_no_es_ed25519_se_rechaza() -> None:
    """Una clave EC P-256 es PEM válido, pero el diseño fija Ed25519 (Cap. 6, tabla de
    algoritmos)."""
    pem = _pem(ec.generate_private_key(ec.SECP256R1()))

    with pytest.raises(SigningKeyError) as exc:
        JwtSigner.from_pem(pem)

    assert "PRIVATE KEY" not in str(exc.value)


def test_generate_private_key_pem_produce_claves_ed25519_distintas() -> None:
    a, b = generate_private_key_pem(), generate_private_key_pem()

    assert a != b
    assert isinstance(load_pem_private_key(a, password=None), Ed25519PrivateKey)
    assert a.startswith(b"-----BEGIN PRIVATE KEY-----")


# --- Firma ----------------------------------------------------------------------------------------


def test_cabecera_trae_alg_typ_y_kid(signer: JwtSigner) -> None:
    token = signer.sign_token(_payload())

    cabecera = json.loads(_b64url_decode(token.split(".")[0]))
    assert cabecera == {"alg": "EdDSA", "typ": "JWT", "kid": signer.kid}


def test_ida_y_vuelta(signer: JwtSigner) -> None:
    token = signer.sign_token(_payload())

    claims = signer.verify_token(token, audience=AUD, issuer=ISS, required_claims=REQUERIDOS)

    assert claims == _payload()


def test_sign_token_no_modifica_el_payload(signer: JwtSigner) -> None:
    payload = _payload()
    signer.sign_token(payload)

    assert payload == _payload()


# --- Verificación (los rechazos detallados viven en tests/unit/auth/test_tokens.py) -------------


def test_firma_de_otra_clave_se_rechaza(signer: JwtSigner) -> None:
    otro = JwtSigner.from_pem(generate_private_key_pem())
    token = otro.sign_token(_payload())

    with pytest.raises(TokenVerificationError) as exc:
        signer.verify_token(token, audience=AUD, issuer=ISS, required_claims=REQUERIDOS)

    assert exc.value.reason == "cabecera"  # kid desconocido: ni siquiera se intenta verificar


def test_la_lista_de_algoritmos_es_fija(signer: JwtSigner, monkeypatch: pytest.MonkeyPatch) -> None:
    """``jwt.decode`` siempre recibe ``algorithms=["EdDSA"]`` (Cap. 6, paso 2 del Algoritmo de
    verificación; evita la confusión de algoritmo)."""
    llamadas: list[object] = []
    original = jwt.decode

    def espia(*args: object, **kwargs: object) -> object:
        llamadas.append(kwargs.get("algorithms"))
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(jwt, "decode", espia)
    signer.verify_token(
        signer.sign_token(_payload()), audience=AUD, issuer=ISS, required_claims=REQUERIDOS
    )

    assert llamadas == [["EdDSA"]]


def test_el_mensaje_de_error_no_incluye_el_token(signer: JwtSigner) -> None:
    token = signer.sign_token(_payload())
    alterado = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")

    with pytest.raises(TokenVerificationError) as exc:
        signer.verify_token(alterado, audience=AUD, issuer=ISS, required_claims=REQUERIDOS)

    assert alterado not in str(exc.value)
    assert alterado.split(".")[1] not in str(exc.value)
