"""Custodia de la clave privada Ed25519 y firma/verificación de JWT con EdDSA
("PKI interno" del diagrama de componentes; RFC 8032, RFC 8037; spec §1.1 y §3.2), y firma
desacoplada del cierre diario de la cadena de la bitácora (conclusiones de TT1; H-81).

La clave privada vive solo dentro de ``JwtSigner``: ``auth/tokens.py`` arma y valida los
*claims*, pero nunca toca la clave (Cap. 6 §Visión general).

A diferencia de la firma de la spec §1.1, ``verify_token`` recibe ``audience``, ``issuer`` y
``required_claims``: PyJWT verifica la firma y los *claims* registrados en una sola llamada a
``jwt.decode``, y esos valores no son de este módulo sino del Servicio de Autenticación.
"""

import base64
import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Self

import jwt
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from portero.crypto.errors import SigningKeyError, TokenVerificationError

ALGORITHM = "EdDSA"
"""Único algoritmo aceptado (Cap. 6, tabla de algoritmos). Lista fija: evita la confusión de
algoritmo (OWASP JWT Cheat Sheet)."""

JWT_TYP = "JWT"

JWT_KEY_VARIABLE = "PORTERO_JWT_PRIVATE_KEY"


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def _jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """Thumbprint JWK (RFC 7638) de la clave pública: SHA-256 del JWK con sus miembros
    obligatorios en orden lexicográfico y sin espacios (RFC 8037 §2 y §A.3).

    Se usa como ``kid``: identifica la clave sin configuración extra y cambia solo al rotarla.
    """
    x = _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    jwk_canonico = f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'
    return _b64url(hashlib.sha256(jwk_canonico.encode("ascii")).digest())


def public_key_thumbprint(public_key: Ed25519PublicKey) -> str:
    """Thumbprint RFC 7638 de una clave pública Ed25519 (43 caracteres base64url). Identifica la
    llave de la firma del cierre en ``chain_signatures`` (H-81), igual que el ``kid`` del JWT."""
    return _jwk_thumbprint(public_key)


def load_ed25519_private_key_pem(pem: bytes, variable: str) -> Ed25519PrivateKey:
    """Carga una clave privada Ed25519 en PEM PKCS#8 sin cifrar. ``variable`` es el nombre de la
    variable de entorno de donde vino, para el mensaje de error.

    Rechaza un PEM ilegible y cualquier clave que no sea Ed25519 con ``SigningKeyError``. El
    mensaje es fijo y nunca incluye el PEM: podría ser la clave correcta mal pegada.
    """
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise SigningKeyError(f"{variable} no es una clave privada Ed25519 en PEM") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyError(f"{variable} no es una clave privada Ed25519 en PEM")
    return key


def load_ed25519_public_key_pem(pem: bytes, variable: str) -> Ed25519PublicKey:
    """Carga una clave pública Ed25519 en PEM SubjectPublicKeyInfo (la de
    ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY``, H-81). Igual que la privada: ``SigningKeyError`` con
    mensaje fijo si no es legible o no es Ed25519."""
    try:
        key = load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise SigningKeyError(f"{variable} no es una clave pública Ed25519 en PEM") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError(f"{variable} no es una clave pública Ed25519 en PEM")
    return key


def public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    """Clave pública en PEM SubjectPublicKeyInfo (la usa ``scripts/generate_oplog_key.py``)."""
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def sign_detached(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Firma Ed25519 de ``message``: 64 bytes (RFC 8032 §5.1.6). Es determinista: no depende de un
    generador aleatorio al firmar (conclusiones de TT1)."""
    return private_key.sign(message)


def verify_detached(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """``True`` si ``signature`` es una firma Ed25519 válida de ``message`` (RFC 8032 §5.1.7).

    Nunca lanza: una firma alterada, de otra clave o de largo inválido da ``False``. La firma
    viene de la BD, que quien la manipula controla, así que todo fallo es solo "no válida".
    """
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def generate_private_key_pem() -> bytes:
    """Genera una clave Ed25519 nueva en PEM PKCS#8 sin cifrar (la usa
    ``scripts/generate_jwt_key.py`` y ``scripts/generate_oplog_key.py``). La aleatoriedad la pone
    ``cryptography`` (CSPRNG del SO)."""
    return Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )


class JwtSigner:
    """Firma y verifica JWT con la clave Ed25519 del sistema (Cap. 6 §Estructura del JWT)."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._kid = _jwk_thumbprint(self._public_key)

    @classmethod
    def from_pem(cls, pem: bytes) -> Self:
        """Carga la clave de ``PORTERO_JWT_PRIVATE_KEY``. Rechaza un PEM ilegible y cualquier
        clave que no sea Ed25519 con ``SigningKeyError`` (mensaje fijo, sin el PEM)."""
        return cls(load_ed25519_private_key_pem(pem, JWT_KEY_VARIABLE))

    @property
    def kid(self) -> str:
        """``kid`` de la cabecera: thumbprint RFC 7638 de la clave pública."""
        return self._kid

    def sign_token(self, payload: Mapping[str, Any]) -> str:
        """Firma ``payload`` con EdDSA; cabecera ``{"alg": "EdDSA", "typ": "JWT", "kid": ...}``."""
        return jwt.encode(
            dict(payload),
            self._private_key,
            algorithm=ALGORITHM,
            headers={"typ": JWT_TYP, "kid": self._kid},
        )

    def verify_token(
        self,
        token: str,
        *,
        audience: str,
        issuer: str,
        required_claims: Sequence[str],
    ) -> dict[str, Any]:
        """Pasos 1–8 del Algoritmo de verificación de un JWT entrante (Cap. 6).

        1–2. Cabecera: ``alg`` debe ser ``EdDSA``, ``typ`` ``JWT`` y ``kid`` el de esta clave. Se
             revisa antes de verificar la firma; PyJWT no revisa ``typ`` por su cuenta.
        3–8. ``jwt.decode`` con ``algorithms=["EdDSA"]`` fijo: firma, ``exp`` (si existe),
             ``iat``, ``iss``, ``aud`` y presencia de ``required_claims``. La firma se verifica
             antes que cualquier *claim*.

        Cualquier fallo lanza ``TokenVerificationError`` con un ``reason`` estable.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError:
            raise TokenVerificationError("malformado") from None
        except jwt.InvalidTokenError:
            # H-26: PyJWT valida la cabecera con otras excepciones (p. ej. ``kid`` no textual).
            # La cabecera aún no está autenticada: cualquiera la controla, así que todo fallo
            # aquí debe terminar en ``TokenVerificationError`` y no escapar del módulo.
            raise TokenVerificationError("cabecera") from None
        if (
            header.get("alg") != ALGORITHM
            or header.get("typ") != JWT_TYP
            or header.get("kid") != self._kid
        ):
            raise TokenVerificationError("cabecera")

        try:
            return jwt.decode(
                token,
                self._public_key,
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=issuer,
                options={"require": list(required_claims)},
            )
        except jwt.InvalidSignatureError:
            reason = "firma"
        except jwt.ExpiredSignatureError:
            reason = "expirado"
        except jwt.InvalidAudienceError:
            reason = "audiencia"
        except jwt.InvalidIssuerError:
            reason = "emisor"
        except jwt.MissingRequiredClaimError:
            reason = "claim_faltante"
        except jwt.DecodeError:
            reason = "malformado"
        except jwt.InvalidTokenError:  # iat en el futuro, sub/jti que no son texto, etc.
            reason = "invalido"
        raise TokenVerificationError(reason)
