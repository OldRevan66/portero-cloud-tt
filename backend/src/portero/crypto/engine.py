"""Cifrado y descifrado de secretos con envoltura de DEK: AES-256-GCM con AAD
(Algoritmos 1 y 2 del Cap. 6; NIST SP 800-38D; H-05).

Cada versión de un secreto se cifra con su propia DEK aleatoria, y la DEK se guarda envuelta
(cifrada) bajo la KEK activa. Ambos cifrados llevan datos asociados (AAD) que los ligan al
``secret_id`` y al ``version_number``, para que una fila de ``secret_versions`` copiada a otro
secreto o a otra versión no descifre (H-05).
"""

import dataclasses
import secrets
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from portero.crypto.errors import CryptoAlgorithmError, CryptoError, CryptoIntegrityError
from portero.crypto.kek import KekProvider
from portero.crypto.memory import secure_zero

AEAD_ALGORITHM = "aes-256-gcm"
WRAP_ALGORITHM = "aes-256-gcm"
# Lista blanca (RNF-021): ChaCha20-Poly1305 es alterno documentado, no implementado (spec §1.2).
_SUPPORTED_AEAD = frozenset({AEAD_ALGORITHM})
_SUPPORTED_WRAP = frozenset({WRAP_ALGORITHM})

DEK_LEN = 32  # AES-256
NONCE_LEN = 12  # 96 bits, longitud recomendada por NIST SP 800-38D §5.2.1.1
TAG_LEN = 16  # 128 bits
WRAPPED_DEK_LEN = NONCE_LEN + DEK_LEN + TAG_LEN  # 60 B: nonce_w || ct_dek || tag_w

_VALUE_AAD_PREFIX = b"portero:v1|"
_WRAP_AAD_PREFIX = b"portero:dek:v1|"
_MAX_VERSION_NUMBER = 2**32 - 1  # debe caber en 4 bytes del AAD


@dataclass(frozen=True)
class SecretContext:
    """Identidad de la versión que se cifra o descifra; de aquí sale el AAD (H-05, spec §1.3).

    ``version_number`` empieza en 1 (Algoritmo 3 del Cap. 6) y se codifica en 4 bytes.
    """

    secret_id: UUID
    version_number: int

    def __post_init__(self) -> None:
        if not 1 <= self.version_number <= _MAX_VERSION_NUMBER:
            raise ValueError("version_number fuera de rango")


@dataclass(frozen=True)
class CiphertextBundle:
    """Resultado del Algoritmo 1; se mapea 1:1 a una fila de ``secret_versions`` (spec §1.4)."""

    ciphertext: bytes  # sin tag
    nonce: bytes  # 12 B
    auth_tag: bytes  # 16 B
    wrapped_dek: bytes  # nonce_w (12) || ct_dek (32) || tag_w (16) = 60 B
    aead_algorithm: str
    wrap_algorithm: str
    kek_version_id: UUID


def _value_aad(ctx: SecretContext) -> bytes:
    """AAD del valor: ``b"portero:v1|" || secret_id || version_number`` (H-05)."""
    return _VALUE_AAD_PREFIX + ctx.secret_id.bytes + ctx.version_number.to_bytes(4, "big")


def _wrap_aad(ctx: SecretContext, kek_version_id: UUID) -> bytes:
    """AAD de la envoltura: ``b"portero:dek:v1|" || secret_id || version || kek_id`` (H-05)."""
    return (
        _WRAP_AAD_PREFIX
        + ctx.secret_id.bytes
        + ctx.version_number.to_bytes(4, "big")
        + kek_version_id.bytes
    )


class CryptoEngine:
    """Motor Criptográfico (Cap. 5, diagrama de componentes; Cap. 6, Algoritmos 1, 2 y 4).

    Recibe un ``KekProvider`` que entrega la KEK activa y resuelve KEKs por versión. El motor
    nunca guarda ni borra la KEK: esa memoria pertenece al proveedor.
    """

    def __init__(self, kek_provider: KekProvider) -> None:
        self._kek_provider = kek_provider

    def encrypt_secret(self, plaintext: bytearray, *, ctx: SecretContext) -> CiphertextBundle:
        """Cifra un valor con una DEK nueva y la envuelve bajo la KEK activa.

        Algoritmo 1 del Cap. 6, con AAD (H-05):
        DEK ← CSPRNG(32); nonce ← CSPRNG(12); (ct, tag) ← AES-GCM(DEK, nonce, plaintext, AAD);
        nonce_w ← CSPRNG(12); wrapped ← AES-GCM(KEK, nonce_w, DEK, AAD_w); SecureZero(DEK).

        Nonces de 96 bits aleatorios con una DEK distinta por cifrado: cada clave cifra un solo
        mensaje, muy por debajo del límite de 2^32 invocaciones (NIST SP 800-38D §8.3). La KEK sí
        envuelve muchas DEKs, con un nonce aleatorio independiente en cada envoltura.

        El plaintext no se borra aquí: es del llamador, que lo borra cuando termine (Algoritmo 2).
        """
        kek_version_id = self._kek_provider.active_version_id
        kek = self._kek_provider.get_kek(kek_version_id)
        dek = bytearray(secrets.token_bytes(DEK_LEN))
        try:
            nonce = secrets.token_bytes(NONCE_LEN)
            ct_and_tag = AESGCM(dek).encrypt(nonce, plaintext, _value_aad(ctx))

            nonce_w = secrets.token_bytes(NONCE_LEN)
            wrapped = AESGCM(kek).encrypt(nonce_w, dek, _wrap_aad(ctx, kek_version_id))
        finally:
            secure_zero(dek)

        # AESGCM.encrypt devuelve ct || tag: el tag son los últimos 16 bytes (spec §1.4).
        return CiphertextBundle(
            ciphertext=ct_and_tag[:-TAG_LEN],
            nonce=nonce,
            auth_tag=ct_and_tag[-TAG_LEN:],
            wrapped_dek=nonce_w + wrapped,
            aead_algorithm=AEAD_ALGORITHM,
            wrap_algorithm=WRAP_ALGORITHM,
            kek_version_id=kek_version_id,
        )

    def decrypt_secret(self, bundle: CiphertextBundle, *, ctx: SecretContext) -> bytearray:
        """Descifra un bundle y devuelve el valor como ``bytearray``.

        Algoritmo 2 del Cap. 6: validar algoritmos → resolver KEK por ``kek_version_id`` →
        desenvolver DEK → descifrar → SecureZero(DEK). La DEK y el valor se descifran con
        ``AESGCM.decrypt_into`` en ``bytearray`` preasignados, sin copias ``bytes`` (H-16). La
        DEK se borra siempre; el búfer del valor se borra si la autenticación falla (Algoritmo 4).
        El llamador debe aplicar ``secure_zero`` al resultado después de usarlo (H-13).

        Raises:
            CryptoAlgorithmError: algoritmo fuera de la lista blanca (RNF-021).
            CryptoIntegrityError: falla la autenticación de GCM en la envoltura o en el valor,
                o los campos tienen longitudes inválidas (NIST SP 800-38D §7.2).
            CryptoError: la versión de KEK no está disponible en el proveedor.
        """
        if (
            bundle.aead_algorithm not in _SUPPORTED_AEAD
            or bundle.wrap_algorithm not in _SUPPORTED_WRAP
        ):
            raise CryptoAlgorithmError("algoritmo de cifrado no soportado")

        if (
            len(bundle.nonce) != NONCE_LEN
            or len(bundle.auth_tag) != TAG_LEN
            or len(bundle.wrapped_dek) != WRAPPED_DEK_LEN
        ):
            raise CryptoIntegrityError("el secreto cifrado no pasó la verificación de integridad")

        try:
            kek = self._kek_provider.get_kek(bundle.kek_version_id)
        except KeyError:
            raise CryptoError("la versión de KEK del secreto no está disponible") from None

        nonce_w = bundle.wrapped_dek[:NONCE_LEN]
        wrapped = bundle.wrapped_dek[NONCE_LEN:]
        # H-16: ``decrypt_into`` escribe en búferes del motor que sí se pueden borrar, en vez de
        # devolver ``bytes`` inmutables. Cada búfer mide exactamente lo que se va a descifrar.
        dek = bytearray(DEK_LEN)
        plaintext = bytearray(len(bundle.ciphertext))
        autenticado = False
        try:
            AESGCM(kek).decrypt_into(nonce_w, wrapped, _wrap_aad(ctx, bundle.kek_version_id), dek)
            AESGCM(dek).decrypt_into(
                bundle.nonce, bundle.ciphertext + bundle.auth_tag, _value_aad(ctx), plaintext
            )
            autenticado = True
        except InvalidTag:
            # ``from None``: no se encadena la excepción original; el mensaje es fijo.
            raise CryptoIntegrityError(
                "el secreto cifrado no pasó la verificación de integridad"
            ) from None
        finally:
            secure_zero(dek)
            if not autenticado:
                # Si la etiqueta falla, el búfer ya contiene datos sin autenticar (H-16).
                secure_zero(plaintext)
        return plaintext

    def rewrap_dek(
        self, bundle: CiphertextBundle, *, ctx: SecretContext, target: KekProvider
    ) -> CiphertextBundle:
        """Re-envuelve la DEK de ``bundle`` bajo la KEK activa de ``target`` (H-07; H-05).

        Rotación de KEK (spec §1.6): este motor (el de la KEK vieja) desenvuelve la DEK con el
        AAD que lleva el ``kek_version_id`` viejo, y la vuelve a envolver con un ``nonce_w``
        nuevo y el AAD del ``kek_version_id`` nuevo. El valor cifrado no se toca: ``ciphertext``,
        ``nonce`` y ``auth_tag`` se copian tal cual, porque la DEK es la misma. Solo cambian
        ``wrapped_dek`` y ``kek_version_id`` (60 B por versión). La DEK en claro se borra al
        terminar (Algoritmo 4).

        Raises:
            CryptoAlgorithmError: algoritmo fuera de la lista blanca (RNF-021).
            CryptoIntegrityError: la envoltura vieja no autentica (alterada, de otro secreto o
                de otra versión) o tiene una longitud inválida.
            CryptoError: la versión de KEK del bundle no está disponible en este motor.
        """
        if (
            bundle.aead_algorithm not in _SUPPORTED_AEAD
            or bundle.wrap_algorithm not in _SUPPORTED_WRAP
        ):
            raise CryptoAlgorithmError("algoritmo de cifrado no soportado")
        if len(bundle.wrapped_dek) != WRAPPED_DEK_LEN:
            raise CryptoIntegrityError("el secreto cifrado no pasó la verificación de integridad")

        try:
            old_kek = self._kek_provider.get_kek(bundle.kek_version_id)
        except KeyError:
            raise CryptoError("la versión de KEK del secreto no está disponible") from None
        new_kek_version_id = target.active_version_id
        new_kek = target.get_kek(new_kek_version_id)

        dek = bytearray(DEK_LEN)  # H-16: se desenvuelve en un búfer borrable
        try:
            AESGCM(old_kek).decrypt_into(
                bundle.wrapped_dek[:NONCE_LEN],
                bundle.wrapped_dek[NONCE_LEN:],
                _wrap_aad(ctx, bundle.kek_version_id),
                dek,
            )
            nonce_w = secrets.token_bytes(NONCE_LEN)
            wrapped = AESGCM(new_kek).encrypt(nonce_w, dek, _wrap_aad(ctx, new_kek_version_id))
        except InvalidTag:
            raise CryptoIntegrityError(
                "el secreto cifrado no pasó la verificación de integridad"
            ) from None
        finally:
            secure_zero(dek)

        return dataclasses.replace(
            bundle,
            wrapped_dek=nonce_w + wrapped,
            wrap_algorithm=WRAP_ALGORITHM,
            kek_version_id=new_kek_version_id,
        )
