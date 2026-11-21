"""Gestión de la KEK: interfaz ``KekProvider`` y ``KeyManager`` con derivación Argon2id y
verificador de passphrase (Cap. 6 §Derivación de la KEK; RFC 9106; spec §1.6; H-06).

La KEK nunca se persiste: en ``kek_versions`` solo quedan la sal, los parámetros de Argon2id y el
verificador, y la KEK se vuelve a derivar en memoria en cada arranque a partir de la passphrase
del operador (``PORTERO_KEK_PASSPHRASE``).

Este módulo no importa la Capa de Persistencia: recibe un ``KekVersionStore`` (protocolo) que
implementa ``KekVersionRepository`` en ``portero.db.repositories.secret``. Así el Motor
Criptográfico se prueba sin base de datos y la regla de capas del monolito se respeta.

La rotación de KEK (H-07; NIST SP 800-57) usa ``KeyManager.create_version`` para la versión N+1
y ``CryptoEngine.rewrap_dek`` para re-envolver las DEKs; la orquesta
``portero.secrets_mgmt.kek_rotation``.
"""

import base64
import binascii
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, Self
from uuid import UUID

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from portero.crypto.errors import CryptoError, KekPassphraseError
from portero.crypto.memory import secure_zero

SOURCE_PASSWORD_KDF = "password_kdf"  # noqa: S105  # valor de kek_versions.source, no una contraseña
SOURCE_EXTERNAL_KMS = "external_kms"
KDF_ALGORITHM = "argon2id"

KEK_LEN = 32  # AES-256
SALT_LEN = 16  # spec §1.2
_NONCE_LEN = 12
_TAG_LEN = 16
_VERIFIER_PLAINTEXT = b"portero-kek-check"  # H-06: constante conocida, no es secreta
_PASSPHRASE_ERROR = "passphrase de KEK incorrecta"  # noqa: S105  # mensaje de error fijo

# H-35: rangos admitidos para los parámetros de Argon2id. Los mínimos son los del propio
# algoritmo (RFC 9106 §3.1: t ≥ 1, p ≥ 1, m ≥ 8·p KiB); unos parámetros débiles no son
# explotables porque el verificador (H-06) aborta. Los techos son varias veces los de producción
# (m=128 MiB, t=4): admiten un aumento legítimo, pero no un valor que agote la memoria o deje el
# arranque colgado si alguien altera ``kek_versions``.
MAX_MEMORY_COST_KIB = 1048576  # 1 GiB, 8× producción
MAX_TIME_COST = 16  # 4× producción
MAX_PARALLELISM = 16


@dataclass(frozen=True)
class KdfParams:
    """Parámetros de Argon2id para derivar la KEK (RFC 9106; Cap. 6, tabla de algoritmos)."""

    memory_cost_kib: int
    time_cost: int
    parallelism: int
    hash_len: int = KEK_LEN

    def __post_init__(self) -> None:
        """Rechaza parámetros fuera de rango antes de cualquier derivación (H-35)."""
        if not (
            1 <= self.time_cost <= MAX_TIME_COST
            and 1 <= self.parallelism <= MAX_PARALLELISM
            and 8 * self.parallelism <= self.memory_cost_kib <= MAX_MEMORY_COST_KIB
        ):
            raise ValueError("parámetros de Argon2id fuera de rango")


PARAMETROS_KEK_PRODUCCION = KdfParams(memory_cost_kib=131072, time_cost=4, parallelism=1)
"""m=128 MiB, t=4, p=1 (Cap. 6): una sola derivación por arranque, así que puede ser costosa."""


@dataclass(frozen=True)
class KekVersionRecord:
    """Fila de ``kek_versions`` vista desde el Motor Criptográfico (Cap. 5; H-06).

    ``kdf_params`` es el JSON de la columna: ``memory_cost_kib``, ``time_cost``, ``parallelism``,
    ``hash_len`` y ``salt_b64`` (la sal en Base64, porque JSON no admite bytes).
    """

    id: UUID
    version_number: int
    source: str
    kdf_algorithm: str | None
    kdf_params: Mapping[str, object] | None
    verifier: bytes | None


class KekVersionStore(Protocol):
    """Acceso a ``kek_versions`` que necesita el ``KeyManager`` (lo implementa la Capa de
    Persistencia)."""

    async def get_active(self) -> KekVersionRecord | None:
        """Versión con ``deactivated_at IS NULL``, o ``None`` si es el primer arranque."""
        ...

    async def add(self, record: KekVersionRecord) -> None:
        """Inserta una versión nueva y activa."""
        ...


class KekProvider(Protocol):
    """Origen de la KEK: la "Bóveda KEK (memoria / KMS externo)" de los diagramas (spec §1.6).

    El Motor Criptográfico depende solo de esta interfaz, así que el origen ``password_kdf``
    (Argon2id sobre la passphrase) y el futuro ``external_kms`` son intercambiables.
    """

    @property
    def active_version_id(self) -> UUID:
        """Id de la versión activa en ``kek_versions`` (``deactivated_at IS NULL``)."""
        ...

    def get_kek(self, kek_version_id: UUID) -> bytearray:
        """Devuelve la KEK (32 B) de esa versión; ``KeyError`` si no está disponible.

        El ``bytearray`` pertenece al proveedor: el llamador no debe modificarlo ni borrarlo.
        """
        ...


def _derive(passphrase: bytes, salt: bytes, params: KdfParams) -> bytearray:
    """KEK = Argon2id(passphrase, sal, m, t, p) con salida de 32 B (RFC 9106; Cap. 6)."""
    return bytearray(
        hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Type.ID,
        )
    )


def _make_verifier(kek: bytearray, kek_version_id: UUID) -> bytes:
    """Verificador H-06: ``nonce || AES-GCM(KEK, nonce, "portero-kek-check", AAD=id)``."""
    nonce = secrets.token_bytes(_NONCE_LEN)
    return nonce + AESGCM(kek).encrypt(nonce, _VERIFIER_PLAINTEXT, kek_version_id.bytes)


def _check_verifier(kek: bytearray, kek_version_id: UUID, verifier: bytes) -> None:
    """Descifra el verificador; si no autentica, la passphrase es incorrecta (H-06)."""
    if len(verifier) < _NONCE_LEN + _TAG_LEN:
        raise KekPassphraseError(_PASSPHRASE_ERROR)
    try:
        claro = AESGCM(kek).decrypt(
            verifier[:_NONCE_LEN], verifier[_NONCE_LEN:], kek_version_id.bytes
        )
    except InvalidTag:
        raise KekPassphraseError(_PASSPHRASE_ERROR) from None
    if claro != _VERIFIER_PLAINTEXT:
        raise KekPassphraseError(_PASSPHRASE_ERROR)


def _params_to_json(params: KdfParams, salt: bytes) -> dict[str, object]:
    return {
        "memory_cost_kib": params.memory_cost_kib,
        "time_cost": params.time_cost,
        "parallelism": params.parallelism,
        "hash_len": params.hash_len,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
    }


def _params_from_json(data: Mapping[str, object] | None) -> tuple[KdfParams, bytes]:
    """Valida el JSON de ``kdf_params``. Un valor malformado detiene el arranque."""
    invalid = CryptoError("parámetros de KDF de la KEK inválidos")
    if data is None:
        raise invalid
    enteros: dict[str, int] = {}
    for campo in ("memory_cost_kib", "time_cost", "parallelism", "hash_len"):
        valor = data.get(campo)
        if type(valor) is not int:  # excluye bool y cadenas
            raise invalid
        enteros[campo] = valor
    sal_b64 = data.get("salt_b64")
    if not isinstance(sal_b64, str):
        raise invalid
    try:
        salt = base64.b64decode(sal_b64, validate=True)
    except binascii.Error:
        raise invalid from None
    if len(salt) != SALT_LEN or enteros["hash_len"] != KEK_LEN:
        raise invalid
    try:
        params = KdfParams(**enteros)
    except ValueError:  # fuera de rango (H-35): se detiene el arranque sin derivar
        raise invalid from None
    return params, salt


class KeyManager:
    """Custodia la KEK activa en memoria; implementa ``KekProvider`` (spec §1.6).

    Se construye con ``bootstrap`` al arrancar el proceso. La KEK vive solo en un ``bytearray``
    y ``close`` la borra (Algoritmo 4). Es *best-effort*: la passphrase llega como ``bytes``
    inmutables y ``argon2-cffi`` devuelve la KEK como ``bytes``; esas copias no se pueden borrar.
    """

    def __init__(self, kek_version_id: UUID, kek: bytearray) -> None:
        self._version_id = kek_version_id
        self._kek = kek
        self._closed = False

    @classmethod
    async def bootstrap(
        cls,
        store: KekVersionStore,
        passphrase: bytes,
        *,
        new_params: KdfParams = PARAMETROS_KEK_PRODUCCION,
    ) -> Self:
        """Deriva la KEK activa, o crea la versión 1 en el primer arranque (spec §1.6, H-06).

        - Sin versiones: genera id y sal nuevos, deriva con ``new_params``, cifra el verificador
          e inserta la versión 1.
        - Con versión activa: deriva con la sal y los parámetros **guardados** (``new_params``
          se ignora) y descifra el verificador.

        Si dos procesos arrancan a la vez por primera vez, ``UNIQUE(version_number)`` hace fallar
        al segundo, que al reiniciarse carga la versión del primero.

        Raises:
            ValueError: passphrase vacía.
            KekPassphraseError: la passphrase no descifra el verificador; el proceso debe abortar.
            CryptoError: el registro de ``kek_versions`` está malformado.
            NotImplementedError: origen ``external_kms`` (trabajo futuro).
        """
        if not passphrase:
            raise ValueError("la passphrase de KEK no puede estar vacía")

        record = await store.get_active()
        if record is None:
            manager, record = cls._create_first_version(passphrase, new_params)
            try:
                await store.add(record)
            except BaseException:
                manager.close()
                raise
            return manager
        return cls.load(record, passphrase)

    @classmethod
    def _create_first_version(
        cls, passphrase: bytes, params: KdfParams
    ) -> tuple[Self, KekVersionRecord]:
        return cls.create_version(passphrase, version_number=1, params=params)

    @classmethod
    def create_version(
        cls,
        passphrase: bytes,
        *,
        version_number: int,
        params: KdfParams = PARAMETROS_KEK_PRODUCCION,
    ) -> tuple[Self, KekVersionRecord]:
        """Crea una versión de KEK nueva: id y sal nuevos, Argon2id y verificador (spec §1.6).

        Lo usan el primer arranque (versión 1) y la rotación de KEK (versión N+1, H-07). No
        escribe en la BD: devuelve el ``KeyManager`` de la versión nueva y el registro que el
        llamador debe insertar en ``kek_versions``.

        Raises:
            ValueError: passphrase vacía o ``version_number`` menor que 1.
        """
        if not passphrase:
            raise ValueError("la passphrase de KEK no puede estar vacía")
        if version_number < 1:
            raise ValueError("version_number de KEK fuera de rango")
        version_id = uuid.uuid4()
        salt = secrets.token_bytes(SALT_LEN)
        kek = _derive(passphrase, salt, params)
        record = KekVersionRecord(
            id=version_id,
            version_number=version_number,
            source=SOURCE_PASSWORD_KDF,
            kdf_algorithm=KDF_ALGORITHM,
            kdf_params=_params_to_json(params, salt),
            verifier=_make_verifier(kek, version_id),
        )
        return cls(version_id, kek), record

    @classmethod
    def load(cls, record: KekVersionRecord, passphrase: bytes) -> Self:
        """Deriva la KEK de ``record`` con su sal y parámetros guardados y comprueba el
        verificador (spec §1.6; H-06, H-35). Lo usan el arranque y la rotación de KEK (H-07).

        Raises:
            KekPassphraseError: la passphrase no descifra el verificador.
            CryptoError: el registro está malformado o su origen es desconocido.
            NotImplementedError: origen ``external_kms`` (trabajo futuro).
        """
        if record.source == SOURCE_EXTERNAL_KMS:
            raise NotImplementedError("origen external_kms: trabajo futuro (spec §1.6)")
        if record.source != SOURCE_PASSWORD_KDF:
            raise CryptoError("origen de KEK desconocido")
        if record.kdf_algorithm != KDF_ALGORITHM:
            raise CryptoError("algoritmo de KDF de la KEK no soportado")
        params, salt = _params_from_json(record.kdf_params)
        if record.verifier is None:
            raise CryptoError("la versión de KEK no tiene verificador")

        kek = _derive(passphrase, salt, params)
        try:
            _check_verifier(kek, record.id, record.verifier)
        except BaseException:
            secure_zero(kek)
            raise
        return cls(record.id, kek)

    @property
    def active_version_id(self) -> UUID:
        """Id de la versión activa de ``kek_versions``."""
        return self._version_id

    def get_kek(self, kek_version_id: UUID) -> bytearray:
        """KEK activa; ``KeyError`` para otra versión o si ya se llamó ``close``.

        Cada ``KeyManager`` custodia una sola versión: tras una rotación (H-07) todas las DEKs se
        re-envuelven, así que nunca hace falta una KEK histórica. Durante la rotación coexisten dos
        ``KeyManager``: el de la versión vieja y el de la nueva.
        """
        if self._closed or kek_version_id != self._version_id:
            raise KeyError(kek_version_id)
        return self._kek

    def close(self) -> None:
        """Borra la KEK de memoria (Algoritmo 4 del Cap. 6). Llamar al apagar el proceso."""
        secure_zero(self._kek)
        self._closed = True
