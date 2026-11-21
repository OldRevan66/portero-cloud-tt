"""Pruebas del Motor Criptográfico: Algoritmos 1, 2 y 4 del Cap. 6, con AAD (H-05).

El motor depende de la interfaz ``KekProvider`` (spec §1.6), implementada en ``crypto/kek.py``.
Aquí se usa un proveedor falso en memoria con una KEK conocida; así se puede abrir
``wrapped_dek`` a mano y comprobar el formato del bundle y los AAD byte por byte (spec §1.3–1.4).
"""

import dataclasses
import secrets
import uuid
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from portero.crypto.engine import CiphertextBundle, CryptoEngine, SecretContext
from portero.crypto.errors import CryptoAlgorithmError, CryptoError, CryptoIntegrityError
from portero.crypto.memory import secure_zero

# Valor de prueba fácil de buscar dentro de un mensaje de error. No es un secreto real.
PLAINTEXT = b"marcador-de-prueba-valor-de-secreto"


class FakeKekProvider:
    """Doble de prueba de ``KekProvider``: una sola versión de KEK, en memoria."""

    def __init__(self, kek: bytes | None = None, version_id: UUID | None = None) -> None:
        self.kek = bytearray(kek if kek is not None else secrets.token_bytes(32))
        self.version_id = version_id or uuid.uuid4()
        self.llamadas_get_kek = 0

    @property
    def active_version_id(self) -> UUID:
        return self.version_id

    def get_kek(self, kek_version_id: UUID) -> bytearray:
        self.llamadas_get_kek += 1
        if kek_version_id != self.version_id:
            raise KeyError(kek_version_id)
        return self.kek


@pytest.fixture
def proveedor() -> FakeKekProvider:
    return FakeKekProvider()


@pytest.fixture
def motor(proveedor: FakeKekProvider) -> CryptoEngine:
    return CryptoEngine(proveedor)


@pytest.fixture
def ctx() -> SecretContext:
    return SecretContext(secret_id=uuid.uuid4(), version_number=1)


def aad_valor(ctx: SecretContext) -> bytes:
    """AAD del valor según H-05 (spec §1.3), construido aquí de forma independiente."""
    return b"portero:v1|" + ctx.secret_id.bytes + ctx.version_number.to_bytes(4, "big")


def aad_envoltura(ctx: SecretContext, kek_version_id: UUID) -> bytes:
    """AAD de la envoltura según H-05 (spec §1.3)."""
    return (
        b"portero:dek:v1|"
        + ctx.secret_id.bytes
        + ctx.version_number.to_bytes(4, "big")
        + kek_version_id.bytes
    )


def desenvolver_dek(bundle: CiphertextBundle, kek: bytes, ctx: SecretContext) -> bytes:
    """Abre ``wrapped_dek = nonce_w (12) || ct_dek (32) || tag_w (16)`` sin pasar por el motor."""
    nonce_w, ct_y_tag = bundle.wrapped_dek[:12], bundle.wrapped_dek[12:]
    return AESGCM(kek).decrypt(nonce_w, ct_y_tag, aad_envoltura(ctx, bundle.kek_version_id))


def alterar(datos: bytes, posicion: int) -> bytes:
    """Invierte un bit en ``posicion``."""
    copia = bytearray(datos)
    copia[posicion] ^= 0x01
    return bytes(copia)


# --- Ida y vuelta y formato -------------------------------------------------------------------


def test_ida_y_vuelta(motor: CryptoEngine, ctx: SecretContext) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    resultado = motor.decrypt_secret(bundle, ctx=ctx)

    assert isinstance(resultado, bytearray)
    assert resultado == PLAINTEXT


def test_ida_y_vuelta_plaintext_vacio(motor: CryptoEngine, ctx: SecretContext) -> None:
    bundle = motor.encrypt_secret(bytearray(), ctx=ctx)

    assert motor.decrypt_secret(bundle, ctx=ctx) == bytearray()


def test_formato_del_bundle(
    motor: CryptoEngine, proveedor: FakeKekProvider, ctx: SecretContext
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    assert len(bundle.nonce) == 12
    assert len(bundle.auth_tag) == 16
    assert len(bundle.ciphertext) == len(PLAINTEXT)  # GCM no agrega relleno; el tag va aparte
    assert len(bundle.wrapped_dek) == 60  # 12 + 32 + 16
    assert bundle.aead_algorithm == "aes-256-gcm"
    assert bundle.wrap_algorithm == "aes-256-gcm"
    assert bundle.kek_version_id == proveedor.active_version_id


def test_bundle_es_inmutable(motor: CryptoEngine, ctx: SecretContext) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    with pytest.raises(dataclasses.FrozenInstanceError):
        bundle.nonce = b"\x00" * 12  # type: ignore[misc]


def test_aad_coinciden_con_la_spec(
    motor: CryptoEngine, proveedor: FakeKekProvider, ctx: SecretContext
) -> None:
    """Descifrar a mano con los AAD de H-05 demuestra que el motor los construye igual."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    dek = desenvolver_dek(bundle, bytes(proveedor.kek), ctx)
    claro = AESGCM(dek).decrypt(bundle.nonce, bundle.ciphertext + bundle.auth_tag, aad_valor(ctx))

    assert len(dek) == 32
    assert claro == PLAINTEXT


# --- Aleatoriedad: nonce y DEK nuevos en cada cifrado ----------------------------------------


def test_mismo_plaintext_produce_ciphertext_distinto(
    motor: CryptoEngine, ctx: SecretContext
) -> None:
    b1 = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    b2 = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    assert b1.ciphertext != b2.ciphertext
    assert b1.nonce != b2.nonce
    assert b1.wrapped_dek != b2.wrapped_dek


def test_una_dek_distinta_por_cifrado(
    motor: CryptoEngine, proveedor: FakeKekProvider, ctx: SecretContext
) -> None:
    deks = {
        desenvolver_dek(motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx), proveedor.kek, ctx)
        for _ in range(5)
    }

    assert len(deks) == 5


# --- Integridad: cualquier alteración → CryptoIntegrityError ---------------------------------


@pytest.mark.parametrize(
    ("campo", "posicion"),
    [
        pytest.param("ciphertext", 0, id="ciphertext"),
        pytest.param("auth_tag", 15, id="tag"),
        pytest.param("nonce", 0, id="nonce"),
        pytest.param("wrapped_dek", 0, id="wrapped_dek-nonce_w"),
        pytest.param("wrapped_dek", 20, id="wrapped_dek-ct_dek"),
        pytest.param("wrapped_dek", 59, id="wrapped_dek-tag_w"),
    ],
)
def test_bundle_alterado_falla(
    motor: CryptoEngine, ctx: SecretContext, campo: str, posicion: int
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    alterado = dataclasses.replace(bundle, **{campo: alterar(getattr(bundle, campo), posicion)})

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(alterado, ctx=ctx)


def test_bundle_de_otro_secreto_falla(motor: CryptoEngine, ctx: SecretContext) -> None:
    """H-05: copiar la fila de ``secret_versions`` de un secreto a otro no debe descifrar."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    otro = SecretContext(secret_id=uuid.uuid4(), version_number=ctx.version_number)

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(bundle, ctx=otro)


def test_bundle_de_otra_version_falla(motor: CryptoEngine, ctx: SecretContext) -> None:
    """H-05: presentar la versión 1 como si fuera la versión 2 no debe descifrar."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    otra = SecretContext(secret_id=ctx.secret_id, version_number=ctx.version_number + 1)

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(bundle, ctx=otra)


def test_intercambio_de_filas_entre_secretos_falla(motor: CryptoEngine) -> None:
    """H-05, escenario STRIDE completo: dos secretos válidos con sus bundles intercambiados."""
    ctx_a = SecretContext(secret_id=uuid.uuid4(), version_number=1)
    ctx_b = SecretContext(secret_id=uuid.uuid4(), version_number=1)
    bundle_a = motor.encrypt_secret(bytearray(b"valor-a"), ctx=ctx_a)
    bundle_b = motor.encrypt_secret(bytearray(b"valor-b"), ctx=ctx_b)

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(bundle_b, ctx=ctx_a)
    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(bundle_a, ctx=ctx_b)


def test_kek_equivocada_falla(ctx: SecretContext) -> None:
    """Mismo ``kek_version_id`` pero otra KEK (p. ej. passphrase distinta): la envoltura no abre."""
    version_id = uuid.uuid4()
    bundle = CryptoEngine(FakeKekProvider(version_id=version_id)).encrypt_secret(
        bytearray(PLAINTEXT), ctx=ctx
    )
    motor_otra_kek = CryptoEngine(FakeKekProvider(version_id=version_id))

    with pytest.raises(CryptoIntegrityError):
        motor_otra_kek.decrypt_secret(bundle, ctx=ctx)


def test_version_de_kek_desconocida_falla(motor: CryptoEngine, ctx: SecretContext) -> None:
    """El resolvedor no conoce el ``kek_version_id``: error del motor, no un ``KeyError`` suelto."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    with pytest.raises(CryptoError):
        motor.decrypt_secret(dataclasses.replace(bundle, kek_version_id=uuid.uuid4()), ctx=ctx)


@pytest.mark.parametrize(
    ("campo", "longitud"),
    [
        pytest.param("nonce", 11, id="nonce-corto"),
        pytest.param("nonce", 13, id="nonce-largo"),
        pytest.param("auth_tag", 15, id="tag-corto"),
        pytest.param("wrapped_dek", 59, id="wrapped_dek-corto"),
        pytest.param("wrapped_dek", 61, id="wrapped_dek-largo"),
    ],
)
def test_bundle_con_longitud_invalida_falla(
    motor: CryptoEngine, ctx: SecretContext, campo: str, longitud: int
) -> None:
    """Una fila malformada en la BD se trata como alteración, no como ``ValueError`` interno."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    valor = (getattr(bundle, campo) + b"\x00")[:longitud]

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(dataclasses.replace(bundle, **{campo: valor}), ctx=ctx)


@pytest.mark.parametrize("version_number", [0, -1, 2**32])
def test_secret_context_rechaza_version_fuera_de_rango(version_number: int) -> None:
    """``version_number`` empieza en 1 (Algoritmo 3) y debe caber en los 4 bytes del AAD."""
    with pytest.raises(ValueError):
        SecretContext(secret_id=uuid.uuid4(), version_number=version_number)


# --- Lista blanca de algoritmos (RNF-021) -----------------------------------------------------


@pytest.mark.parametrize("campo", ["aead_algorithm", "wrap_algorithm"])
@pytest.mark.parametrize("valor", ["chacha20-poly1305", "AES-256-GCM", "aes-128-gcm", ""])
def test_algoritmo_no_soportado_se_rechaza(
    motor: CryptoEngine, proveedor: FakeKekProvider, ctx: SecretContext, campo: str, valor: str
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    llamadas_antes = proveedor.llamadas_get_kek

    with pytest.raises(CryptoAlgorithmError):
        motor.decrypt_secret(dataclasses.replace(bundle, **{campo: valor}), ctx=ctx)

    # Algoritmo 2: se valida el algoritmo antes de resolver la KEK.
    assert proveedor.llamadas_get_kek == llamadas_antes


def test_jerarquia_de_excepciones() -> None:
    assert issubclass(CryptoIntegrityError, CryptoError)
    assert issubclass(CryptoAlgorithmError, CryptoError)


# --- Sin datos sensibles en los errores (spec §1.3; ASVS V7.4.1) ------------------------------


def test_mensaje_de_error_no_contiene_plaintext(motor: CryptoEngine, ctx: SecretContext) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    alterado = dataclasses.replace(bundle, auth_tag=alterar(bundle.auth_tag, 0))

    with pytest.raises(CryptoIntegrityError) as info:
        motor.decrypt_secret(alterado, ctx=ctx)

    texto = str(info.value) + repr(info.value) + repr(info.value.args)
    assert PLAINTEXT.decode() not in texto
    assert PLAINTEXT.hex() not in texto


def test_mensaje_de_error_no_contiene_kek(
    proveedor: FakeKekProvider, motor: CryptoEngine, ctx: SecretContext
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    alterado = dataclasses.replace(bundle, wrapped_dek=alterar(bundle.wrapped_dek, 30))

    with pytest.raises(CryptoIntegrityError) as info:
        motor.decrypt_secret(alterado, ctx=ctx)

    texto = str(info.value) + repr(info.value) + repr(info.value.args)
    assert proveedor.kek.hex() not in texto
    assert repr(bytes(proveedor.kek)) not in texto


# --- SecureZero (Algoritmo 4) -----------------------------------------------------------------


def test_secure_zero_deja_el_bytearray_en_ceros() -> None:
    buf = bytearray(b"\xaa" * 32)
    direccion_antes = id(buf)

    secure_zero(buf)

    assert buf == bytearray(32)
    assert len(buf) == 32
    assert id(buf) == direccion_antes  # se borra en sitio, no se reemplaza el objeto


def test_secure_zero_con_bytearray_vacio() -> None:
    buf = bytearray()

    secure_zero(buf)

    assert buf == bytearray()


# --- Re-envoltura de la DEK al rotar la KEK (H-07, H-05) ---------------------------------------


class ProveedorPermisivo(FakeKekProvider):
    """Entrega su KEK para **cualquier** ``kek_version_id``. Sirve para aislar el AAD: si la
    re-envoltura no ligara el id de la KEK nueva, cambiar ``kek_version_id`` no se detectaría."""

    def get_kek(self, kek_version_id: UUID) -> bytearray:
        self.llamadas_get_kek += 1
        return self.kek


def test_rewrap_conserva_el_valor_y_cambia_solo_la_envoltura(
    motor: CryptoEngine, proveedor: FakeKekProvider, ctx: SecretContext
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    nuevo = FakeKekProvider()

    reenvuelto = motor.rewrap_dek(bundle, ctx=ctx, target=nuevo)

    # El valor no se toca: mismo ciphertext, nonce y tag (spec §1.6, H-07).
    assert reenvuelto.ciphertext == bundle.ciphertext
    assert reenvuelto.nonce == bundle.nonce
    assert reenvuelto.auth_tag == bundle.auth_tag
    assert reenvuelto.aead_algorithm == bundle.aead_algorithm
    # La envoltura sí: otra KEK, otro nonce_w, misma DEK.
    assert reenvuelto.kek_version_id == nuevo.version_id
    assert reenvuelto.wrapped_dek != bundle.wrapped_dek
    assert len(reenvuelto.wrapped_dek) == 60
    assert reenvuelto.wrapped_dek[:12] != bundle.wrapped_dek[:12]
    assert desenvolver_dek(reenvuelto, bytes(nuevo.kek), ctx) == desenvolver_dek(
        bundle, bytes(proveedor.kek), ctx
    )
    assert CryptoEngine(nuevo).decrypt_secret(reenvuelto, ctx=ctx) == bytearray(PLAINTEXT)


def test_rewrap_la_kek_vieja_ya_no_abre_el_bundle(motor: CryptoEngine, ctx: SecretContext) -> None:
    reenvuelto = motor.rewrap_dek(
        motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx), ctx=ctx, target=FakeKekProvider()
    )

    with pytest.raises(CryptoError):
        motor.decrypt_secret(reenvuelto, ctx=ctx)


def test_rewrap_liga_el_aad_al_id_de_la_kek_nueva(motor: CryptoEngine, ctx: SecretContext) -> None:
    """AAD de la envoltura = ... || kek_version_id **nuevo** (H-05): con la KEK correcta pero
    otro id en la fila, la envoltura no autentica."""
    nuevo = ProveedorPermisivo()
    reenvuelto = motor.rewrap_dek(
        motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx), ctx=ctx, target=nuevo
    )
    nonce_w, resto = reenvuelto.wrapped_dek[:12], reenvuelto.wrapped_dek[12:]
    AESGCM(bytes(nuevo.kek)).decrypt(nonce_w, resto, aad_envoltura(ctx, nuevo.version_id))

    with pytest.raises(CryptoIntegrityError):
        CryptoEngine(nuevo).decrypt_secret(
            dataclasses.replace(reenvuelto, kek_version_id=uuid.uuid4()), ctx=ctx
        )


def test_rewrap_con_contexto_equivocado_falla(motor: CryptoEngine, ctx: SecretContext) -> None:
    """La envoltura vieja está ligada a su secreto y versión: no se re-envuelve con otro ctx."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    otro = SecretContext(secret_id=uuid.uuid4(), version_number=1)

    with pytest.raises(CryptoIntegrityError):
        motor.rewrap_dek(bundle, ctx=otro, target=FakeKekProvider())


def test_rewrap_con_kek_vieja_no_disponible_falla(motor: CryptoEngine, ctx: SecretContext) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    with pytest.raises(CryptoError):
        motor.rewrap_dek(
            dataclasses.replace(bundle, kek_version_id=uuid.uuid4()),
            ctx=ctx,
            target=FakeKekProvider(),
        )


@pytest.mark.parametrize("campo", ["aead_algorithm", "wrap_algorithm"])
def test_rewrap_algoritmo_no_soportado_se_rechaza(
    motor: CryptoEngine, ctx: SecretContext, campo: str
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    with pytest.raises(CryptoAlgorithmError):
        motor.rewrap_dek(
            dataclasses.replace(bundle, **{campo: "chacha20-poly1305"}),
            ctx=ctx,
            target=FakeKekProvider(),
        )


def test_rewrap_wrapped_dek_con_longitud_invalida_falla(
    motor: CryptoEngine, ctx: SecretContext
) -> None:
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    with pytest.raises(CryptoIntegrityError):
        motor.rewrap_dek(
            dataclasses.replace(bundle, wrapped_dek=bundle.wrapped_dek[:59]),
            ctx=ctx,
            target=FakeKekProvider(),
        )


def test_rewrap_borra_la_dek(
    motor: CryptoEngine, ctx: SecretContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Algoritmo 4: la DEK en claro se sobrescribe con ceros al terminar la re-envoltura."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    borrados: list[bytearray] = []

    def espia(buf: bytearray) -> None:
        borrados.append(buf)
        secure_zero(buf)

    monkeypatch.setattr("portero.crypto.engine.secure_zero", espia)

    motor.rewrap_dek(bundle, ctx=ctx, target=FakeKekProvider())

    assert [len(b) for b in borrados] == [32]
    assert borrados[0] == bytearray(32)


# --- H-16: descifrar en búferes borrables con decrypt_into ------------------------------------
#
# ``AESGCM.decrypt`` devuelve ``bytes`` inmutables que ``secure_zero`` no puede borrar. Con
# ``decrypt_into`` (cryptography >= 47.0.0) el motor descifra en ``bytearray`` preasignados.
# Con cryptography 50.0.2 se comprobó que, si la etiqueta falla, el búfer ya contiene el
# resultado sin autenticar; por eso el motor lo borra también tras ``InvalidTag``.


class AESGCMEspia:
    """Envoltorio de ``AESGCM`` que guarda cada búfer que el motor pasa a ``decrypt_into``.

    La clase de ``cryptography`` está escrita en Rust y no se le pueden cambiar métodos; por eso
    se sustituye el nombre ``AESGCM`` dentro de ``portero.crypto.engine``.
    No ofrece ``decrypt``: si el motor volviera a usarlo (``bytes`` no borrables), la prueba falla.
    """

    bufers: list[bytearray] = []

    def __init__(self, key: bytes | bytearray) -> None:
        self._aesgcm = AESGCM(key)

    def encrypt(self, nonce: bytes, data: bytes | bytearray, aad: bytes) -> bytes:
        return self._aesgcm.encrypt(nonce, data, aad)

    def decrypt_into(self, nonce: bytes, data: bytes, aad: bytes, buf: bytearray) -> int:
        AESGCMEspia.bufers.append(buf)
        return self._aesgcm.decrypt_into(nonce, data, aad, buf)


@pytest.fixture
def bufers(monkeypatch: pytest.MonkeyPatch) -> list[bytearray]:
    """Instala el espía y devuelve la lista de búferes que el motor pasó a ``decrypt_into``."""
    registro: list[bytearray] = []
    monkeypatch.setattr(AESGCMEspia, "bufers", registro)
    monkeypatch.setattr("portero.crypto.engine.AESGCM", AESGCMEspia)
    return registro


def test_descifrar_usa_decrypt_into_y_borra_la_dek(
    motor: CryptoEngine, ctx: SecretContext, bufers: list[bytearray]
) -> None:
    """H-16: DEK y plaintext se descifran en ``bytearray`` del motor; la DEK queda en ceros."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)

    plaintext = motor.decrypt_secret(bundle, ctx=ctx)

    assert [len(b) for b in bufers] == [32, len(PLAINTEXT)]
    assert all(type(b) is bytearray for b in bufers)
    assert bufers[0] == bytearray(32)
    assert bufers[1] is plaintext  # se entrega el mismo búfer, sin copias intermedias
    assert plaintext == PLAINTEXT


def test_descifrar_con_tag_invalido_borra_dek_y_plaintext(
    motor: CryptoEngine, ctx: SecretContext, bufers: list[bytearray]
) -> None:
    """H-16: tras ``InvalidTag`` en el valor se borran la DEK y el búfer no autenticado."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    alterado = dataclasses.replace(bundle, ciphertext=alterar(bundle.ciphertext, 0))

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(alterado, ctx=ctx)

    assert [len(b) for b in bufers] == [32, len(PLAINTEXT)]
    assert bufers[0] == bytearray(32)
    assert bufers[1] == bytearray(len(PLAINTEXT))


def test_descifrar_con_envoltura_invalida_borra_la_dek(
    motor: CryptoEngine, ctx: SecretContext, bufers: list[bytearray]
) -> None:
    """H-16: si la envoltura no autentica, la DEK se borra y el valor ni se intenta descifrar."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    otro_ctx = SecretContext(secret_id=uuid.uuid4(), version_number=1)

    with pytest.raises(CryptoIntegrityError):
        motor.decrypt_secret(bundle, ctx=otro_ctx)

    assert bufers == [bytearray(32)]


def test_rewrap_usa_decrypt_into_y_borra_la_dek(
    motor: CryptoEngine, ctx: SecretContext, bufers: list[bytearray]
) -> None:
    """H-16: la re-envoltura desenvuelve la DEK en un ``bytearray`` que queda en ceros."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    destino = FakeKekProvider()

    nuevo = motor.rewrap_dek(bundle, ctx=ctx, target=destino)

    assert bufers == [bytearray(32)]
    assert type(bufers[0]) is bytearray
    assert CryptoEngine(destino).decrypt_secret(nuevo, ctx=ctx) == PLAINTEXT


def test_rewrap_con_envoltura_invalida_borra_la_dek(
    motor: CryptoEngine, ctx: SecretContext, bufers: list[bytearray]
) -> None:
    """H-16: tras ``InvalidTag`` al desenvolver, el búfer de la DEK queda en ceros."""
    bundle = motor.encrypt_secret(bytearray(PLAINTEXT), ctx=ctx)
    otro_ctx = SecretContext(secret_id=uuid.uuid4(), version_number=1)

    with pytest.raises(CryptoIntegrityError):
        motor.rewrap_dek(bundle, ctx=otro_ctx, target=FakeKekProvider())

    assert bufers == [bytearray(32)]
