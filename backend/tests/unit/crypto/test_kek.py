"""Pruebas de ``KeyManager``: derivación de la KEK con Argon2id y verificador de passphrase (H-06).

Se usa un almacén falso en memoria en lugar de la tabla ``kek_versions``: así se prueba la lógica
del Motor Criptográfico sin base de datos (spec §1.6). La prueba contra PostgreSQL vive en
``tests/integration/``. Todas usan la fixture ``parametros_argon2_solo_pruebas`` (parámetros
reducidos) salvo la que fija los valores de producción.
"""

import base64
import dataclasses
import uuid

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from portero.crypto.engine import CryptoEngine, SecretContext
from portero.crypto.errors import CryptoError, KekPassphraseError
from portero.crypto.kek import (
    KDF_ALGORITHM,
    PARAMETROS_KEK_PRODUCCION,
    SOURCE_EXTERNAL_KMS,
    SOURCE_PASSWORD_KDF,
    KdfParams,
    KekVersionRecord,
    KeyManager,
)

# Passphrases de prueba fáciles de buscar en mensajes de error. No son secretos reales.
PASSPHRASE = b"marcador-de-prueba-passphrase-kek"
OTRA_PASSPHRASE = b"marcador-de-prueba-passphrase-equivocada"


class FakeKekStore:
    """Doble de prueba de ``KekVersionStore``: guarda las versiones en una lista."""

    def __init__(self) -> None:
        self.registros: list[KekVersionRecord] = []

    async def get_active(self) -> KekVersionRecord | None:
        return self.registros[-1] if self.registros else None

    async def add(self, record: KekVersionRecord) -> None:
        self.registros.append(record)


@pytest.fixture
def almacen() -> FakeKekStore:
    return FakeKekStore()


async def arrancar(
    almacen: FakeKekStore, params: KdfParams, passphrase: bytes = PASSPHRASE
) -> KeyManager:
    return await KeyManager.bootstrap(almacen, passphrase, new_params=params)


def test_parametros_de_produccion_son_los_del_cap6() -> None:
    # Cap. 6, tabla "Resumen de algoritmos": m=131072 KiB, t=4, p=1, salida 32 B (spec §1.2).
    assert PARAMETROS_KEK_PRODUCCION == KdfParams(
        memory_cost_kib=131072, time_cost=4, parallelism=1, hash_len=32
    )


def test_bootstrap_usa_parametros_de_produccion_por_omision() -> None:
    import inspect

    firma = inspect.signature(KeyManager.bootstrap)
    assert firma.parameters["new_params"].default is PARAMETROS_KEK_PRODUCCION


async def test_primer_arranque_crea_la_version_1(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)

    assert len(almacen.registros) == 1
    reg = almacen.registros[0]
    assert reg.id == km.active_version_id
    assert reg.version_number == 1
    assert reg.source == SOURCE_PASSWORD_KDF
    assert reg.kdf_algorithm == KDF_ALGORITHM == "argon2id"
    assert reg.kdf_params is not None
    assert reg.kdf_params["memory_cost_kib"] == parametros_argon2_solo_pruebas.memory_cost_kib
    assert reg.kdf_params["time_cost"] == parametros_argon2_solo_pruebas.time_cost
    assert reg.kdf_params["parallelism"] == parametros_argon2_solo_pruebas.parallelism
    assert reg.kdf_params["hash_len"] == 32
    assert len(base64.b64decode(str(reg.kdf_params["salt_b64"]))) == 16
    # nonce (12) || "portero-kek-check" cifrado (17) || tag (16)
    assert reg.verifier is not None
    assert len(reg.verifier) == 12 + 17 + 16


async def test_kek_es_argon2id_de_la_passphrase_con_la_sal_guardada(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    assert reg.kdf_params is not None
    p = parametros_argon2_solo_pruebas

    esperada = hash_secret_raw(
        secret=PASSPHRASE,
        salt=base64.b64decode(str(reg.kdf_params["salt_b64"])),
        time_cost=p.time_cost,
        memory_cost=p.memory_cost_kib,
        parallelism=p.parallelism,
        hash_len=32,
        type=Type.ID,
    )
    kek = km.get_kek(km.active_version_id)
    assert isinstance(kek, bytearray)
    assert bytes(kek) == esperada


async def test_verificador_cifra_la_constante_con_aad_del_id(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    assert reg.verifier is not None

    kek = bytes(km.get_kek(reg.id))
    claro = AESGCM(kek).decrypt(reg.verifier[:12], reg.verifier[12:], reg.id.bytes)
    assert claro == b"portero-kek-check"


async def test_segundo_arranque_con_la_misma_passphrase_recupera_la_misma_kek(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km1 = await arrancar(almacen, parametros_argon2_solo_pruebas)
    km2 = await arrancar(almacen, parametros_argon2_solo_pruebas)

    assert len(almacen.registros) == 1  # no se crea otra versión
    assert km2.active_version_id == km1.active_version_id
    assert km2.get_kek(km2.active_version_id) == km1.get_kek(km1.active_version_id)


async def test_passphrase_incorrecta_aborta_sin_filtrar_datos(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await arrancar(almacen, parametros_argon2_solo_pruebas)

    with pytest.raises(KekPassphraseError) as exc:
        await arrancar(almacen, parametros_argon2_solo_pruebas, OTRA_PASSPHRASE)

    assert str(exc.value) == "passphrase de KEK incorrecta"
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__
    assert isinstance(exc.value, CryptoError)
    assert len(almacen.registros) == 1


async def test_verificador_alterado_aborta(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    assert reg.verifier is not None
    alterado = bytearray(reg.verifier)
    alterado[-1] ^= 0x01
    almacen.registros[0] = dataclasses.replace(reg, verifier=bytes(alterado))

    with pytest.raises(KekPassphraseError):
        await arrancar(almacen, parametros_argon2_solo_pruebas)


async def test_verificador_truncado_aborta(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await arrancar(almacen, parametros_argon2_solo_pruebas)
    almacen.registros[0] = dataclasses.replace(almacen.registros[0], verifier=b"\x00" * 5)

    with pytest.raises(KekPassphraseError):
        await arrancar(almacen, parametros_argon2_solo_pruebas)


async def test_al_recargar_usa_los_parametros_guardados_no_los_nuevos(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km1 = await arrancar(almacen, parametros_argon2_solo_pruebas)
    otros = KdfParams(memory_cost_kib=2048, time_cost=2, parallelism=1)

    km2 = await arrancar(almacen, otros)

    assert km2.get_kek(km2.active_version_id) == km1.get_kek(km1.active_version_id)


async def test_cada_instalacion_tiene_sal_y_kek_distintas(
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    a, b = FakeKekStore(), FakeKekStore()
    km_a = await arrancar(a, parametros_argon2_solo_pruebas)
    km_b = await arrancar(b, parametros_argon2_solo_pruebas)

    assert a.registros[0].kdf_params != b.registros[0].kdf_params
    assert km_a.get_kek(km_a.active_version_id) != km_b.get_kek(km_b.active_version_id)


async def test_get_kek_de_otra_version_lanza_keyerror(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)

    with pytest.raises(KeyError):
        km.get_kek(uuid.uuid4())


async def test_close_borra_la_kek(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)
    kek = km.get_kek(km.active_version_id)

    km.close()

    assert kek == bytearray(32)
    with pytest.raises(KeyError):
        km.get_kek(km.active_version_id)


async def test_ida_y_vuelta_con_el_motor(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)
    motor = CryptoEngine(km)
    ctx = SecretContext(secret_id=uuid.uuid4(), version_number=1)

    bundle = motor.encrypt_secret(bytearray(b"marcador-de-prueba-valor"), ctx=ctx)

    assert bundle.kek_version_id == km.active_version_id
    assert motor.decrypt_secret(bundle, ctx=ctx) == bytearray(b"marcador-de-prueba-valor")


async def test_passphrase_vacia_se_rechaza(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    with pytest.raises(ValueError, match="vacía"):
        await arrancar(almacen, parametros_argon2_solo_pruebas, b"")
    assert almacen.registros == []


async def test_origen_external_kms_no_implementado(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    almacen.registros.append(
        KekVersionRecord(
            id=uuid.uuid4(),
            version_number=1,
            source=SOURCE_EXTERNAL_KMS,
            kdf_algorithm=None,
            kdf_params=None,
            verifier=None,
        )
    )

    with pytest.raises(NotImplementedError):
        await arrancar(almacen, parametros_argon2_solo_pruebas)


@pytest.mark.parametrize(
    "cambio",
    [
        {"kdf_algorithm": "pbkdf2"},
        {"kdf_params": None},
        {"kdf_params": {"time_cost": 1}},
        {
            "kdf_params": {
                "memory_cost_kib": "1024",
                "time_cost": 1,
                "parallelism": 1,
                "hash_len": 32,
                "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
            }
        },
        {
            "kdf_params": {
                "memory_cost_kib": 1024,
                "time_cost": 1,
                "parallelism": 1,
                "hash_len": 32,
                "salt_b64": "no-es-base64!",
            }
        },
        {
            "kdf_params": {
                "memory_cost_kib": 1024,
                "time_cost": 1,
                "parallelism": 1,
                "hash_len": 16,
                "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
            }
        },
        {"verifier": None},
        {"source": "desconocido"},
    ],
    ids=[
        "algoritmo-no-soportado",
        "sin-parametros",
        "parametros-incompletos",
        "tipo-invalido",
        "sal-invalida",
        "salida-no-de-32",
        "sin-verificador",
        "origen-desconocido",
    ],
)
async def test_registro_invalido_se_rechaza(
    almacen: FakeKekStore,
    parametros_argon2_solo_pruebas: KdfParams,
    cambio: dict[str, object],
) -> None:
    await arrancar(almacen, parametros_argon2_solo_pruebas)
    almacen.registros[0] = dataclasses.replace(almacen.registros[0], **cambio)  # type: ignore[arg-type]

    with pytest.raises(CryptoError) as exc:
        await arrancar(almacen, parametros_argon2_solo_pruebas)
    assert PASSPHRASE.decode() not in str(exc.value)


async def test_verificador_con_otra_constante_aborta(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    # Autentica con la KEK correcta, pero no contiene "portero-kek-check".
    km = await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    nonce = b"\x00" * 12
    falso = nonce + AESGCM(bytes(km.get_kek(reg.id))).encrypt(
        nonce, b"otra-constante", reg.id.bytes
    )
    almacen.registros[0] = dataclasses.replace(reg, verifier=falso)

    with pytest.raises(KekPassphraseError):
        await arrancar(almacen, parametros_argon2_solo_pruebas)


async def test_sal_que_no_es_cadena_se_rechaza(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    assert reg.kdf_params is not None
    almacen.registros[0] = dataclasses.replace(reg, kdf_params={**reg.kdf_params, "salt_b64": 7})

    with pytest.raises(CryptoError):
        await arrancar(almacen, parametros_argon2_solo_pruebas)


async def test_si_falla_la_insercion_se_borra_la_kek(
    parametros_argon2_solo_pruebas: KdfParams, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AlmacenQueFalla(FakeKekStore):
        async def add(self, record: KekVersionRecord) -> None:
            raise RuntimeError("fallo simulado de la base de datos")

    creadas: list[KeyManager] = []
    original = KeyManager._create_first_version.__func__  # type: ignore[attr-defined]

    def espia(cls: type[KeyManager], passphrase: bytes, params: KdfParams):  # type: ignore[no-untyped-def]
        manager, record = original(cls, passphrase, params)
        creadas.append(manager)
        return manager, record

    monkeypatch.setattr(KeyManager, "_create_first_version", classmethod(espia))

    with pytest.raises(RuntimeError):
        await arrancar(AlmacenQueFalla(), parametros_argon2_solo_pruebas)

    assert len(creadas) == 1
    assert creadas[0]._kek == bytearray(32)


# --- Rangos de los parámetros de Argon2id (H-35) ------------------------------------------------

_SAL_CEROS = "AAAAAAAAAAAAAAAAAAAAAA=="

RANGOS_INVALIDOS = [
    {"memory_cost_kib": 2**31, "time_cost": 1, "parallelism": 1},  # agotaría la memoria
    {"memory_cost_kib": 1048577, "time_cost": 1, "parallelism": 1},  # 1 GiB + 1 KiB
    {"memory_cost_kib": 1024, "time_cost": 10**6, "parallelism": 1},  # arranque interminable
    {"memory_cost_kib": 1024, "time_cost": 17, "parallelism": 1},
    {"memory_cost_kib": 1024, "time_cost": 1, "parallelism": 17},
    {"memory_cost_kib": 1024, "time_cost": 0, "parallelism": 1},  # mínimo de RFC 9106 §3.1
    {"memory_cost_kib": 1024, "time_cost": 1, "parallelism": 0},
    {"memory_cost_kib": 7, "time_cost": 1, "parallelism": 1},  # m < 8·p
    {"memory_cost_kib": -1, "time_cost": 1, "parallelism": 1},
]
IDS_RANGOS = [
    "memoria-2^31",
    "memoria-sobre-techo",
    "tiempo-enorme",
    "tiempo-sobre-techo",
    "paralelismo-sobre-techo",
    "tiempo-cero",
    "paralelismo-cero",
    "memoria-bajo-8p",
    "memoria-negativa",
]


def _derivacion_prohibida(*_: object) -> bytearray:
    raise AssertionError("no debe derivarse con parámetros fuera de rango")


@pytest.mark.parametrize("rango", RANGOS_INVALIDOS, ids=IDS_RANGOS)
async def test_parametros_fuera_de_rango_en_la_bd_se_rechazan_sin_derivar(
    almacen: FakeKekStore,
    parametros_argon2_solo_pruebas: KdfParams,
    rango: dict[str, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-35: una fila de ``kek_versions`` alterada con parámetros absurdos detiene el arranque
    con ``CryptoError`` **antes** de llamar a Argon2id (si no, agotaría memoria o tiempo)."""
    await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg = almacen.registros[0]
    almacen.registros[0] = dataclasses.replace(
        reg, kdf_params={**rango, "hash_len": 32, "salt_b64": _SAL_CEROS}
    )
    monkeypatch.setattr("portero.crypto.kek._derive", _derivacion_prohibida)

    with pytest.raises(CryptoError) as exc:
        await arrancar(almacen, parametros_argon2_solo_pruebas)
    assert PASSPHRASE.decode() not in str(exc.value)


@pytest.mark.parametrize("rango", RANGOS_INVALIDOS, ids=IDS_RANGOS)
def test_kdf_params_fuera_de_rango_no_se_construyen(rango: dict[str, int]) -> None:
    """La validación vive en ``KdfParams``: cubre también los parámetros de la versión nueva."""
    with pytest.raises(ValueError, match="fuera de rango"):
        KdfParams(**rango)


@pytest.mark.parametrize(
    "rango",
    [
        {"memory_cost_kib": 1048576, "time_cost": 16, "parallelism": 16},  # techos exactos
        {"memory_cost_kib": 8, "time_cost": 1, "parallelism": 1},  # mínimos exactos
        {"memory_cost_kib": 131072, "time_cost": 4, "parallelism": 1},  # producción
    ],
    ids=["techos", "minimos", "produccion"],
)
def test_kdf_params_en_rango_se_aceptan(rango: dict[str, int]) -> None:
    KdfParams(**rango)


# --- Versión N+1 para la rotación de KEK (H-07) -------------------------------------------------


async def test_create_version_crea_la_version_siguiente_con_sal_y_kek_nuevas(
    almacen: FakeKekStore, parametros_argon2_solo_pruebas: KdfParams
) -> None:
    km1 = await arrancar(almacen, parametros_argon2_solo_pruebas)
    reg1 = almacen.registros[0]

    km2, reg2 = KeyManager.create_version(
        OTRA_PASSPHRASE, version_number=2, params=parametros_argon2_solo_pruebas
    )

    assert reg2.version_number == 2
    assert reg2.id == km2.active_version_id != km1.active_version_id
    assert reg2.source == SOURCE_PASSWORD_KDF
    assert reg2.kdf_algorithm == KDF_ALGORITHM
    assert reg1.kdf_params is not None and reg2.kdf_params is not None
    assert reg2.kdf_params["salt_b64"] != reg1.kdf_params["salt_b64"]
    assert km2.get_kek(reg2.id) != km1.get_kek(reg1.id)
    # El verificador (H-06) de la versión nueva abre con la passphrase nueva y no con la vieja.
    assert KeyManager.load(reg2, OTRA_PASSPHRASE).get_kek(reg2.id) == km2.get_kek(reg2.id)
    with pytest.raises(KekPassphraseError):
        KeyManager.load(reg2, PASSPHRASE)


def test_create_version_rechaza_passphrase_vacia(parametros_argon2_solo_pruebas: KdfParams) -> None:
    with pytest.raises(ValueError, match="vacía"):
        KeyManager.create_version(b"", version_number=2, params=parametros_argon2_solo_pruebas)


@pytest.mark.parametrize("version_number", [0, -1])
def test_create_version_rechaza_numero_de_version_invalido(
    parametros_argon2_solo_pruebas: KdfParams, version_number: int
) -> None:
    with pytest.raises(ValueError, match="version_number"):
        KeyManager.create_version(
            PASSPHRASE, version_number=version_number, params=parametros_argon2_solo_pruebas
        )


def test_create_version_usa_parametros_de_produccion_por_omision() -> None:
    import inspect

    firma = inspect.signature(KeyManager.create_version)
    assert firma.parameters["params"].default is PARAMETROS_KEK_PRODUCCION
