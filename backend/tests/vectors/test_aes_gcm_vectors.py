"""Vectores oficiales de AES-256-GCM: casos 13 a 16 de McGrew y Viega, "The Galois/Counter Mode
of Operation (GCM)", Apéndice B (incluidos también en los vectores CAVP del NIST). Hallazgo H-02.

Se usa ``AESGCM`` directamente para demostrar dos cosas: que la biblioteca produce los valores
oficiales y que nuestra codificación del bundle (``ct || tag`` separado en los últimos 16 bytes,
spec §1.4) coincide con la separación ciphertext/etiqueta de la especificación.
"""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAG_LEN = 16

_K_CERO = "00" * 32
_IV_CERO = "00" * 12
_K_FEFF = "feffe9928665731c6d6a8f9467308308" * 2
_IV_CAFE = "cafebabefacedbaddecaf888"
_P_LARGO = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
_C_LARGO = (
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
)

# (K, IV, P, A, C, T) en hexadecimal.
VECTORES = [
    pytest.param(_K_CERO, _IV_CERO, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b", id="caso-13"),
    pytest.param(
        _K_CERO,
        _IV_CERO,
        "00" * 16,
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
        id="caso-14",
    ),
    pytest.param(
        _K_FEFF, _IV_CAFE, _P_LARGO, "", _C_LARGO, "b094dac5d93471bdec1a502270e3cc6c", id="caso-15"
    ),
    pytest.param(
        _K_FEFF,
        _IV_CAFE,
        _P_LARGO[:120],  # 60 bytes: el caso 16 recorta los últimos 4 bytes de P
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        _C_LARGO[:120],
        "76fc6ece0f4e1768cddf8853bb2d551b",
        id="caso-16",
    ),
]


@pytest.mark.parametrize(("k", "iv", "p", "a", "c", "t"), VECTORES)
def test_cifrado_coincide_con_vector(k: str, iv: str, p: str, a: str, c: str, t: str) -> None:
    salida = AESGCM(bytes.fromhex(k)).encrypt(
        bytes.fromhex(iv), bytes.fromhex(p), bytes.fromhex(a) or None
    )

    ciphertext, auth_tag = salida[:-TAG_LEN], salida[-TAG_LEN:]
    assert ciphertext.hex() == c
    assert auth_tag.hex() == t


@pytest.mark.parametrize(("k", "iv", "p", "a", "c", "t"), VECTORES)
def test_descifrado_coincide_con_vector(k: str, iv: str, p: str, a: str, c: str, t: str) -> None:
    claro = AESGCM(bytes.fromhex(k)).decrypt(
        bytes.fromhex(iv), bytes.fromhex(c + t), bytes.fromhex(a) or None
    )

    assert claro.hex() == p


def test_caso_16_rechaza_aad_distinto() -> None:
    """El AAD está autenticado: cambiar un solo bit invalida la etiqueta (base de H-05)."""
    aad_alterado = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad3")

    with pytest.raises(InvalidTag):
        AESGCM(bytes.fromhex(_K_FEFF)).decrypt(
            bytes.fromhex(_IV_CAFE),
            bytes.fromhex(_C_LARGO[:120] + "76fc6ece0f4e1768cddf8853bb2d551b"),
            aad_alterado,
        )
