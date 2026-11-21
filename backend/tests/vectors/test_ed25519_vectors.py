"""Vectores oficiales de Ed25519: RFC 8032 §7.1, TEST 1, TEST 2 y TEST 3.

Ed25519 es determinista: con la misma clave secreta y el mismo mensaje la firma es siempre la
misma, así que se puede comparar byte a byte contra el RFC.
"""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# (clave secreta, clave pública, mensaje, firma) en hexadecimal.
VECTORES = [
    pytest.param(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        id="TEST-1",
    ),
    pytest.param(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        id="TEST-2",
    ),
    pytest.param(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        id="TEST-3",
    ),
]


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), VECTORES)
def test_clave_publica_derivada(sk: str, pk: str, msg: str, sig: str) -> None:
    privada = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk))

    assert privada.public_key().public_bytes_raw().hex() == pk


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), VECTORES)
def test_firma_coincide_con_vector(sk: str, pk: str, msg: str, sig: str) -> None:
    privada = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk))

    assert privada.sign(bytes.fromhex(msg)).hex() == sig


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), VECTORES)
def test_verificacion_acepta_firma_oficial(sk: str, pk: str, msg: str, sig: str) -> None:
    publica = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk))

    publica.verify(bytes.fromhex(sig), bytes.fromhex(msg))  # no lanza


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), VECTORES)
def test_verificacion_rechaza_firma_alterada(sk: str, pk: str, msg: str, sig: str) -> None:
    publica = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk))
    firma = bytearray.fromhex(sig)
    firma[0] ^= 0x01

    with pytest.raises(InvalidSignature):
        publica.verify(bytes(firma), bytes.fromhex(msg))
