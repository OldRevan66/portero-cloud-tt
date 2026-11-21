"""Pruebas de contraseñas: Argon2id con los parámetros del Cap. 6, política NIST SP 800-63B
§5.1.1 y verificación contra hash señuelo (spec §3.1; H-08).

Las contraseñas de este archivo son marcadores de prueba, no credenciales reales.
"""

import secrets
import string

import pytest
from argon2 import PasswordHasher

from portero.auth import passwords
from portero.auth.passwords import (
    MAX_LENGTH,
    MEMORY_COST_KIB,
    MIN_LENGTH,
    PARALLELISM,
    TIME_COST,
    PasswordPolicyError,
    check_password_policy,
    common_passwords,
    hash_password,
    needs_rehash,
    prepare_decoy_hash,
    verify_against_decoy,
    verify_password,
)

CONTRASENA = "marcador de prueba largo"  # noqa: S105


# --- Hash Argon2id -------------------------------------------------------------------------------


def test_parametros_son_los_del_cap6() -> None:
    """m=19456 KiB, t=2, p=1 (Cap. 6, tabla de algoritmos; OWASP Password Storage)."""
    assert (MEMORY_COST_KIB, TIME_COST, PARALLELISM) == (19456, 2, 1)


def test_el_hash_es_argon2id_con_esos_parametros() -> None:
    h = hash_password(CONTRASENA)

    assert h.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert CONTRASENA not in h


def test_dos_hashes_de_la_misma_contrasena_difieren() -> None:
    """Sal aleatoria por hash: dos usuarios con la misma contraseña no comparten hash."""
    assert hash_password(CONTRASENA) != hash_password(CONTRASENA)


def test_verify_correcta_e_incorrecta() -> None:
    h = hash_password(CONTRASENA)

    assert verify_password(h, CONTRASENA) is True
    assert verify_password(h, CONTRASENA + "x") is False
    assert verify_password(h, "") is False


@pytest.mark.parametrize(
    "corrupto",
    ["", "no-es-un-hash", "$argon2id$v=19$m=19456,t=2,p=1$AAAA$BBBB", "$2b$12$bcryptnoaplica"],
)
def test_hash_corrupto_devuelve_false_sin_lanzar(corrupto: str) -> None:
    assert verify_password(corrupto, CONTRASENA) is False


def test_needs_rehash() -> None:
    """Un hash con otros parámetros (p. ej. los de argon2-cffi por omisión) se debe rehacer al
    siguiente login exitoso (spec §3.1)."""
    viejo = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4).hash(CONTRASENA)

    assert needs_rehash(viejo) is True
    assert needs_rehash(hash_password(CONTRASENA)) is False
    assert verify_password(viejo, CONTRASENA) is True  # se sigue aceptando mientras tanto


# --- Hash señuelo (H-08) -----------------------------------------------------------------------


class EspiaHasher(PasswordHasher):
    """``PasswordHasher`` que cuenta las llamadas a ``verify`` (prueba de flujo, no de tiempo)."""

    def __init__(self) -> None:
        super().__init__(memory_cost=MEMORY_COST_KIB, time_cost=TIME_COST, parallelism=PARALLELISM)
        self.hashes_verificados: list[str] = []

    def verify(self, hash: str | bytes, password: str | bytes) -> bool:  # noqa: A002
        self.hashes_verificados.append(str(hash))
        return super().verify(hash, password)


def test_senuelo_ejecuta_un_verify_real(monkeypatch: pytest.MonkeyPatch) -> None:
    """Si el correo no existe se calcula Argon2id de todos modos: la respuesta tarda lo mismo
    que con un correo válido y no se filtra la existencia de la cuenta (H-08)."""
    espia = EspiaHasher()
    monkeypatch.setattr(passwords, "_hasher", espia)

    assert verify_against_decoy(CONTRASENA) is False
    assert len(espia.hashes_verificados) == 1
    assert espia.hashes_verificados[0].startswith("$argon2id$v=19$m=19456,t=2,p=1$")


def test_prepare_decoy_hash_lo_deja_calculado(monkeypatch: pytest.MonkeyPatch) -> None:
    """H-32: tras prepararlo, el primer correo inexistente cuesta un solo ``verify``, igual
    que un correo válido, en lugar de ``hash`` + ``verify``."""
    passwords._decoy_hash.cache_clear()
    prepare_decoy_hash()
    espia = EspiaHasher()
    monkeypatch.setattr(passwords, "_hasher", espia)
    llamadas_a_hash: list[str] = []
    monkeypatch.setattr(espia, "hash", lambda *a, **k: llamadas_a_hash.append("hash") or "")

    verify_against_decoy(CONTRASENA)

    assert llamadas_a_hash == []
    assert len(espia.hashes_verificados) == 1


def test_senuelo_nunca_acepta() -> None:
    for _ in range(3):
        assert verify_against_decoy(secrets.token_urlsafe(16)) is False
    assert verify_against_decoy("") is False


# --- Política de contraseñas (NIST SP 800-63B §5.1.1) -------------------------------------------


def test_longitud_minima_es_12() -> None:
    assert MIN_LENGTH == 12


def test_11_caracteres_se_rechaza() -> None:
    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy("k7#mqv2zpx9")

    assert exc.value.reason == "longitud"
    assert "k7#mqv2zpx9" not in str(exc.value)


def test_12_caracteres_no_comunes_se_aceptan() -> None:
    check_password_policy("k7#mqv2zpx9w")


def test_sin_reglas_de_composicion() -> None:
    """Solo minúsculas, sin dígitos ni símbolos: NIST desaconseja exigir composición."""
    candidata = "".join(secrets.choice(string.ascii_lowercase) for _ in range(16))

    check_password_policy(candidata)


def test_longitud_en_caracteres_no_en_bytes() -> None:
    """12 caracteres acentuados son más de 12 bytes en UTF-8, pero cuentan como 12."""
    check_password_policy("ñandúcañónñá")
    with pytest.raises(PasswordPolicyError):
        check_password_policy("ñandúcañónñ")


@pytest.mark.parametrize("comun", ["password1234", "PASSWORD1234", "Qwertyuiop123"])
def test_contrasena_comun_se_rechaza(comun: str) -> None:
    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy(comun)

    assert exc.value.reason == "comun"
    assert comun not in str(exc.value)


def test_lista_local_cargada() -> None:
    lista = common_passwords()

    assert len(lista) > 1000
    assert all(len(p) >= MIN_LENGTH for p in lista)
    assert all(p == p.lower() for p in lista)
    assert not any(p.startswith("#") for p in lista)
    assert "password1234" in lista
    assert "qwertyuiop123" in lista


# --- Longitud máxima (H-30; OWASP ASVS V2.1.2) --------------------------------------------------


def test_longitud_maxima_es_128() -> None:
    assert MAX_LENGTH == 128


def test_128_caracteres_se_aceptan() -> None:
    check_password_policy("k7#mqv2zpx9w" * 10 + "abcdefgh")


def test_129_caracteres_se_rechazan() -> None:
    candidata = "k7#mqv2zpx9w" * 10 + "abcdefghi"

    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy(candidata)

    assert exc.value.reason == "longitud_maxima"
    assert candidata not in str(exc.value)


# --- Normalización Unicode NFKC (H-31; NIST SP 800-63B §5.1.1.2) -------------------------------

# Los mismos caracteres en dos codificaciones: "ñ" precompuesta (NFC) y "n" + tilde combinante
# (NFD). Un teclado de macOS y uno de Windows pueden producir una u otra.
ENIE_NFC = "ñ"
ENIE_NFD = "ñ"


def test_contrasena_nfc_verifica_con_su_forma_nfd() -> None:
    h = hash_password(f"contrase{ENIE_NFC}a de prueba")

    assert verify_password(h, f"contrase{ENIE_NFD}a de prueba") is True


def test_contrasena_nfd_verifica_con_su_forma_nfc() -> None:
    h = hash_password(f"contrase{ENIE_NFD}a de prueba")

    assert verify_password(h, f"contrase{ENIE_NFC}a de prueba") is True


def test_formas_de_compatibilidad_se_unifican() -> None:
    """NFKC lleva los caracteres de ancho completo (teclados de Asia oriental) a ASCII."""
    h = hash_password("ｍａｒｃａｄｏｒ de prueba")

    assert verify_password(h, "marcador de prueba") is True


def test_normalizar_no_vuelve_iguales_contrasenas_distintas() -> None:
    h = hash_password(f"contrase{ENIE_NFC}a de prueba")

    assert verify_password(h, "contrasena de prueba") is False


def test_longitud_minima_se_mide_tras_normalizar() -> None:
    """11 "ñ" en NFD son 22 puntos de código, pero 11 caracteres: se rechaza."""
    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy(ENIE_NFD * 11)

    assert exc.value.reason == "longitud"
    check_password_policy(ENIE_NFD * 12)


def test_longitud_maxima_se_mide_tras_normalizar() -> None:
    """La longitud que cuenta es la de lo que se hashea. 100 "ñ" en NFD (200 puntos de código)
    son 100 caracteres; 8 U+FDFA son 8 puntos de código, pero NFKC los expande a 144."""
    check_password_policy(ENIE_NFD * 100)

    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy("ﷺ" * 8)

    assert exc.value.reason == "longitud_maxima"


def test_contrasena_comun_en_ancho_completo_se_rechaza() -> None:
    """ "ｐａｓｓｗｏｒｄ１２３４" normaliza a "password1234", que está en la lista."""
    candidata = "".join(chr(ord(c) + 0xFEE0) for c in "password1234")

    with pytest.raises(PasswordPolicyError) as exc:
        check_password_policy(candidata)

    assert exc.value.reason == "comun"
