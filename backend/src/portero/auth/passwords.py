"""Hash y verificación de contraseñas con Argon2id (m=19456 KiB, t=2, p=1), política
NIST SP 800-63B §5.1.1 y hash señuelo contra enumeración por tiempo (spec §3.1; H-08).

Toda contraseña se normaliza a NFKC antes de medirla, hashearla o verificarla (H-31; NIST
SP 800-63B §5.1.1.2): la misma contraseña tecleada en otro sistema operativo o teclado puede
llegar con otros puntos de código (p. ej. "ñ" precompuesta o "n" + tilde combinante).

Solo se usa ``argon2-cffi``: la comparación en tiempo constante, la sal aleatoria y el formato
PHC (``$argon2id$v=19$m=...,t=...,p=...$sal$hash``) los pone la biblioteca.
"""

import secrets
import unicodedata
from functools import cache
from importlib import resources
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MEMORY_COST_KIB = 19456
TIME_COST = 2
PARALLELISM = 1
"""Parámetros del Cap. 6 (tabla de algoritmos; OWASP Password Storage Cheat Sheet). Se fijan a
mano porque los de argon2-cffi por omisión (m=65536, t=3, p=4) son otros."""

MIN_LENGTH = 12
"""Longitud mínima en caracteres (Cap. 6 §Política de contraseñas; NIST SP 800-63B §5.1.1)."""

MAX_LENGTH = 128
"""Longitud máxima en caracteres (H-30; OWASP ASVS V2.1.2: se permiten al menos 64 y se
rechazan las de más de 128)."""

_hasher = PasswordHasher(time_cost=TIME_COST, memory_cost=MEMORY_COST_KIB, parallelism=PARALLELISM)

PolicyReason = Literal["longitud", "longitud_maxima", "comun"]


class PasswordPolicyError(ValueError):
    """La contraseña candidata no cumple la política. El mensaje nunca la incluye."""

    def __init__(self, reason: PolicyReason) -> None:
        mensajes = {
            "longitud": f"la contraseña debe tener al menos {MIN_LENGTH} caracteres",
            "longitud_maxima": f"la contraseña debe tener como máximo {MAX_LENGTH} caracteres",
            "comun": "la contraseña aparece en la lista de contraseñas comunes",
        }
        super().__init__(mensajes[reason])
        self.reason: PolicyReason = reason


def _normalize(password: str) -> str:
    """Forma NFKC de la contraseña (H-31; NIST SP 800-63B §5.1.1.2).

    NFKC une las dos codificaciones de un mismo carácter acentuado y lleva las formas de
    compatibilidad (ancho completo, ligaduras) a su equivalente común. No quita acentos.
    """
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    """Hash Argon2id con sal aleatoria de 16 B, en formato PHC (``users.password_hash``).
    La contraseña se normaliza a NFKC antes de hashearla (H-31)."""
    return _hasher.hash(_normalize(password))


def verify_password(stored_hash: str, password: str) -> bool:
    """``True`` si ``password`` corresponde a ``stored_hash``.

    ``PasswordHasher.verify`` compara en tiempo constante. Un hash corrupto o de otro esquema
    devuelve ``False`` en lugar de propagar una excepción: el llamador responde siempre
    "credenciales inválidas" (Cap. 6 §Autenticación de actores humanos).

    La contraseña se normaliza a NFKC igual que al hashearla (H-31). No se rechazan aquí las
    de más de ``MAX_LENGTH``: ninguna almacenada lo supera, así que simplemente no verifican.
    """
    try:
        return _hasher.verify(stored_hash, _normalize(password))
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """``True`` si el hash se calculó con otros parámetros: tras un login exitoso se recalcula
    con los actuales (spec §3.1)."""
    return _hasher.check_needs_rehash(stored_hash)


@cache
def _decoy_hash() -> str:
    """Hash de un valor aleatorio que nadie conoce, con los mismos parámetros que los reales.
    Se calcula una sola vez; ``prepare_decoy_hash`` lo adelanta al arranque (H-32)."""
    return hash_password(secrets.token_urlsafe(32))


def prepare_decoy_hash() -> None:
    """Calcula el hash señuelo al arrancar la aplicación (H-32).

    Si se calculara en el primer login con un correo inexistente, esa respuesta costaría
    ``hash`` + ``verify`` (el doble que con un correo válido) y reabriría, una vez por proceso,
    la enumeración por tiempo que cierra H-08.
    """
    _decoy_hash()


def verify_against_decoy(password: str) -> bool:
    """H-08: cuando el correo no existe, ejecuta un ``verify`` real contra el hash señuelo para
    que la respuesta tarde lo mismo que con un correo existente. Siempre devuelve ``False``."""
    verify_password(_decoy_hash(), password)
    return False


@cache
def common_passwords() -> frozenset[str]:
    """Lista local de contraseñas comunes (``portero/resources/common-passwords.txt``), sin
    consulta externa (Cap. 6 §Política de contraseñas; OWASP ASVS V2.1.7). En minúsculas."""
    texto = (
        resources.files("portero")
        .joinpath("resources", "common-passwords.txt")
        .read_text(encoding="utf-8")
    )
    return frozenset(
        linea.strip().lower()
        for linea in texto.splitlines()
        if linea.strip() and not linea.startswith("#")
    )


def check_password_policy(password: str) -> None:
    """Política del Cap. 6 para registro y cambio de contraseña (NIST SP 800-63B §5.1.1):

    - al menos ``MIN_LENGTH`` y a lo más ``MAX_LENGTH`` caracteres (H-30; OWASP ASVS V2.1.2),
      contados en puntos de código de la forma NFKC, que es lo que se hashea (H-31);
    - no aparecer en la lista de contraseñas comunes (sin distinguir mayúsculas);
    - sin reglas de composición: NIST las desaconseja porque inducen patrones predecibles.

    Lanza ``PasswordPolicyError`` con ``reason`` ``"longitud"``, ``"longitud_maxima"`` o
    ``"comun"``.
    """
    normalizada = _normalize(password)
    if len(normalizada) < MIN_LENGTH:
        raise PasswordPolicyError("longitud")
    if len(normalizada) > MAX_LENGTH:
        raise PasswordPolicyError("longitud_maxima")
    if normalizada.lower() in common_passwords():
        raise PasswordPolicyError("comun")
