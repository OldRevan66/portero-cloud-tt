"""Cursor opaco de la paginación del API REST Gateway (spec Fase 5 §1; OWASP API4).

La paginación es por cursor, sin ``offset``: el cursor codifica la última clave de orden que se
entregó (``version_number`` en las versiones de un secreto, ``id`` en la bitácora). Es "opaco"
para el cliente, que solo lo devuelve tal cual. No es un control de seguridad: alterarlo solo
mueve la página dentro de lo que el actor ya puede ver, porque la autorización se decide antes.
Uno mal formado → 400 ``validation-error``.
"""

import base64
import binascii

from portero.api.errors import ApiProblem

_PREFIX = "k:"


def encode_cursor(key: int) -> str:
    """Clave de orden → cursor (base64url sin relleno de ``"k:<clave>"``)."""
    return base64.urlsafe_b64encode(f"{_PREFIX}{key}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """Cursor → clave de orden (entero positivo). Cualquier otra cosa → 400."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ApiProblem(400, "validation-error", "El cursor no es válido.") from None
    key = raw.removeprefix(_PREFIX)
    if not raw.startswith(_PREFIX) or not key.isdecimal() or int(key) < 1:
        raise ApiProblem(400, "validation-error", "El cursor no es válido.")
    return int(key)
