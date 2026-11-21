"""Tipos de entrada del API REST Gateway: parámetros de ruta, texto y correo (spec Fase 5 §1;
OWASP ASVS V5.1.3, V5.1.4).

- ``CanonicalUUID``: ``uuid.UUID`` de Pydantic acepta varias formas (32 hex sin guiones, con
  llaves, URN). La spec fija que los identificadores de ruta son UUID **canónicos** de 36
  caracteres con guiones y que cualquier otra forma es un 400 ``validation-error``: así un mismo
  recurso tiene una sola URL y la validación de la entrada es estricta.
- ``PlainText`` **[H-44]**: texto sin caracteres de control. PostgreSQL no admite el carácter
  NUL en columnas de texto; sin este tipo, un NUL pasaba el esquema y la petición terminaba en un
  500. Se conservan el tabulador y los saltos de línea, válidos en una descripción.
- ``Email`` **[H-45]**: correo en forma canónica (``normalize_email``) y sin caracteres de
  control.
"""

import re
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, BeforeValidator, Field

from portero.auth.emails import normalize_email

_CANONICAL_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _require_canonical(value: object) -> object:
    """Rechaza un texto que no tenga la forma canónica; Pydantic convierte después a ``UUID``.
    El ``ValueError`` termina en ``RequestValidationError`` → 400 (``api/errors.py``)."""
    if isinstance(value, str) and not _CANONICAL_UUID.fullmatch(value):
        raise ValueError("el identificador debe ser un UUID canónico")
    return value


CanonicalUUID = Annotated[UUID, BeforeValidator(_require_canonical)]
"""Parámetro de ruta UUID en forma canónica (spec Fase 5 §1)."""


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
"""Caracteres de control C0 y DEL, salvo el tabulador, el salto de línea y el retorno de
carro."""


def _reject_control_chars(value: str) -> str:
    """El ``ValueError`` termina en ``RequestValidationError`` → 400; el manejador nunca repite
    el valor recibido (``api/errors.py``)."""
    if _CONTROL_CHARS.search(value):
        raise ValueError("el texto contiene caracteres de control")
    return value


PlainText = Annotated[str, AfterValidator(_reject_control_chars)]
"""Texto de entrada sin caracteres de control (H-44). Se combina con ``Field`` para los largos."""

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
"""Forma mínima de un correo (``algo@dominio.tld``). En el login basta: un correo con otra forma
no existe en ``users``. Evita depender de ``email-validator``, que no está en el stack."""


def _normalize(value: object) -> object:
    return normalize_email(value) if isinstance(value, str) else value


Email = Annotated[
    PlainText,
    BeforeValidator(_normalize),
    Field(max_length=255, pattern=EMAIL_PATTERN),
]
"""Correo de entrada: normalizado antes de validar su forma (H-45) y sin caracteres de control."""
