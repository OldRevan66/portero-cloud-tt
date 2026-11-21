"""Tipos de retorno del SDK (Cap. 6 §API pública del SDK, "Tipos de retorno").

*Dataclasses* inmutables, como pide el Cap. 6: el consumidor recibe un tipo de la biblioteca
estándar con anotaciones completas (``mypy`` y el autocompletado de los IDE funcionan) y no
depende de la API de Pydantic. Pydantic solo se usa adentro del SDK para validar el JSON
(``TypeAdapter`` en ``_core``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class Secret:
    """Metadatos de un secreto, **sin** su valor (Cap. 6: ``id``, ``name``, ``version``,
    ``description``, ``created_at``).

    El valor solo lo devuelve ``get_secret_value`` como ``str``: ningún objeto del SDK lo
    guarda, así que ningún ``repr`` puede mostrarlo (OWASP ASVS V8.3)."""

    id: UUID
    name: str
    version: int
    description: str | None
    created_at: datetime
