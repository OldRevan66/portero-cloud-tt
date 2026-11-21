"""Cadena de hashes del Servicio de Registro de Operaciones: funciones puras, sin BD (spec núcleo
§5; spec Fase 5 §5.1; H-11; RF-018; OWASP ASVS V7.3.3, integridad de los registros).

Cada registro guarda ``previous_hash`` y ``current_hash = SHA-256(previous_hash || JSON
canónico)``. Alterar, borrar o reordenar una fila rompe la igualdad en esa posición, y
``verify_chain`` la reporta. El primer registro encadena desde ``GENESIS_HASH``.

Por qué un JSON *canónico*: el hash se calcula al insertar y se recalcula al verificar, con los
valores que devuelve PostgreSQL. Los dos lados deben producir exactamente los mismos bytes, aunque
JSONB reordene las llaves o ``timestamptz`` devuelva la fecha en otra zona.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

GENESIS_HASH = "0" * 64
"""``previous_hash`` del primer registro de la cadena (spec núcleo §5)."""

CHAINED_FIELDS = (
    "event_timestamp",
    "actor_user_id",
    "actor_type",
    "actor_ref",
    "verb",
    "resource_type",
    "resource_id",
    "result",
    "ip_address",
    "user_agent",
    "project_id",
    "environment_id",
    "details",
)
"""Campos que entran al hash (spec Fase 5 §5.1). ``id``, ``previous_hash`` y ``current_hash`` no
entran: ``id`` lo asigna la BD después, y los hashes son el resultado del encadenamiento."""


def _to_json(value: object) -> str:
    """Convierte a texto los tipos que ``json`` no conoce, siempre de la misma forma."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("event_timestamp debe tener zona horaria")
        # Microsegundos fijos: ``timestamptz`` guarda microsegundos, así que el texto es el mismo
        # antes y después de pasar por la BD.
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, UUID | IPv4Address | IPv6Address):
        return str(value)
    raise TypeError(f"tipo no serializable en la bitácora: {type(value).__name__}")


def canonical_json(fields: Mapping[str, Any]) -> bytes:
    """JSON canónico de un registro: solo ``CHAINED_FIELDS``, llaves ordenadas, sin espacios y
    en UTF-8 (spec Fase 5 §5.1). Fechas en UTC ISO 8601 con microsegundos; UUID e IP como
    texto.

    Lanza ``KeyError`` si falta un campo y ``ValueError`` si una fecha no tiene zona horaria.
    """
    record = {name: fields[name] for name in CHAINED_FIELDS}
    text = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_to_json,
    )
    return text.encode("utf-8")


def compute_hash(previous_hash: str, canonical: bytes) -> str:
    """``SHA-256(previous_hash || JSON canónico)`` en hex de 64 caracteres (spec núcleo §5;
    FIPS 180-4). ``||`` es concatenación: los 64 caracteres hex del hash anterior en ASCII,
    seguidos de los bytes del JSON."""
    return hashlib.sha256(previous_hash.encode("ascii") + canonical).hexdigest()


@dataclass(frozen=True)
class ChainRow:
    """Una fila de ``audit_logs`` tal como se verifica: su ``id``, sus hashes y los campos
    encadenados."""

    id: int
    previous_hash: str | None
    current_hash: str
    fields: Mapping[str, Any]


@dataclass(frozen=True)
class ChainVerification:
    """Resultado de ``verify_chain`` (spec Fase 5 §5.1). ``broken`` lista los ``id`` de las filas
    donde la cadena no cuadra, en orden; el primero es la primera fila afectada.

    **[H-46]** ``last_hash`` es el ``current_hash`` almacenado de la última fila (``None`` si no
    hay filas). La cadena no tiene ancla externa: borrar los últimos registros, o reescribir y
    recalcular toda la cadena, pasa la verificación. Anotar ``last_hash`` fuera de la BD y
    compararlo en la siguiente verificación revela ese truncado o esa reescritura.

    **[H-81]** Los campos de firma los llena el servicio con ``checkpoint.verify_checkpoints``;
    ``verify_chain`` (solo la cadena) los deja en sus valores por omisión.
    ``signing_configured`` es falso si la API no tiene la llave pública. ``invalid_signatures`` y
    ``missing_signatures`` son ids de firma; ``last_signed_at`` y ``last_signed_audit_id`` son de
    la última firma válida.
    """

    verified_from: int | None
    verified_to: int | None
    total: int
    ok: bool
    broken: list[int]
    last_hash: str | None
    signing_configured: bool = False
    signatures_total: int = 0
    invalid_signatures: list[str] = field(default_factory=list)
    missing_signatures: list[str] = field(default_factory=list)
    last_signed_at: datetime | None = None
    last_signed_audit_id: int | None = None


def verify_chain(rows: Sequence[ChainRow]) -> ChainVerification:
    """Recorre las filas en orden ascendente de ``id`` y recalcula la cadena (spec Fase 5 §5.1;
    OWASP ASVS V7.3.3).

    Una fila está rota si:

    1. su ``previous_hash`` no es el ``current_hash`` **almacenado** de la fila anterior
       (``GENESIS_HASH`` para la primera): hay una fila borrada, insertada o reordenada; o
    2. el hash recalculado de sus campos no es su ``current_hash``: la fila se alteró.

    Se compara contra el hash almacenado, no contra el recalculado, para que una sola fila
    alterada marque solo esa fila y no todas las siguientes.
    """
    broken: list[int] = []
    expected_previous = GENESIS_HASH
    for row in rows:
        if row.previous_hash != expected_previous:
            broken.append(row.id)
        elif row.current_hash != compute_hash(expected_previous, canonical_json(row.fields)):
            broken.append(row.id)
        expected_previous = row.current_hash
    return ChainVerification(
        verified_from=rows[0].id if rows else None,
        verified_to=rows[-1].id if rows else None,
        total=len(rows),
        ok=not broken,
        broken=broken,
        last_hash=rows[-1].current_hash if rows else None,
    )
