"""Formato de la exportación de la bitácora (RF-021; H-83; RFC 4180; OWASP CSV Injection).

Funciones puras: convierten lotes de ``AuditLog`` en trozos de texto CSV o JSON, sin SQL ni HTTP.
El endpoint ``GET /operations/export`` los envuelve en una ``StreamingResponse`` y el Servicio de
Registro de Operaciones entrega los lotes (``OperationLogService.iter_operations``), así que en
memoria solo hay un lote a la vez.

**CSV injection.** Una hoja de cálculo evalúa como fórmula la celda que empieza con ``=``, ``+``,
``-`` o ``@`` (y algunas también con tabulador o retorno de carro). Hay campos que cualquiera
controla: el ``User-Agent`` de un ``login_failed`` se guarda sin autenticarse. Por eso cada celda
del CSV que empiece con uno de esos caracteres se prefija con ``'``, que la hoja de cálculo lee
como "esto es texto". El JSON no se neutraliza: es una copia fiel y ninguna hoja de cálculo lo
evalúa.

**Todas las celdas entre comillas (H-84).** Un Excel con ``;`` como separador de lista (es-ES)
partiría una celda sin comillas como ``a;=1+1`` en dos, y la segunda empezaría con ``=`` sin el
apóstrofo. Con ``csv.QUOTE_ALL`` el separador siempre queda dentro de la celda, sea cual sea la
configuración regional.
"""

import csv
import io
import json
from collections.abc import AsyncIterable, AsyncIterator, Sequence
from datetime import datetime
from typing import Any, Final

from portero.db.models import AuditLog

EXPORT_COLUMNS: Final = (
    "id",
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
    "previous_hash",
    "current_hash",
)
"""Columnas de la exportación: los campos de ``OperationOut`` (spec Fase 5 §5.1 más ``id``,
``previous_hash`` y ``current_hash``), en el mismo orden, en CSV y en JSON."""

FORMULA_PREFIXES: Final = ("=", "+", "-", "@", "\t", "\r")
"""Caracteres iniciales que una hoja de cálculo puede interpretar como fórmula (OWASP CSV
Injection)."""

UTF8_BOM: Final = "\ufeff"
"""Marca de orden de bytes: sin ella, Excel abre el CSV como Windows-1252 y rompe los acentos."""


def neutralize_csv_cell(text: str) -> str:
    """Prefija con ``'`` la celda que empieza como fórmula (OWASP CSV Injection); las demás no
    cambian."""
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def _json_value(value: object) -> Any:
    """Valor de una columna en tipos de JSON: UUID e IP como texto, fechas en ISO 8601."""
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, int | str | dict | list):
        return value
    return str(value)  # UUID, IPv4Address, IPv6Address


def _row(entry: AuditLog) -> dict[str, Any]:
    return {column: _json_value(getattr(entry, column)) for column in EXPORT_COLUMNS}


def _csv_cell(value: Any) -> str:
    """Texto de una celda: ``None`` → vacía, ``details`` → JSON con llaves ordenadas, y siempre
    neutralizada."""
    if value is None:
        text = ""
    elif isinstance(value, dict | list):
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    else:
        text = str(value)
    return neutralize_csv_cell(text)


def _csv_lines(rows: Sequence[Sequence[str]]) -> str:
    buffer = io.StringIO()
    # RFC 4180; QUOTE_ALL por H-84 (Excel con ``;`` como separador).
    csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_ALL).writerows(rows)
    return buffer.getvalue()


async def csv_stream(batches: AsyncIterable[Sequence[AuditLog]]) -> AsyncIterator[str]:
    """CSV de la bitácora por trozos: BOM y encabezado, y luego un trozo por lote (RFC 4180,
    líneas ``\\r\\n``, todas las celdas entre comillas por H-84). Cada celda pasa por
    ``neutralize_csv_cell``."""
    yield UTF8_BOM + _csv_lines([[neutralize_csv_cell(c) for c in EXPORT_COLUMNS]])
    async for batch in batches:
        if batch:
            yield _csv_lines([[_csv_cell(v) for v in _row(e).values()] for e in batch])


async def json_stream(batches: AsyncIterable[Sequence[AuditLog]]) -> AsyncIterator[str]:
    """Arreglo JSON de la bitácora por trozos: ``[``, los objetos de cada lote separados por
    comas, y ``]``. Los valores van tal cual (sin neutralizar)."""
    yield "["
    first = True
    async for batch in batches:
        if batch:
            items = ",".join(json.dumps(_row(e), ensure_ascii=False) for e in batch)
            yield ("" if first else ",") + items
            first = False
    yield "]"
