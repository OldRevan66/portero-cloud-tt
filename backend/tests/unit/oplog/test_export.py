"""Formato de la exportación de la bitácora (RF-021; H-83; OWASP CSV Injection). Sin BD.

``portero.oplog.export`` convierte lotes de ``AuditLog`` en texto CSV o JSON, sin HTTP ni SQL:
el endpoint solo los envuelve en una ``StreamingResponse``. Decisiones que fijan estas pruebas:

- Las columnas son los 16 campos de ``OperationOut`` (spec Fase 5 §5.1 más ``id``,
  ``previous_hash`` y ``current_hash``), en ese orden, en los dos formatos.
- **CSV injection.** Toda celda del CSV que empiece con ``=``, ``+``, ``-``, ``@``, tabulador o
  retorno de carro se prefija con ``'``: así una hoja de cálculo la lee como texto y no como
  fórmula. El vector realista es el ``User-Agent``, que cualquiera controla y queda en un
  ``login_failed`` sin autenticarse.
- El CSV sigue la RFC 4180 (módulo ``csv`` de la stdlib) y empieza con el BOM de UTF-8 para que
  Excel lea bien los acentos. ``None`` es una celda vacía y ``details`` va como JSON ordenado.
- El JSON es un arreglo fiel: no se neutraliza (ninguna hoja de cálculo evalúa JSON).
"""

import csv
import io
import json
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from uuid import UUID

import pytest

from portero.db.models import AuditLog
from portero.oplog.export import EXPORT_COLUMNS, csv_stream, json_stream, neutralize_csv_cell

BOM = "\ufeff"

COLUMNAS = (
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

FORMULA = '=HYPERLINK("http://atacante.example/x","clic")'
USUARIO = UUID("6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b")
PROYECTO = UUID("0b7e1c3d-5f6a-4b8c-9d0e-1f2a3b4c5d6e")
MOMENTO = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _registro(id_: int, **cambios: object) -> AuditLog:
    campos: dict[str, object] = {
        "id": id_,
        "event_timestamp": MOMENTO,
        "actor_user_id": USUARIO,
        "actor_type": "human",
        "actor_ref": "ana@example.com",
        "verb": "login",
        "resource_type": "user",
        "resource_id": None,
        "result": "success",
        "ip_address": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
        "project_id": None,
        "environment_id": None,
        "details": None,
        "previous_hash": "0" * 64,
        "current_hash": f"{id_:064x}",
    }
    campos.update(cambios)
    return AuditLog(**campos)


async def _lotes(*lotes: Sequence[AuditLog]) -> AsyncIterator[Sequence[AuditLog]]:
    for lote in lotes:
        yield lote


async def _texto(trozos: AsyncIterator[str]) -> str:
    return "".join([t async for t in trozos])


def _filas_csv(texto: str) -> list[list[str]]:
    assert texto.startswith(BOM)
    return list(csv.reader(io.StringIO(texto.removeprefix(BOM), newline="")))


# --- Neutralización de fórmulas ------------------------------------------------------------------


@pytest.mark.parametrize("celda", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx", FORMULA])
def test_celda_que_parece_formula_se_prefija_con_apostrofo(celda: str) -> None:
    assert neutralize_csv_cell(celda) == "'" + celda


@pytest.mark.parametrize("celda", ["ana@example.com", "a=b", "", "1.2.3.4", "login", "'=ya"])
def test_celda_normal_no_cambia(celda: str) -> None:
    assert neutralize_csv_cell(celda) == celda


# --- CSV -----------------------------------------------------------------------------------------


def test_las_columnas_son_las_de_operation_out() -> None:
    assert tuple(EXPORT_COLUMNS) == COLUMNAS


async def test_csv_vacio_solo_trae_bom_y_encabezado() -> None:
    texto = await _texto(csv_stream(_lotes()))

    assert texto.startswith(BOM)
    assert _filas_csv(texto) == [list(COLUMNAS)]
    assert texto.endswith("\r\n")  # RFC 4180


async def test_csv_neutraliza_el_user_agent_y_conserva_comas_comillas_y_saltos() -> None:
    raro = 'navegador, "raro"\nsegunda línea'
    texto = await _texto(
        csv_stream(
            _lotes(
                [_registro(2, verb="login_failed", result="failure", user_agent=FORMULA)],
                [_registro(1, user_agent=raro, actor_ref="-ana@example.com")],
            )
        )
    )

    encabezado, *filas = _filas_csv(texto)
    assert encabezado == list(COLUMNAS)
    assert [len(f) for f in filas] == [len(COLUMNAS)] * 2
    primera = dict(zip(encabezado, filas[0], strict=True))
    segunda = dict(zip(encabezado, filas[1], strict=True))
    assert primera["user_agent"] == "'" + FORMULA
    assert (primera["id"], primera["verb"], primera["result"]) == ("2", "login_failed", "failure")
    assert segunda["user_agent"] == raro  # el lector de CSV lo recupera intacto
    assert segunda["actor_ref"] == "'-ana@example.com"


async def test_csv_entrecomilla_todas_las_celdas_para_excel_con_punto_y_coma() -> None:
    """H-84: un Excel con ``;`` como separador (es-ES) partiría ``a;=1+1`` en dos celdas y la
    segunda empezaría con ``=`` sin neutralizar. Con todas las celdas entre comillas (OWASP CSV
    Injection) el ``;`` queda dentro de la celda. Se revisa el texto crudo: ``csv.reader`` lee
    igual las dos formas."""
    texto = await _texto(csv_stream(_lotes([_registro(1, user_agent="a;=1+1", details=None)])))

    encabezado, fila, fin = texto.removeprefix(BOM).split("\r\n")
    assert encabezado == ",".join(f'"{c}"' for c in COLUMNAS)
    assert fila.startswith('"1","')
    assert ',"a;=1+1",' in fila
    assert fila.endswith('"' + f"{1:064x}" + '"')
    assert ',"",' in fila  # también las celdas vacías
    assert fin == ""


async def test_csv_convierte_nulos_uuid_fechas_y_details() -> None:
    texto = await _texto(
        csv_stream(
            _lotes(
                [
                    _registro(
                        7,
                        verb="rotate_secret",
                        resource_type="secret",
                        project_id=PROYECTO,
                        ip_address=None,
                        user_agent=None,
                        details={"to_version": 2, "from_version": 1},
                    )
                ]
            )
        )
    )

    encabezado, fila = _filas_csv(texto)
    celdas = dict(zip(encabezado, fila, strict=True))
    assert celdas["ip_address"] == ""
    assert celdas["user_agent"] == ""
    assert celdas["resource_id"] == ""
    assert celdas["project_id"] == str(PROYECTO)
    assert celdas["actor_user_id"] == str(USUARIO)
    assert datetime.fromisoformat(celdas["event_timestamp"]) == MOMENTO
    assert celdas["details"] == '{"from_version":1,"to_version":2}'  # llaves ordenadas


# --- JSON ----------------------------------------------------------------------------------------


async def test_json_vacio_es_un_arreglo_vacio() -> None:
    assert json.loads(await _texto(json_stream(_lotes()))) == []


async def test_json_une_los_lotes_en_un_arreglo_fiel() -> None:
    texto = await _texto(
        json_stream(
            _lotes(
                [_registro(3, user_agent=FORMULA), _registro(2)],
                [],
                [_registro(1, details={"permission": "audit:read", "status": 403})],
            )
        )
    )

    items = json.loads(texto)
    assert [item["id"] for item in items] == [3, 2, 1]
    assert all(tuple(item) == COLUMNAS for item in items)
    assert items[0]["user_agent"] == FORMULA  # el JSON no se neutraliza
    assert items[0]["actor_user_id"] == str(USUARIO)
    assert items[0]["resource_id"] is None
    assert datetime.fromisoformat(items[0]["event_timestamp"]) == MOMENTO
    assert items[2]["details"] == {"permission": "audit:read", "status": 403}
