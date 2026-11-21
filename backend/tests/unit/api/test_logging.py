"""Logging en despliegue (Cap. 6 §Logging estructurado; spec Fase 5 §7; OWASP ASVS V7.1).

Lo que escribe el proceso en stderr, no lo que ve ``caplog``: en el contenedor cada línea debe
ser un objeto JSON, con ``trace_id`` cuando hay petición, y el nivel lo fija
``PORTERO_LOG_LEVEL``. Sin BD: las rutas de prueba se agregan a la app real.
"""

import json
import logging
import sys
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from portero.api.middleware import ACCESS_LOGGER, configure_logging
from portero.config import Settings
from portero.main import create_app

MARCADOR = "marcador-detalle-interno"
_LOGGERS = ("portero", ACCESS_LOGGER, "portero.api", "uvicorn", "uvicorn.error", "uvicorn.access")


@pytest.fixture(autouse=True)
def _restaurar_loggers() -> Iterator[None]:
    """``configure_logging`` cambia loggers globales: se dejan como estaban."""
    antes = {}
    for nombre in _LOGGERS:
        lg = logging.getLogger(nombre)
        antes[nombre] = (list(lg.handlers), lg.level, lg.propagate, lg.disabled)
    yield
    for nombre, (handlers, level, propagate, disabled) in antes.items():
        lg = logging.getLogger(nombre)
        lg.handlers = handlers
        lg.setLevel(level)
        lg.propagate = propagate
        lg.disabled = disabled


def _como_uvicorn() -> None:
    """Lo que deja ``uvicorn.config.LOGGING_CONFIG`` antes de llamar a ``create_app``: manejadores
    de texto plano en INFO y sin propagar."""
    for nombre in ("uvicorn", "uvicorn.access"):
        lg = logging.getLogger(nombre)
        lg.handlers = [logging.StreamHandler(sys.stderr)]
        lg.setLevel(logging.INFO)
        lg.propagate = False


def _lineas(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    """Cada línea de stderr como JSON; falla si alguna no lo es."""
    salida = [linea for linea in capsys.readouterr().err.splitlines() if linea.strip()]
    lineas = [json.loads(linea) for linea in salida]
    assert all(isinstance(linea, dict) for linea in lineas)
    return lineas


def test_error_con_traza_es_una_sola_linea_json_con_trace_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    try:
        raise RuntimeError(MARCADOR)
    except RuntimeError as exc:
        logging.getLogger("portero.api").error(
            "excepción no controlada",
            extra={"trace_id": "t-1", "path": "/api/v1/x"},
            exc_info=exc,
        )

    [linea] = _lineas(capsys)
    assert linea["level"] == "ERROR"
    assert linea["logger"] == "portero.api"
    assert linea["message"] == "excepción no controlada"
    assert linea["trace_id"] == "t-1"
    assert linea["path"] == "/api/v1/x"
    assert "RuntimeError" in linea["exc_info"]


def test_la_linea_de_acceso_sale_tal_cual(capsys: pytest.CaptureFixture[str]) -> None:
    """El middleware ya la arma como JSON (``access_entry``): no se envuelve otra vez."""
    configure_logging("INFO")
    entrada = {"trace_id": "t-2", "verb": "GET", "path": "/api/v1/health", "status_code": 200}

    logging.getLogger(ACCESS_LOGGER).info(json.dumps(entrada))

    assert _lineas(capsys) == [entrada]


def test_configurar_dos_veces_no_duplica_lineas(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    configure_logging("INFO")

    logging.getLogger(ACCESS_LOGGER).info(json.dumps({"trace_id": "t-3"}))

    assert len(_lineas(capsys)) == 1


def test_nivel_warning_omite_el_log_de_acceso(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("WARNING")

    logging.getLogger(ACCESS_LOGGER).info(json.dumps({"trace_id": "t-4"}))
    logging.getLogger("portero.api").warning("aviso")

    assert [linea["message"] for linea in _lineas(capsys)] == ["aviso"]


def test_errores_de_uvicorn_tambien_salen_en_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Starlette vuelve a lanzar la excepción del 500 y uvicorn la registra en
    ``uvicorn.error``; sin esto, esa traza saldría en texto plano."""
    _como_uvicorn()
    configure_logging("INFO")
    try:
        raise RuntimeError(MARCADOR)
    except RuntimeError as exc:
        logging.getLogger("uvicorn.error").error("Exception in ASGI application", exc_info=exc)

    [linea] = _lineas(capsys)
    assert linea["logger"] == "uvicorn.error"
    assert "RuntimeError" in linea["exc_info"]


def test_el_log_de_acceso_de_uvicorn_queda_apagado(capsys: pytest.CaptureFixture[str]) -> None:
    """Duplicaba cada petición en texto plano y con la query string; la registra
    ``AccessLogMiddleware`` en JSON."""
    _como_uvicorn()
    configure_logging("INFO")

    logging.getLogger("uvicorn.access").info('172.30.251.1:0 - "GET /api/v1/x?q=1 HTTP/1.1" 200')

    assert _lineas(capsys) == []


@pytest.fixture
async def cliente_que_falla(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings.model_copy(update={"log_level": "INFO"}))

    @app.get("/api/v1/_prueba/falla")
    async def falla() -> None:
        raise RuntimeError(MARCADOR)

    transporte = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transporte, base_url="https://test") as c:
        yield c


async def test_un_500_deja_en_el_log_el_mismo_trace_id_que_la_respuesta(
    cliente_que_falla: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    respuesta = await cliente_que_falla.get("/api/v1/_prueba/falla")

    assert respuesta.status_code == 500
    trace_id = respuesta.json()["trace_id"]
    lineas = _lineas(capsys)
    [error] = [linea for linea in lineas if linea.get("logger") == "portero.api"]
    assert error["trace_id"] == trace_id
    assert error["path"] == "/api/v1/_prueba/falla"
    [acceso] = [linea for linea in lineas if linea.get("status_code") == 500]
    assert acceso["trace_id"] == trace_id
