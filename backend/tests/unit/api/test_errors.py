"""Errores del API REST Gateway con Problem Details (RFC 9457; Cap. 6 §Manejo de errores; spec
Fase 5 §6). Sin BD ni lifespan: se usan rutas de prueba agregadas a la app real.

``raise_app_exceptions=False``: Starlette vuelve a lanzar la excepción no controlada después de
enviar el 500 (para que la registre el servidor); aquí solo interesa la respuesta.
"""

from collections.abc import AsyncIterator
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ConfigDict

from portero.config import Settings
from portero.main import create_app

TIPO_ERROR = "https://portero-cloud.example/errors/"
CAMPOS_PROBLEMA = {"type", "title", "status", "detail", "instance", "trace_id"}
MARCADOR = "marcador-detalle-interno-no-debe-salir"
RUTA_INTERNA = r"C:\srv\portero\src\portero\secrets_mgmt\service.py"


class _Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nombre: str


@pytest.fixture
async def cliente(settings: Settings) -> AsyncIterator[AsyncClient]:
    app: FastAPI = create_app(settings)

    @app.get("/api/v1/_prueba/falla")
    async def falla() -> None:
        raise RuntimeError(f"{MARCADOR} en {RUTA_INTERNA}")

    @app.post("/api/v1/_prueba/eco")
    async def eco(entrada: _Entrada) -> dict[str, str]:
        return {"nombre": entrada.nombre}

    transporte = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transporte, base_url="https://test") as c:
        yield c


def _assert_problema(respuesta_status: int, cuerpo: dict[str, object], status: int) -> None:
    assert respuesta_status == status
    assert set(cuerpo) >= CAMPOS_PROBLEMA
    assert cuerpo["status"] == status
    assert isinstance(cuerpo["title"], str) and cuerpo["title"]
    assert isinstance(cuerpo["detail"], str) and cuerpo["detail"]
    UUID(str(cuerpo["trace_id"]), version=4)


@pytest.mark.parametrize(
    ("metodo", "ruta", "json", "status", "tipo"),
    [
        ("GET", "/api/v1/no-existe", None, 404, "resource-not-found"),
        ("POST", "/api/v1/_prueba/eco", {"nombre": "x", "extra": 1}, 400, "validation-error"),
        ("GET", "/api/v1/_prueba/falla", None, 500, "internal-error"),
    ],
)
async def test_toda_respuesta_de_error_es_problem_details(
    cliente: AsyncClient,
    metodo: str,
    ruta: str,
    json: dict[str, object] | None,
    status: int,
    tipo: str,
) -> None:
    respuesta = await cliente.request(metodo, ruta + "?q=marcador-query", json=json)

    assert respuesta.headers["content-type"].startswith("application/problem+json")
    cuerpo = respuesta.json()
    _assert_problema(respuesta.status_code, cuerpo, status)
    assert cuerpo["type"] == TIPO_ERROR + tipo
    # instance = ruta de la petición, sin query string (spec §6).
    assert cuerpo["instance"] == ruta
    assert respuesta.headers["x-trace-id"] == cuerpo["trace_id"]


async def test_trace_id_distinto_por_peticion(cliente: AsyncClient) -> None:
    a = (await cliente.get("/api/v1/no-existe")).json()["trace_id"]
    b = (await cliente.get("/api/v1/no-existe")).json()["trace_id"]

    assert a != b


async def test_excepcion_no_controlada_da_500_sin_detalles_internos(
    cliente: AsyncClient,
) -> None:
    respuesta = await cliente.get("/api/v1/_prueba/falla")

    assert respuesta.status_code == 500
    texto = respuesta.text
    assert MARCADOR not in texto
    assert "Traceback" not in texto
    assert "RuntimeError" not in texto
    assert ".py" not in texto
    assert "srv" not in texto


async def test_validacion_no_devuelve_el_valor_enviado(cliente: AsyncClient) -> None:
    """Spec §6: los 400 listan ``loc`` y ``type`` de cada error, nunca ``input``."""
    respuesta = await cliente.post(
        "/api/v1/_prueba/eco", json={"nombre": 123, "otro": "marcador-valor-enviado"}
    )

    assert respuesta.status_code == 400
    cuerpo = respuesta.json()
    assert cuerpo["errors"]
    for error in cuerpo["errors"]:
        assert set(error) <= {"loc", "type"}
    assert "marcador-valor-enviado" not in respuesta.text
