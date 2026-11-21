"""``GET /api/v1/health/ready`` contra la app real (spec Fase 5 §3.8; H-06).

200 si la BD responde y la KEK quedó derivada y verificada en el arranque; 503 si no. Ningún
cuerpo de salud identifica al producto (no da pistas a un escaneo).
"""

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.exc import OperationalError

PISTAS_DE_PRODUCTO = ("portero", "fastapi", "uvicorn", "0.1.0")


class _SesionCaida:
    """Sesión que simula una BD que no responde: toda consulta falla como lo haría asyncpg con
    la conexión rechazada."""

    async def execute(self, *args: object, **kwargs: object) -> object:
        raise OperationalError("SELECT 1", {}, ConnectionRefusedError())

    async def scalar(self, *args: object, **kwargs: object) -> object:
        raise OperationalError("SELECT 1", {}, ConnectionRefusedError())

    async def close(self) -> None:
        return None


async def test_ready_con_bd_y_kek_listas_da_200(cliente: AsyncClient) -> None:
    respuesta = await cliente.get("/api/v1/health/ready")

    assert respuesta.status_code == 200


async def test_ready_con_bd_caida_da_503(app: FastAPI, cliente: AsyncClient) -> None:
    from portero.api.deps import get_session

    async def sesion_caida() -> AsyncIterator[_SesionCaida]:
        yield _SesionCaida()

    app.dependency_overrides[get_session] = sesion_caida
    try:
        respuesta = await cliente.get("/api/v1/health/ready")
    finally:
        app.dependency_overrides.clear()

    assert respuesta.status_code == 503
    assert "ConnectionRefused" not in respuesta.text
    assert "SELECT" not in respuesta.text


@pytest.mark.parametrize("ruta", ["/api/v1/health", "/api/v1/health/ready"])
async def test_cuerpo_de_salud_no_identifica_al_producto(cliente: AsyncClient, ruta: str) -> None:
    respuesta = await cliente.get(ruta)

    texto = respuesta.text.lower()
    for pista in PISTAS_DE_PRODUCTO:
        assert pista not in texto
