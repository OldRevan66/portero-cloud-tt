"""``validate()`` (fail fast al arranque) y ``health()`` (health check de la aplicación).

Cap. 6 §Manejo de credenciales del cliente, "Validación al arranque": comprobar que el token es
válido y el backend accesible antes de la lógica de negocio. Se usa ``GET /projects`` porque
``/auth/me`` responde 403 a un PAT (spec §3.4). ``health()`` usa ``GET /health/ready`` (spec §3.8).
"""

from __future__ import annotations

import httpx
import pytest

from apoyo import FabricaCliente, ServidorFalso, esperar, problema
from portero_cloud_sdk import AuthenticationError, NetworkError, ServerError


def _conexion_rechazada(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("conexión rechazada", request=request)


async def test_validate_con_200_devuelve_none(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    assert await esperar(cliente.validate()) is None
    assert [p.url.path for p in servidor.peticiones] == ["/api/v1/projects"]


async def test_validate_con_401_es_authentication_error(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente(lambda _r: problema(401))
    with pytest.raises(AuthenticationError):
        await esperar(cliente.validate())


async def test_validate_sin_conexion_es_network_error(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente(_conexion_rechazada)
    with pytest.raises(NetworkError):
        await esperar(cliente.validate())


async def test_health_con_200_es_true(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    assert await esperar(cliente.health()) is True
    assert [p.url.path for p in servidor.peticiones] == ["/api/v1/health/ready"]


async def test_health_con_503_es_false(crear_cliente: FabricaCliente) -> None:
    """503 = la BD no responde o la KEK no está cargada (H-06): el backend no está listo."""
    cliente = crear_cliente(lambda _r: httpx.Response(503, json={"status": "unavailable"}))
    assert await esperar(cliente.health()) is False


async def test_health_con_500_es_server_error(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente(lambda _r: problema(500))
    with pytest.raises(ServerError):
        await esperar(cliente.health())


async def test_health_sin_conexion_es_network_error(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente(_conexion_rechazada)
    with pytest.raises(NetworkError):
        await esperar(cliente.health())
