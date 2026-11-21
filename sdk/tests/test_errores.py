"""Mapeo de respuestas HTTP y fallos de red a excepciones tipadas.

Cap. 6 §API pública del SDK, "Excepciones tipadas": ``PorteroError`` ← ``AuthenticationError``,
``PermissionDenied``, ``SecretNotFound``, ``NetworkError``, ``ServerError``. Precisión al Cap. 6:
``RateLimited`` (429 de la spec §7, con ``Retry-After``). El SDK no reintenta: la aplicación
decide (Cap. 6, "Falla de manera segura").
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from apoyo import (
    AMBIENTE,
    NOMBRE,
    PROYECTO,
    TRACE_ID,
    FabricaCliente,
    ServidorFalso,
    esperar,
    problema,
)
from portero_cloud_sdk import (
    AuthenticationError,
    NetworkError,
    PermissionDenied,
    PorteroError,
    RateLimited,
    SecretNotFound,
    ServerError,
)


def test_jerarquia_de_excepciones() -> None:
    assert issubclass(PorteroError, Exception)
    for clase in (
        AuthenticationError,
        PermissionDenied,
        SecretNotFound,
        RateLimited,
        NetworkError,
        ServerError,
    ):
        assert issubclass(clase, PorteroError)


def responder(respuesta: httpx.Response) -> Callable[[httpx.Request], httpx.Response]:
    """Manejador que responde lo mismo a toda petición."""
    return lambda _request: respuesta


@pytest.mark.parametrize(
    ("status", "esperada"),
    [
        (401, AuthenticationError),
        (403, PermissionDenied),
        (404, SecretNotFound),
        (500, ServerError),
        (502, ServerError),
        (503, ServerError),
    ],
)
async def test_codigo_http_a_excepcion(
    crear_cliente: FabricaCliente, status: int, esperada: type[PorteroError]
) -> None:
    cliente = crear_cliente(responder(problema(status)))
    with pytest.raises(esperada) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert excinfo.value.status_code == status
    assert excinfo.value.trace_id == TRACE_ID


@pytest.mark.parametrize("status", [400, 409, 413, 422])
async def test_otros_4xx_son_portero_error_generico(
    crear_cliente: FabricaCliente, status: int
) -> None:
    cliente = crear_cliente(responder(problema(status)))
    with pytest.raises(PorteroError) as excinfo:
        await esperar(cliente.list_secrets(project=PROYECTO, environment=AMBIENTE))
    assert type(excinfo.value) is PorteroError
    assert excinfo.value.status_code == status


async def test_403_al_pedir_el_valor_es_permission_denied(
    crear_cliente: FabricaCliente,
) -> None:
    """El Cap. 6 lo pide para ``get_secret_value``: el alcance del token no cubre el secreto."""
    servidor = ServidorFalso()
    servidor.respuesta_valor = problema(403)
    cliente = crear_cliente(servidor)
    with pytest.raises(PermissionDenied):
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))


@pytest.mark.parametrize(
    ("retry_after", "esperado"),
    [("30", 30.0), ("1", 1.0), (None, None), ("Wed, 21 Oct 2026 07:28:00 GMT", None)],
)
async def test_429_es_rate_limited_con_retry_after(
    crear_cliente: FabricaCliente, retry_after: str | None, esperado: float | None
) -> None:
    cabeceras = {} if retry_after is None else {"Retry-After": retry_after}
    llamadas: list[httpx.Request] = []

    def manejador(request: httpx.Request) -> httpx.Response:
        llamadas.append(request)
        return problema(429, cabeceras)

    cliente = crear_cliente(manejador)
    with pytest.raises(RateLimited) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert excinfo.value.retry_after == esperado
    assert excinfo.value.status_code == 429
    assert len(llamadas) == 1  # sin reintentos automáticos


@pytest.mark.parametrize("retry_after", ["²".encode("latin-1"), b"1.5", b"-1", b" "])
async def test_retry_after_no_entero_se_ignora(
    crear_cliente: FabricaCliente, retry_after: bytes
) -> None:
    """H-67: "²" pasa ``str.isdigit()`` pero ``float("²")`` falla; antes escapaba un
    ``ValueError`` en lugar de ``RateLimited``. Solo se aceptan dígitos ASCII (spec §7)."""

    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers=[(b"Retry-After", retry_after)])

    cliente = crear_cliente(manejador)
    with pytest.raises(RateLimited) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert excinfo.value.retry_after is None


def _lanzar(clase: type[httpx.TransportError]) -> Callable[[httpx.Request], httpx.Response]:
    def manejador(request: httpx.Request) -> httpx.Response:
        raise clase("fallo de transporte simulado", request=request)

    return manejador


@pytest.mark.parametrize(
    "clase",
    [httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError],
)
async def test_fallos_de_red_son_network_error(
    crear_cliente: FabricaCliente, clase: type[httpx.TransportError]
) -> None:
    cliente = crear_cliente(_lanzar(clase))
    with pytest.raises(NetworkError) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert excinfo.value.status_code is None
    assert excinfo.value.trace_id is None


@pytest.mark.parametrize(
    "crear_respuesta",
    [
        lambda: httpx.Response(200, content=b"<html>no es JSON</html>"),
        lambda: httpx.Response(200, json={"inesperado": True}),
        lambda: httpx.Response(200, json=[{"id": "no-es-uuid", "name": PROYECTO}]),
    ],
)
async def test_respuesta_mal_formada_es_portero_error(
    crear_cliente: FabricaCliente, crear_respuesta: Callable[[], httpx.Response]
) -> None:
    """``crear_respuesta`` es una fábrica: un ``Response`` no se reutiliza entre pruebas."""
    cliente = crear_cliente(responder(crear_respuesta()))
    with pytest.raises(PorteroError):
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
