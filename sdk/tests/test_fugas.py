"""Ni el token ni el valor se filtran por ``repr``, excepciones, trazas ni logs.

RNF-006; Cap. 6 §Alcance y filosofía ("no cachea secretos en disco ni en logs");
OWASP ASVS V8.3 (datos sensibles fuera de logs) y V7.1.1 (sin credenciales en logs). Las
excepciones se lanzan sin encadenar la de httpx, cuyo ``Request`` guarda la cabecera
``Authorization``; aquí se comprueba con la traza formateada, que es lo que imprime la aplicación.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable

import httpx
import pytest

from apoyo import (
    AMBIENTE,
    DETALLE_DEL_SERVIDOR,
    NOMBRE,
    PROYECTO,
    SID,
    TOKEN,
    VALOR,
    FabricaCliente,
    ServidorFalso,
    esperar,
    problema,
)
from portero_cloud_sdk import PorteroError


def _conexion_rechazada(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("conexión rechazada", request=request)


MANEJADORES_DE_ERROR: list[Callable[[httpx.Request], httpx.Response]] = [
    lambda _r: problema(401),
    lambda _r: problema(403),
    lambda _r: problema(404),
    lambda _r: problema(429, {"Retry-After": "30"}),
    lambda _r: problema(409),
    lambda _r: problema(500),
    lambda _r: problema(503),
    _conexion_rechazada,
]


def _sin_fugas(texto: str) -> None:
    assert TOKEN not in texto
    assert VALOR not in texto
    assert DETALLE_DEL_SERVIDOR not in texto  # ni el cuerpo de la respuesta


async def test_repr_del_cliente_sin_token_ni_valor(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente()
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    _sin_fugas(repr(cliente))
    _sin_fugas(str(cliente))
    _sin_fugas(repr(vars(cliente)) if hasattr(cliente, "__dict__") else "")


async def test_repr_de_secret_sin_valor(crear_cliente: FabricaCliente) -> None:
    cliente = crear_cliente()
    secreto = await esperar(cliente.get_secret(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    _sin_fugas(repr(secreto))


@pytest.mark.parametrize("manejador", MANEJADORES_DE_ERROR)
async def test_excepciones_sin_token_ni_cuerpo(
    crear_cliente: FabricaCliente, manejador: Callable[[httpx.Request], httpx.Response]
) -> None:
    cliente = crear_cliente(manejador)
    with pytest.raises(PorteroError) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    excepcion = excinfo.value
    _sin_fugas(str(excepcion))
    _sin_fugas(repr(excepcion))
    _sin_fugas(repr(excepcion.args))
    _sin_fugas("".join(traceback.format_exception(excepcion)))
    assert excepcion.__cause__ is None


@pytest.mark.parametrize(
    "crear_respuesta",
    [
        lambda: httpx.Response(
            200, json={"id": "no-es-uuid", "name": NOMBRE, "value": VALOR, "version": "tres"}
        ),
        lambda: httpx.Response(200, json={"id": str(SID), "name": NOMBRE, "valor": VALOR}),
        lambda: httpx.Response(200, json=[VALOR]),
    ],
)
async def test_value_mal_formado_no_filtra_el_valor(
    crear_cliente: FabricaCliente,
    servidor: ServidorFalso,
    crear_respuesta: Callable[[], httpx.Response],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """El ``str()`` de un ``ValidationError`` de Pydantic incluye la entrada: el SDK no debe
    propagarlo ni encadenarlo."""
    caplog.set_level(logging.DEBUG)
    servidor.respuesta_valor = crear_respuesta()
    cliente = crear_cliente()
    with pytest.raises(PorteroError) as excinfo:
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    _sin_fugas(str(excinfo.value))
    _sin_fugas(repr(excinfo.value))
    _sin_fugas("".join(traceback.format_exception(excinfo.value)))
    _sin_fugas(caplog.text)


async def test_logs_en_debug_sin_token_ni_valor(
    crear_cliente: FabricaCliente, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    for nombre in ("httpx", "httpcore", "portero_cloud_sdk"):
        caplog.set_level(logging.DEBUG, logger=nombre)

    cliente = crear_cliente()
    valor = await esperar(
        cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
    )
    assert valor == VALOR
    await esperar(cliente.validate())
    await esperar(cliente.health())
    for manejador in MANEJADORES_DE_ERROR:
        con_error = crear_cliente(manejador)
        with pytest.raises(PorteroError):
            await esperar(
                con_error.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
            )

    assert caplog.records, "httpx debe haber registrado las peticiones: la prueba no es vacía"
    _sin_fugas(caplog.text)
    for registro in caplog.records:
        _sin_fugas(registro.getMessage())
