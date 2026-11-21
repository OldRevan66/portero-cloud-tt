"""Accesorios de las pruebas del SDK (Cap. 6 §Modelos de uso síncrono y asíncrono).

``tipo`` parametriza cada prueba de comportamiento con ``PorteroClient`` y
``PorteroAsyncClient``: ambas clases deben comportarse igual. ``crear_cliente`` construye el
cliente sobre un ``httpx.MockTransport`` y lo cierra al terminar.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from apoyo import BASE_URL, TOKEN, FabricaCliente, ServidorFalso, esperar


@pytest.fixture(params=["sync", "async"])
def tipo(request: pytest.FixtureRequest) -> str:
    """``"sync"`` → PorteroClient; ``"async"`` → PorteroAsyncClient."""
    return str(request.param)


@pytest.fixture
def clase_cliente(tipo: str) -> type[Any]:
    from portero_cloud_sdk import PorteroAsyncClient, PorteroClient

    return PorteroClient if tipo == "sync" else PorteroAsyncClient


@pytest.fixture
def servidor() -> ServidorFalso:
    return ServidorFalso()


@pytest.fixture
async def crear_cliente(
    clase_cliente: type[Any], servidor: ServidorFalso
) -> AsyncIterator[FabricaCliente]:
    """Fábrica: ``crear_cliente(manejador=None, base_url=..., token=..., **kwargs)``.

    Sin ``manejador`` usa el ``servidor`` falso. ``transport`` en ``kwargs`` sustituye al
    ``MockTransport`` por omisión."""
    creados: list[Any] = []

    def fabrica(
        manejador: Callable[[httpx.Request], httpx.Response] | None = None,
        *,
        base_url: str = BASE_URL,
        token: str = TOKEN,
        **kwargs: Any,
    ) -> Any:
        transporte = kwargs.pop("transport", None) or httpx.MockTransport(manejador or servidor)
        cliente = clase_cliente(base_url=base_url, token=token, transport=transporte, **kwargs)
        creados.append(cliente)
        return cliente

    yield fabrica
    for cliente in creados:
        await esperar(cliente.close())
