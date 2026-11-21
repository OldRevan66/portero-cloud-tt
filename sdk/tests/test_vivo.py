"""Prueba en vivo contra el stack de desarrollo con el seed (``backend/scripts/seed_demo.py``).

Se salta si no están ``PORTERO_SDK_BASE_URL`` y ``PORTERO_SDK_TOKEN``. El token debe ser el PAT
de una Aplicación Cliente del proyecto "Tienda en línea" **con ambiente** ``development``
(creada en el Dashboard como Líder): una de todo el proyecto también vería ``production``.

    $env:PORTERO_SDK_BASE_URL = "http://localhost:8000"; $env:PORTERO_SDK_TOKEN = "<PAT>"
    uv run pytest -m vivo -v

Comprueba de punta a punta el alcance del PAT (spec Fase 5 §3.7 y §4.1): lee un secreto de
``development`` y no ve uno que sí existe en ``production`` (``SMTP_PASSWORD`` del seed).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest

from portero_cloud_sdk import PorteroAsyncClient, PorteroClient, SecretNotFound

BASE_URL = os.environ.get("PORTERO_SDK_BASE_URL", "")
TOKEN = os.environ.get("PORTERO_SDK_TOKEN", "")
PROYECTO = "Tienda en línea"
PREFIJO_DEMO = "demo-no-es-real-"

pytestmark = [
    pytest.mark.vivo,
    pytest.mark.skipif(
        not (BASE_URL and TOKEN), reason="faltan PORTERO_SDK_BASE_URL y PORTERO_SDK_TOKEN"
    ),
]


@pytest.fixture
def cliente() -> PorteroClient:
    return PorteroClient(base_url=BASE_URL, token=TOKEN)


@pytest.fixture
async def cliente_async() -> AsyncIterator[PorteroAsyncClient]:
    async with PorteroAsyncClient(base_url=BASE_URL, token=TOKEN) as client:
        yield client


def test_lee_un_secreto_de_development(cliente: PorteroClient) -> None:
    with cliente:
        cliente.validate()
        assert cliente.health() is True
        valor = cliente.get_secret_value(PROYECTO, "development", "DB_PASSWORD")
        secreto = cliente.get_secret(PROYECTO, "development", "DB_PASSWORD")
        nombres = {s.name for s in cliente.list_secrets(PROYECTO, "development")}
    assert valor.startswith(PREFIJO_DEMO)  # nunca se imprime: solo se compara el prefijo
    assert secreto.name == "DB_PASSWORD" and secreto.version >= 1
    assert "DB_PASSWORD" in nombres


def test_no_ve_un_secreto_de_production(cliente: PorteroClient) -> None:
    with cliente, pytest.raises(SecretNotFound):
        cliente.get_secret_value(PROYECTO, "production", "SMTP_PASSWORD")


async def test_async_lee_development_y_no_ve_production(
    cliente_async: PorteroAsyncClient,
) -> None:
    valor = await cliente_async.get_secret_value(PROYECTO, "development", "DB_PASSWORD")
    assert valor.startswith(PREFIJO_DEMO)
    with pytest.raises(SecretNotFound):
        await cliente_async.get_secret_value(PROYECTO, "production", "SMTP_PASSWORD")
