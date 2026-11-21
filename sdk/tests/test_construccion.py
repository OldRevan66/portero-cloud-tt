"""Construcción del cliente: token, URL base, cabeceras, timeout y cierre.

Cap. 6 §API pública del SDK (constructor con ``base_url``, ``token`` y ``timeout``),
§Manejo de credenciales del cliente (el token solo llega por el constructor) y §Modelos de uso
(gestor de contexto). La exigencia de https fuera de loopback es el hallazgo H-55 (propuesto).
"""

from __future__ import annotations

import importlib.metadata
from typing import Any

import httpx
import pytest

import portero_cloud_sdk
from apoyo import (
    AMBIENTE,
    BASE_URL,
    NOMBRE,
    PROYECTO,
    TOKEN,
    FabricaCliente,
    ServidorFalso,
    TransporteConCierre,
    esperar,
)


async def test_bearer_en_cada_peticion(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    await esperar(cliente.get_secret(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    await esperar(cliente.list_secrets(project=PROYECTO, environment=AMBIENTE))
    await esperar(cliente.validate())
    await esperar(cliente.health())

    rutas = {p.url.path for p in servidor.peticiones}
    assert "/api/v1/projects" in rutas and "/api/v1/health/ready" in rutas
    assert len(servidor.peticiones) >= 7
    for peticion in servidor.peticiones:
        assert peticion.headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("base_url", [BASE_URL, BASE_URL + "/"])
async def test_base_url_con_o_sin_diagonal_final(
    crear_cliente: FabricaCliente, servidor: ServidorFalso, base_url: str
) -> None:
    cliente = crear_cliente(base_url=base_url)
    await esperar(cliente.validate())
    assert str(servidor.peticiones[0].url) == "https://portero.example/api/v1/projects"


async def test_timeout_configurable(crear_cliente: FabricaCliente, servidor: ServidorFalso) -> None:
    cliente = crear_cliente(timeout=2.5)
    await esperar(cliente.validate())
    assert servidor.peticiones[0].extensions["timeout"] == {
        "connect": 2.5,
        "read": 2.5,
        "write": 2.5,
        "pool": 2.5,
    }


async def test_timeout_por_omision_de_10_segundos(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    """10 s, como el Listado del uso básico del Cap. 6."""
    cliente = crear_cliente()
    await esperar(cliente.validate())
    assert set(servidor.peticiones[0].extensions["timeout"].values()) == {10.0}


@pytest.mark.parametrize("timeout", [0, -1.0])
async def test_timeout_no_positivo_es_value_error(
    crear_cliente: FabricaCliente, timeout: float
) -> None:
    """Sin tiempo de espera, una red caída colgaría la aplicación consumidora."""
    with pytest.raises(ValueError):
        crear_cliente(timeout=timeout)


async def test_user_agent_con_la_version(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    await esperar(cliente.validate())
    version = importlib.metadata.version("portero-cloud-sdk")
    assert portero_cloud_sdk.__version__ == version
    assert servidor.peticiones[0].headers["User-Agent"] == f"portero-cloud-sdk/{version}"


@pytest.mark.parametrize(
    "token",
    ["", "   ", "pat-con espacio-interno", "pat-con\nsalto", "\tpat-con-tabulador", "pat-final "],
)
async def test_token_vacio_o_con_espacios_es_value_error(
    crear_cliente: FabricaCliente, token: str
) -> None:
    """Un salto de línea en una cabecera sería inyección de cabeceras; un espacio, un token
    mal copiado. Se rechaza al construir (fail fast) sin repetir el token en el mensaje."""
    with pytest.raises(ValueError) as excinfo:
        crear_cliente(token=token)
    if token.strip():
        assert token.strip() not in str(excinfo.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://portero.example",  # http a un host que no es loopback (H-55)
        "http://192.168.1.10:8000",
        "ftp://portero.example",
        "portero.example",
        "https://",
        "",
        "http://[::1",  # httpx no la puede parsear
        # H-66: credenciales, consulta o fragmento en la URL base.
        "https://usuario:clave@portero.example",
        "https://usuario@portero.example",
        "https://portero.example?x=1",
        "https://portero.example/#f",
    ],
)
async def test_base_url_invalida_es_value_error(
    crear_cliente: FabricaCliente, base_url: str
) -> None:
    with pytest.raises(ValueError):
        crear_cliente(base_url=base_url)


async def test_credenciales_en_base_url_no_aparecen_en_el_error(
    crear_cliente: FabricaCliente,
) -> None:
    """H-66: con usuario y contraseña en la URL, el ``repr`` del cliente los mostraría en
    cualquier log (OWASP ASVS V7.1.1). Se rechazan al construir y el mensaje no los repite."""
    with pytest.raises(ValueError) as excinfo:
        crear_cliente(base_url="https://ana-de-prueba:clave-de-prueba@portero.example")
    assert "clave-de-prueba" not in str(excinfo.value)
    assert "ana-de-prueba" not in str(excinfo.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://portero.example",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
async def test_https_o_http_en_loopback_se_aceptan(
    crear_cliente: FabricaCliente, servidor: ServidorFalso, base_url: str
) -> None:
    cliente = crear_cliente(base_url=base_url)
    await esperar(cliente.validate())
    assert str(servidor.peticiones[0].url) == f"{base_url}/api/v1/projects"


async def test_http_en_red_interna_solo_con_permiso_explicito(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    """H-55: ``allow_insecure_http=True`` para la red interna de Compose (TLS en el borde)."""
    cliente = crear_cliente(base_url="http://backend:8000", allow_insecure_http=True)
    await esperar(cliente.validate())
    assert str(servidor.peticiones[0].url) == "http://backend:8000/api/v1/projects"


class FallaDeLaAplicacion(Exception):
    """Excepción propia de la prueba: no la puede lanzar el SDK por accidente."""


async def _usar_con_gestor(
    tipo: str, clase_cliente: type[Any], transporte: httpx.MockTransport, fallar: bool
) -> None:
    if tipo == "sync":
        with clase_cliente(base_url=BASE_URL, token=TOKEN, transport=transporte) as cliente:
            cliente.validate()
            if fallar:
                raise FallaDeLaAplicacion
    else:
        async with clase_cliente(base_url=BASE_URL, token=TOKEN, transport=transporte) as cliente:
            await cliente.validate()
            if fallar:
                raise FallaDeLaAplicacion


async def test_gestor_de_contexto_cierra_el_cliente(
    tipo: str, clase_cliente: type[Any], servidor: ServidorFalso
) -> None:
    transporte = TransporteConCierre(servidor)
    await _usar_con_gestor(tipo, clase_cliente, transporte, fallar=False)
    assert transporte.cerrado
    assert servidor.contar("/projects") == 1


async def test_gestor_de_contexto_cierra_aun_ante_excepciones(
    tipo: str, clase_cliente: type[Any], servidor: ServidorFalso
) -> None:
    """Cap. 6 §Modelos de uso: el cliente HTTP cierra al salir del *scope*, incluso ante
    excepciones; la excepción de la aplicación se propaga sin cambios."""
    transporte = TransporteConCierre(servidor)
    with pytest.raises(FallaDeLaAplicacion):
        await _usar_con_gestor(tipo, clase_cliente, transporte, fallar=True)
    assert transporte.cerrado


async def test_close_libera_el_cliente_y_es_idempotente(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    transporte = TransporteConCierre(servidor)
    cliente = crear_cliente(transport=transporte)
    await esperar(cliente.close())
    await esperar(cliente.close())
    assert transporte.cerrado
