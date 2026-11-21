"""Controles transversales del API REST Gateway (Cap. 6 §Rate limiting y controles transversales;
spec Fase 5 §6, §7; OWASP API Security API4, OWASP ASVS V13 y V14.4; RNF-006).

Con la aplicación real (lifespan, db-test) y httpx ``ASGITransport``, cuyo cliente aparece como
``127.0.0.1``: todas las peticiones de una prueba comparten IP.

Decisiones que fijan estas pruebas (plan de la sesión 13):

- El límite de 1 MiB se comprueba con un cuerpo que **no es JSON válido**: si se deserializara,
  la respuesta sería 400; un 413 demuestra que se cortó antes.
- Las cabeceras de seguridad y ``Cache-Control: no-store`` van en **toda** respuesta de
  ``/api/v1`` (spec §7), también en los errores.
- El log de acceso usa el logger ``portero.access``: un registro por petición cuyo mensaje es un
  objeto JSON con exactamente los siete campos del Cap. 6 §Logging estructurado.
"""

import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import Escenario, assert_problema, contar_registros

from portero.config import Settings
from portero.main import create_app

MIB = 1024 * 1024
VALOR = "marcador-valor-s13-transversal"
VALOR_NUEVO = "marcador-valor-s13-rotado"
AGENTE = "pruebas-s13/1.0"
CONSULTA_SENSIBLE = "marcador-consulta-s13"
CAMPOS_LOG = {"trace_id", "actor_id", "verb", "path", "status_code", "latency_ms", "user_agent"}
CABECERAS_SEGURIDAD = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}
LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"


# --- Auxiliares ----------------------------------------------------------------------------------


async def _crear_secreto(cliente: AsyncClient, esc: Escenario) -> str:
    respuesta = await cliente.post(
        f"/api/v1/projects/{esc.a.id}/environments/{esc.a.dev}/secrets",
        json={"name": "DB_PASSWORD", "value": VALOR},
        headers=esc.h("lider_a"),
    )
    assert respuesta.status_code == 201, respuesta.text
    secret_id: str = respuesta.json()["id"]
    return secret_id


async def _agotar_refresh(cliente: AsyncClient) -> httpx.Response:
    """Diez ``POST /auth/refresh`` sin cookie (401, baratos: no hay Argon2id) y el undécimo."""
    for _ in range(10):
        respuesta = await cliente.post(REFRESH)
        assert respuesta.status_code == 401, respuesta.text
    return await cliente.post(REFRESH)


def _registros_de_acceso(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    entradas = []
    for registro in caplog.records:
        if registro.name == "portero.access":
            entrada = json.loads(registro.getMessage())
            assert isinstance(entrada, dict)
            entradas.append(entrada)
    return entradas


# --- Tamaño del cuerpo (1 MiB → 413) -------------------------------------------------------------


async def test_cuerpo_de_mas_de_1_mib_es_413_antes_de_deserializar(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    total = await contar_registros(db_session)
    cuerpo = b"{" + b"x" * MIB  # 1 MiB + 1 byte y JSON inválido

    respuesta = await cliente.post(
        LOGIN, content=cuerpo, headers={"content-type": "application/json"}
    )

    assert_problema(respuesta, 413, "payload-too-large")
    assert await contar_registros(db_session) == total  # no llegó al login


async def test_cuerpo_por_chunks_de_mas_de_1_mib_es_413(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    """Sin ``Content-Length``: el límite cuenta los bytes conforme llegan (spec §7)."""
    total = await contar_registros(db_session)

    async def trozos() -> AsyncIterator[bytes]:
        yield b"{"
        for _ in range(17):  # 17 × 64 KiB > 1 MiB
            yield b"x" * 65_536

    respuesta = await cliente.post(
        LOGIN, content=trozos(), headers={"content-type": "application/json"}
    )

    assert "content-length" not in respuesta.request.headers
    assert_problema(respuesta, 413, "payload-too-large")
    assert await contar_registros(db_session) == total


async def test_cuerpo_de_exactamente_1_mib_pasa_el_limite(cliente: AsyncClient) -> None:
    respuesta = await cliente.post(
        LOGIN, content=b"{" + b"x" * (MIB - 1), headers={"content-type": "application/json"}
    )

    assert_problema(respuesta, 400, "validation-error")  # se deserializó y no es JSON válido


# --- Cabeceras de seguridad ----------------------------------------------------------------------

Peticion = Callable[[AsyncClient, Escenario], Awaitable[httpx.Response]]


async def _salud(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await c.get("/api/v1/health")


async def _valor(c: AsyncClient, esc: Escenario) -> httpx.Response:
    secret_id = await _crear_secreto(c, esc)
    return await c.get(f"/api/v1/secrets/{secret_id}/value", headers=esc.h("dev_a"))


async def _sin_token(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await c.get("/api/v1/auth/me")


async def _ruta_inexistente(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await c.get("/api/v1/no-existe", headers=esc.h("admin"))


async def _validacion(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await c.post(LOGIN, json={"email": "ana@example.com", "extra": 1})


async def _demasiado_grande(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await c.post(LOGIN, content=b"x" * (MIB + 1))


async def _limite_de_tasa(c: AsyncClient, esc: Escenario) -> httpx.Response:
    return await _agotar_refresh(c)


@pytest.mark.parametrize(
    ("peticion", "status"),
    [
        (_salud, 200),
        (_valor, 200),
        (_sin_token, 401),
        (_ruta_inexistente, 404),
        (_validacion, 400),
        (_demasiado_grande, 413),
        (_limite_de_tasa, 429),
    ],
    ids=["salud", "valor", "sin_token", "ruta_inexistente", "validacion", "413", "429"],
)
async def test_cabeceras_de_seguridad_en_toda_respuesta(
    cliente: AsyncClient, escenario: Escenario, peticion: Peticion, status: int
) -> None:
    respuesta = await peticion(cliente, escenario)

    assert respuesta.status_code == status
    for nombre, valor in CABECERAS_SEGURIDAD.items():
        assert respuesta.headers.get(nombre) == valor, nombre
    assert "no-store" in respuesta.headers.get("cache-control", "")
    UUID(respuesta.headers["x-trace-id"], version=4)


async def test_no_store_en_el_valor_revelado(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await _valor(cliente, escenario)

    assert respuesta.status_code == 200
    assert respuesta.headers["cache-control"] == "no-store"


# --- trace_id ------------------------------------------------------------------------------------


async def test_el_trace_id_de_la_cabecera_es_el_del_problem_details(cliente: AsyncClient) -> None:
    primera = await cliente.get("/api/v1/auth/me")
    segunda = await cliente.get("/api/v1/auth/me")

    for respuesta in (primera, segunda):
        cuerpo = assert_problema(respuesta, 401, "authentication-failed")
        assert cuerpo["trace_id"] == respuesta.headers["x-trace-id"]
    assert primera.headers["x-trace-id"] != segunda.headers["x-trace-id"]


# --- Límite de tasa de extremo a extremo ---------------------------------------------------------


async def test_el_undecimo_intento_de_autenticacion_es_429_y_no_se_registra(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    """Cap. 6: 10 por minuto por IP en ``/auth/login`` y ``/auth/refresh``. El 429 no se registra
    en la bitácora (spec §5.2): tomar el lock de la cadena por cada rechazo sería una vía de
    denegación de servicio."""
    total = await contar_registros(db_session)

    respuesta = await _agotar_refresh(cliente)

    assert_problema(respuesta, 429, "rate-limit-exceeded")
    assert 1 <= int(respuesta.headers["retry-after"]) <= 60
    assert await contar_registros(db_session) == total
    # login comparte la categoría y la IP: también está agotado
    login = await cliente.post(LOGIN, json={"email": "ana@example.com", "password": "x" * 12})
    assert_problema(login, 429, "rate-limit-exceeded")


# --- Logging estructurado (RNF-006) --------------------------------------------------------------


async def test_log_de_acceso_estructurado_sin_valores_ni_credenciales(
    cliente: AsyncClient, escenario: Escenario, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    secret_id = await _crear_secreto(cliente, escenario)
    ruta_valor = f"/api/v1/secrets/{secret_id}/value"
    ruta_rotar = f"/api/v1/secrets/{secret_id}/rotate"

    revelado = await cliente.get(
        ruta_valor,
        params={"marcador": CONSULTA_SENSIBLE},
        headers={**escenario.h("dev_a"), "user-agent": AGENTE},
    )
    rotado = await cliente.post(
        ruta_rotar,
        json={"new_value": VALOR_NUEVO},
        headers={**escenario.h("lider_a"), "user-agent": AGENTE},
    )
    sin_token = await cliente.get("/api/v1/auth/me", headers={"user-agent": AGENTE})
    assert (revelado.status_code, rotado.status_code, sin_token.status_code) == (200, 200, 401)

    entradas = _registros_de_acceso(caplog)
    assert len(entradas) == 4  # una por petición: crear, revelar, rotar y la del 401
    for entrada in entradas:
        assert set(entrada) == CAMPOS_LOG
        assert isinstance(entrada["latency_ms"], int | float)
        assert entrada["latency_ms"] >= 0
    por_trace = {e["trace_id"]: e for e in entradas}

    log_valor = por_trace[revelado.headers["x-trace-id"]]
    assert log_valor == {
        **log_valor,
        "actor_id": str(escenario.ids["dev_a"]),
        "verb": "GET",
        "path": ruta_valor,  # sin query string
        "status_code": 200,
        "user_agent": AGENTE,
    }
    log_rotar = por_trace[rotado.headers["x-trace-id"]]
    assert (log_rotar["actor_id"], log_rotar["verb"], log_rotar["path"]) == (
        str(escenario.ids["lider_a"]),
        "POST",
        ruta_rotar,
    )
    log_401 = por_trace[sin_token.headers["x-trace-id"]]
    assert (log_401["actor_id"], log_401["status_code"]) == (None, 401)

    # Todo lo que registró el servidor. Se excluye el logger ``httpx``: es el cliente de la
    # prueba, que sí escribe la URL completa con su query string.
    texto_servidor = "\n".join(
        r.getMessage() for r in caplog.records if not r.name.startswith("httpx")
    )
    assert texto_servidor
    for prohibido in (
        VALOR,
        VALOR_NUEVO,
        CONSULTA_SENSIBLE,
        escenario.tokens["dev_a"],
        escenario.tokens["lider_a"],
    ):
        assert prohibido not in texto_servidor


# --- OpenAPI (Cap. 6 §OpenAPI; spec §1) ----------------------------------------------------------


@pytest.fixture
async def cliente_sin_lifespan(
    request: pytest.FixtureRequest, settings_app: Settings
) -> AsyncIterator[AsyncClient]:
    """App sin lifespan ni BD: el documento OpenAPI no los necesita."""
    docs_enabled: bool = request.param
    app: FastAPI = create_app(settings_app.model_copy(update={"docs_enabled": docs_enabled}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        yield c


@pytest.mark.parametrize("cliente_sin_lifespan", [True], indirect=True)
async def test_openapi_existe_con_docs_enabled(cliente_sin_lifespan: AsyncClient) -> None:
    respuesta = await cliente_sin_lifespan.get("/api/v1/openapi.json")

    assert respuesta.status_code == 200
    documento = respuesta.json()
    assert documento["openapi"].startswith("3.1")
    assert "/api/v1/operations" in documento["paths"]
    assert "/api/v1/operations/verify-chain" in documento["paths"]
    assert (await cliente_sin_lifespan.get("/docs")).status_code == 200


@pytest.mark.parametrize("cliente_sin_lifespan", [False], indirect=True)
async def test_openapi_no_existe_sin_docs_enabled(cliente_sin_lifespan: AsyncClient) -> None:
    assert (await cliente_sin_lifespan.get("/api/v1/openapi.json")).status_code == 404
    assert (await cliente_sin_lifespan.get("/docs")).status_code == 404
