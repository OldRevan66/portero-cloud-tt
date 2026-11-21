"""Pruebas que cierran huecos del plan de pruebas de seguridad (Cap. 8 del reporte técnico;
OWASP ASVS 4.0.3 V3.1.1, V13.2.1, V13.2.5 y V14.5.1).

Cada una fija un comportamiento que el código ya tenía por construcción (FastAPI, Starlette y
el manejador de errores RFC 9457), pero que ninguna prueba ejercía.
"""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    CONTRASENA,
    Escenario,
    assert_problema,
    contar_registros,
)

API = "/api/v1"
PROBLEMA = "application/problem+json"


# --- V3.1.1: el token de sesión nunca viaja en la URL --------------------------------------------


async def test_un_token_en_la_query_no_autentica(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """Un access token válido en la query string no se acepta: solo la cabecera
    ``Authorization`` autentica (RFC 6750 §2.3 desaconseja la query; ASVS V3.1.1)."""
    token = escenario.tokens["admin"]

    for nombre in ("access_token", "token"):
        respuesta = await cliente.get(f"{API}/auth/me", params={nombre: token})

        assert_problema(respuesta, 401, "authentication-failed")


# --- V13.2.5: el Content-Type se valida ----------------------------------------------------------


async def test_json_con_content_type_de_texto_se_rechaza(cliente: AsyncClient) -> None:
    """Un cuerpo JSON declarado como ``text/plain`` no se interpreta: 400 de validación.
    Una petición "simple" de un formulario ajeno (sin preflight CORS) no llega al login."""
    respuesta = await cliente.post(
        f"{API}/auth/login",
        content=f'{{"email": "ana@example.com", "password": "{CONTRASENA}"}}',
        headers={"Content-Type": "text/plain"},
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_escritura_con_content_type_de_formulario_no_crea_nada(
    cliente: AsyncClient, db_session: AsyncSession, escenario: Escenario
) -> None:
    """Igual con un actor autorizado: ``application/x-www-form-urlencoded`` no crea el secreto
    ni deja registro de escritura."""
    antes = await contar_registros(db_session)

    respuesta = await cliente.post(
        f"{API}/projects/{escenario.a.id}/environments/{escenario.a.dev}/secrets",
        content="name=NUEVO&value=marcador-valor",
        headers={**escenario.h("lider_a"), "Content-Type": "application/x-www-form-urlencoded"},
    )

    assert_problema(respuesta, 400, "validation-error")
    assert await contar_registros(db_session) == antes


# --- V13.2.1 y V14.5.1: solo los métodos declarados ----------------------------------------------


async def test_metodo_no_declarado_da_405_con_problem_details(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """``PUT`` no existe en ``/projects/{pid}`` (la API usa ``PATCH``): 405 en formato RFC 9457,
    antes de autenticar o autorizar.

    Starlette arma ``Allow`` con la primera ruta que coincide (aquí ``GET``), no con todos los
    métodos de la URL; RFC 9110 §15.5.6 pide la lista completa. No afecta la seguridad: solo se
    comprueba que ``PUT`` no aparezca como permitido."""
    respuesta = await cliente.put(
        f"{API}/projects/{escenario.a.id}", json={}, headers=escenario.h("admin")
    )

    assert respuesta.status_code == 405
    assert respuesta.headers["content-type"].startswith(PROBLEMA)
    assert "PUT" not in respuesta.headers["allow"]


async def test_trace_da_405(cliente: AsyncClient) -> None:
    """``TRACE`` reflejaría las cabeceras de la petición (incluido ``Authorization``) en el
    cuerpo (Cross-Site Tracing); ninguna ruta lo acepta."""
    respuesta = await cliente.request("TRACE", f"{API}/health")

    assert respuesta.status_code == 405
    assert respuesta.headers["content-type"].startswith(PROBLEMA)
    assert "authorization" not in respuesta.text.lower()
