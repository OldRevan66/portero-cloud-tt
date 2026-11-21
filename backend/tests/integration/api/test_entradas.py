"""Validación de texto de entrada en el API REST Gateway (spec Fase 5 §1, §6; H-44, H-45; OWASP
ASVS V5.1.3, V5.1.4, V7.4.1).

- **H-44.** PostgreSQL no admite el carácter NUL en columnas de texto: un ``\\u0000`` que pasara el
  esquema terminaba en un 500 con traza en el log (en ``/auth/login``, sin autenticarse). Todo
  campo de texto de entrada rechaza los caracteres de control con 400 ``validation-error``; las
  descripciones conservan el salto de línea y el tabulador.
- **H-45.** El correo se normaliza (sin espacios alrededor y en minúsculas) antes de buscarlo o
  guardarlo: ``Ana@x.mx`` y ``ana@x.mx`` son la misma cuenta.
"""

from typing import Any

import pytest
from httpx import AsyncClient
from tests.integration.api.conftest import CONTRASENA, Escenario, assert_problema, login

from portero.db.models import User

NUEVA = "marcador-nueva-clave-larga"  # noqa: S105  # marcador de prueba, no un secreto

# --- H-44: caracteres de control -----------------------------------------------------------------

CASOS_CONTROL = [
    pytest.param("admin", "post", "/api/v1/projects", {"name": "p\u0000"}, id="proyecto-nombre"),
    pytest.param(
        "admin",
        "post",
        "/api/v1/projects",
        {"name": "p-ok", "description": "a\u0000b"},
        id="proyecto-descripcion",
    ),
    pytest.param(
        "lider_a", "patch", "/projects/{a}", {"description": "\u0001"}, id="proyecto-patch"
    ),
    pytest.param(
        "lider_a", "post", "/projects/{a}/environments", {"name": "qa\u0000"}, id="ambiente"
    ),
    pytest.param(
        "lider_a",
        "post",
        "/projects/{a}/environments/{a_dev}/secrets",
        {"name": "API_KEY", "value": "marcador", "description": "\u007f"},
        id="secreto-descripcion",
    ),
    pytest.param(
        "lider_a", "post", "/projects/{a}/service-accounts", {"name": "ci\u0000"}, id="sa-nombre"
    ),
    pytest.param(
        "admin",
        "post",
        "/api/v1/users",
        {"email": "n@example.com", "name": "N\u0000", "password": NUEVA},
        id="usuario-nombre",
    ),
    pytest.param(
        "admin",
        "post",
        "/api/v1/users",
        {"email": "n\u0000@example.com", "password": NUEVA},
        id="usuario-correo",
    ),
]


def _ruta(plantilla: str, esc: Escenario) -> str:
    ruta = plantilla.format(a=esc.a.id, a_dev=esc.a.dev)
    return ruta if ruta.startswith("/api/v1") else "/api/v1" + ruta


@pytest.mark.parametrize(("usuario", "metodo", "ruta", "cuerpo"), CASOS_CONTROL)
async def test_texto_con_caracteres_de_control_da_400(
    cliente: AsyncClient,
    escenario: Escenario,
    usuario: str,
    metodo: str,
    ruta: str,
    cuerpo: dict[str, Any],
) -> None:
    respuesta = await cliente.request(
        metodo.upper(), _ruta(ruta, escenario), json=cuerpo, headers=escenario.h(usuario)
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_login_con_nul_en_el_correo_da_400_sin_autenticarse(cliente: AsyncClient) -> None:
    respuesta = await cliente.post(
        "/api/v1/auth/login", json={"email": "ana\u0000@example.com", "password": CONTRASENA}
    )

    cuerpo = assert_problema(respuesta, 400, "validation-error")
    assert CONTRASENA not in str(cuerpo)


@pytest.mark.parametrize("parametro", ["verb", "resource_type"])
async def test_filtro_de_bitacora_con_nul_da_400(
    cliente: AsyncClient, escenario: Escenario, parametro: str
) -> None:
    respuesta = await cliente.get(
        "/api/v1/operations", params={parametro: "x\u0000"}, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_descripcion_conserva_salto_de_linea_y_tabulador(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    descripcion = "línea uno\nlínea\tdos\r\n"
    respuesta = await cliente.post(
        "/api/v1/projects",
        json={"name": "multilinea", "description": descripcion},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201
    assert respuesta.json()["description"] == descripcion


# --- H-45: correo normalizado ---------------------------------------------------------------------


async def test_alta_guarda_el_correo_en_minusculas(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        "/api/v1/users",
        json={"email": "  Nuevo@Example.COM ", "password": NUEVA},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201
    assert respuesta.json()["email"] == "nuevo@example.com"


async def test_alta_con_otra_capitalizacion_de_un_correo_existente_da_409(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        "/api/v1/users",
        json={"email": "DEV_A@Example.com", "password": NUEVA},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 409, "conflict")


async def test_login_no_distingue_mayusculas_en_el_correo(
    cliente: AsyncClient, usuario: User
) -> None:
    respuesta = await login(cliente, email=" ANA@Example.com ")

    assert respuesta.status_code == 200
