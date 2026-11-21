"""Pruebas de los endpoints de autenticación del API REST Gateway contra la app real y db-test
(Cap. 6 §Endpoints de autenticación, §Revocación y renovación de tokens; spec Fase 5 §3.1–3.5
y §6; H-25, H-36, H-37; RFC 6750; RFC 9457; OWASP ASVS V3.4).
"""

from datetime import UTC, datetime, timedelta

import jwt
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    CONTRASENA,
    COOKIE_REFRESH,
    RUTA_COOKIE,
    Asignacion,
    assert_problema,
    atributos_refresh,
    bearer,
    crear_usuario,
    login,
    valor_refresh,
)
from tests.integration.conftest import crear_alcance

from portero.db.models import User

ADMINISTRADOR = 1
DESARROLLADOR = 3
DETALLE_BEARER = "token inválido o expirado"
ETIQUETAS_INTERNAS = (
    "firma",
    "tipo",
    "revocado",
    "usuario_inactivo",
    "tokens_invalidados",
    "claim",
    "cabecera",
)


# --- POST /auth/login ----------------------------------------------------------------------------


async def test_login_correcto_devuelve_access_y_refresh_en_cookie(
    cliente: AsyncClient, usuario: User
) -> None:
    respuesta = await login(cliente)

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    # H-36: el refresh token NO viaja en el cuerpo.
    assert set(cuerpo) == {"access_token", "token_type", "expires_in"}
    assert cuerpo["token_type"] == "Bearer"  # noqa: S105  # esquema RFC 6750, no un secreto
    assert cuerpo["expires_in"] == 900
    assert cuerpo["access_token"]

    atributos = atributos_refresh(respuesta)
    assert atributos["httponly"] == "true"
    assert atributos["secure"] == "true"
    assert atributos["samesite"] == "strict"
    assert atributos["path"] == RUTA_COOKIE
    assert atributos["max-age"] == "1800"  # H-61: 30 min de inactividad (OWASP ASVS V3.3.2)
    assert valor_refresh(respuesta) not in respuesta.text


async def test_login_con_credenciales_malas_da_401_generico(
    cliente: AsyncClient, usuario: User
) -> None:
    mala = await login(cliente, password="marcador-prueba-clave-equivocada")  # noqa: S106
    inexistente = await login(cliente, email="nadie@example.com")

    cuerpo_mala = assert_problema(mala, 401, "authentication-failed")
    cuerpo_inexistente = assert_problema(inexistente, 401, "authentication-failed")
    # El mismo mensaje para las dos causas: no se revela si la cuenta existe (OWASP ASVS V2.2.1).
    assert cuerpo_mala["detail"] == cuerpo_inexistente["detail"]
    assert cuerpo_mala["title"] == cuerpo_inexistente["title"]
    assert "marcador-prueba-clave-equivocada" not in mala.text
    assert "set-cookie" not in mala.headers
    assert "set-cookie" not in inexistente.headers


async def test_login_con_campo_extra_da_400_sin_eco_de_la_contrasena(
    cliente: AsyncClient, usuario: User
) -> None:
    respuesta = await cliente.post(
        "/api/v1/auth/login",
        json={"email": "ana@example.com", "password": CONTRASENA, "is_admin": True},
    )

    cuerpo = assert_problema(respuesta, 400, "validation-error")
    # spec §6: solo ubicación y tipo de cada error, nunca el valor enviado.
    for error in cuerpo.get("errors", []):  # type: ignore[union-attr]
        assert set(error) <= {"loc", "type"}
    assert CONTRASENA not in respuesta.text


async def test_login_con_correo_mal_formado_da_400(cliente: AsyncClient) -> None:
    respuesta = await cliente.post(
        "/api/v1/auth/login", json={"email": "no-es-un-correo", "password": CONTRASENA}
    )

    assert_problema(respuesta, 400, "validation-error")
    assert CONTRASENA not in respuesta.text


# --- POST /auth/refresh --------------------------------------------------------------------------


async def test_refresh_con_cookie_emite_par_nuevo_y_cookie_nueva(
    cliente: AsyncClient, usuario: User
) -> None:
    primero = await login(cliente)

    respuesta = await cliente.post("/api/v1/auth/refresh")

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert set(cuerpo) == {"access_token", "token_type", "expires_in"}
    assert cuerpo["expires_in"] == 900
    assert cuerpo["access_token"] != primero.json()["access_token"]
    assert valor_refresh(respuesta) != valor_refresh(primero)
    assert atributos_refresh(respuesta)["path"] == RUTA_COOKIE
    # H-61: el refresh rotado conserva el inicio de la sesión y da otros 30 min; Max-Age es su
    # vida.
    viejo = jwt.decode(valor_refresh(primero), options={"verify_signature": False})
    nuevo = jwt.decode(valor_refresh(respuesta), options={"verify_signature": False})
    assert nuevo["auth_time"] == viejo["auth_time"] == viejo["iat"]
    assert nuevo["exp"] == nuevo["iat"] + 1800
    assert int(atributos_refresh(respuesta)["max-age"]) == nuevo["exp"] - nuevo["iat"]


async def test_refresh_sin_cookie_da_401_y_borra_la_cookie(cliente: AsyncClient) -> None:
    respuesta = await cliente.post("/api/v1/auth/refresh")

    assert_problema(respuesta, 401, "authentication-failed")
    atributos = atributos_refresh(respuesta)
    assert atributos["max-age"] == "0"
    assert atributos["path"] == RUTA_COOKIE


async def test_reusar_la_cookie_vieja_da_401(cliente: AsyncClient, usuario: User) -> None:
    viejo = valor_refresh(await login(cliente))
    assert (await cliente.post("/api/v1/auth/refresh")).status_code == 200
    cliente.cookies.clear()

    respuesta = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={viejo}"}
    )

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    assert "refresh_reused" not in str(cuerpo)


async def test_reusar_la_cookie_vieja_cierra_la_sesion_del_atacante(
    cliente: AsyncClient, usuario: User
) -> None:
    """H-43: el atacante canjea primero la cookie robada; cuando el dueño la reusa, el access y la
    cookie que obtuvo el atacante dejan de servir (reautenticación completa, Cap. 6)."""
    robada = valor_refresh(await login(cliente))
    canje = await cliente.post("/api/v1/auth/refresh")
    assert canje.status_code == 200
    access_atacante = canje.json()["access_token"]
    cookie_atacante = valor_refresh(canje)
    cliente.cookies.clear()

    reuso = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={robada}"}
    )
    assert reuso.status_code == 401

    me = await cliente.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_atacante}"}
    )
    assert_problema(me, 401, "authentication-failed")
    renovar = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={cookie_atacante}"}
    )
    assert_problema(renovar, 401, "authentication-failed")


async def test_refresh_token_en_el_cuerpo_no_se_acepta(cliente: AsyncClient, usuario: User) -> None:
    """H-36: el refresh solo se lee de la cookie; un cuerpo con él es un campo no esperado."""
    refresh = valor_refresh(await login(cliente))
    cliente.cookies.clear()

    respuesta = await cliente.post("/api/v1/auth/refresh", json={"refresh_token": refresh})

    assert respuesta.status_code in (400, 401)
    assert refresh not in respuesta.text


# --- POST /auth/logout ---------------------------------------------------------------------------


async def test_logout_borra_la_cookie_y_revoca_ambos_tokens(
    cliente: AsyncClient, usuario: User
) -> None:
    sesion = await login(cliente)
    access = sesion.json()["access_token"]
    refresh = valor_refresh(sesion)

    respuesta = await cliente.post("/api/v1/auth/logout", headers=bearer(access))

    assert respuesta.status_code == 204
    atributos = atributos_refresh(respuesta)
    assert atributos["max-age"] == "0"
    assert atributos["path"] == RUTA_COOKIE

    me = await cliente.get("/api/v1/auth/me", headers=bearer(access))
    assert_problema(me, 401, "authentication-failed")
    cliente.cookies.clear()
    otra = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={refresh}"}
    )
    assert_problema(otra, 401, "authentication-failed")


async def test_logout_sin_bearer_da_401(cliente: AsyncClient) -> None:
    respuesta = await cliente.post("/api/v1/auth/logout")

    assert_problema(respuesta, 401, "authentication-failed")


# --- GET /auth/me --------------------------------------------------------------------------------


async def test_me_devuelve_usuario_y_asignaciones(
    cliente: AsyncClient, db_session: AsyncSession
) -> None:
    alcance = await crear_alcance(db_session)
    user = await crear_usuario(
        db_session,
        asignaciones=(
            Asignacion(role_id=ADMINISTRADOR),
            Asignacion(
                role_id=DESARROLLADOR,
                project_id=alcance.project_id,
                environment_id=alcance.environment_id,
            ),
        ),
    )
    access = (await login(cliente)).json()["access_token"]

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(access))

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["id"] == str(user.id)
    assert cuerpo["email"] == "ana@example.com"
    assert cuerpo["name"] == "Ana"
    asignaciones = {
        (a["role_id"], a["role"], a["project_id"], a["environment_id"])
        for a in cuerpo["assignments"]
    }
    assert asignaciones == {
        (ADMINISTRADOR, "Administrador", None, None),
        (
            DESARROLLADOR,
            "Desarrollador",
            str(alcance.project_id),
            str(alcance.environment_id),
        ),
    }
    assert all("id" in a for a in cuerpo["assignments"])
    assert "password_hash" not in cuerpo


def _assert_401_bearer(respuesta_texto: str, cuerpo: dict[str, object]) -> None:
    assert cuerpo["detail"] == DETALLE_BEARER
    for etiqueta in ETIQUETAS_INTERNAS:
        assert etiqueta not in respuesta_texto


async def test_me_sin_token_da_401_con_www_authenticate(cliente: AsyncClient) -> None:
    respuesta = await cliente.get("/api/v1/auth/me")

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    assert respuesta.headers["www-authenticate"].startswith("Bearer")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_me_con_esquema_que_no_es_bearer_da_401(cliente: AsyncClient, usuario: User) -> None:
    access = (await login(cliente)).json()["access_token"]

    respuesta = await cliente.get("/api/v1/auth/me", headers={"Authorization": f"Basic {access}"})

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_me_con_token_alterado_da_401(cliente: AsyncClient, usuario: User) -> None:
    access = (await login(cliente)).json()["access_token"]
    # Cambia un carácter en medio de la firma (no el último, cuyos bits bajos pueden ignorarse).
    i = len(access) - 10
    alterado = access[:i] + ("A" if access[i] != "A" else "B") + access[i + 1 :]

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(alterado))

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    assert respuesta.headers["www-authenticate"].startswith("Bearer")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_me_con_refresh_como_bearer_da_401(cliente: AsyncClient, usuario: User) -> None:
    """H-25: el refresh token no autentica peticiones a la API."""
    refresh = valor_refresh(await login(cliente))

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(refresh))

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_me_con_usuario_desactivado_da_401(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    access = (await login(cliente)).json()["access_token"]
    usuario.is_active = False
    await db_session.commit()

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(access))

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_me_con_token_anterior_al_corte_da_401(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    """H-37: un token con ``iat`` anterior a ``tokens_invalid_before`` ya no sirve."""
    access = (await login(cliente)).json()["access_token"]
    usuario.tokens_invalid_before = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)
    await db_session.commit()

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(access))

    cuerpo = assert_problema(respuesta, 401, "authentication-failed")
    _assert_401_bearer(respuesta.text, cuerpo)


async def test_refresh_anterior_al_corte_da_401(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    """H-37 también en ``/auth/refresh`` (spec §3.5: la regla se aplica en dos lugares)."""
    await login(cliente)
    usuario.tokens_invalid_before = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)
    await db_session.commit()

    respuesta = await cliente.post("/api/v1/auth/refresh")

    assert_problema(respuesta, 401, "authentication-failed")
