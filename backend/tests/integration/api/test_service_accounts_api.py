"""API de Aplicaciones Cliente (A-04; spec Fase 5 §2, §3.7, §4.1, §4.4, §5; spec núcleo §3.3;
H-09, H-14, H-21, H-23a, H-41; Cap. 6 §Autenticación de Aplicaciones Cliente).

Mismo escenario compartido (``conftest.escenario``). Las service accounts se gestionan con
``projects:manage`` en el proyecto (H-23a): el Administrador y el Líder del proyecto. Un
Desarrollador de A ve el proyecto (403); el Líder de B no lo ve (404, H-14).

Decisiones que fijan estas pruebas (sesión 12):

- El ``token`` solo aparece en el 201. En la BD solo queda ``token_hash = SHA-256(token)`` en hex
  y ``token_prefix`` (spec núcleo §3.3), que son los **últimos** 8 caracteres del token (H-42:
  los primeros son la cabecera del JWT, igual en todos).
- ``expires_at`` en el pasado y un ambiente de otro proyecto dan **422** ``semantic-error``
  (spec §1, §6): el cuerpo pasa el esquema, pero viola una regla de negocio.
- En la ruta de colección (``/projects/{pid}/service-accounts``), el recurso del
  ``access_denied`` es el proyecto padre (spec §4.1, como en proyectos y secretos). En las rutas
  por identificador es la service account.
- **H-41:** ``DELETE`` de un ambiente con alguna service account (vigente o revocada) → 409
  ``conflict``, igual que H-39 y sin migración. Las asignaciones de rol del ambiente se siguen
  borrando por CASCADE, y ``delete_environment`` las cuenta en ``details``
  (``{"removed_role_assignments": n}``).

Cada 404 de la regla H-14 se comprueba junto con su fila ``access_denied``. Un 404 de ruta
inexistente no la produce, así que la prueba no pasa antes de que exista el endpoint.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    Escenario,
    assert_denegacion,
    assert_escritura,
    assert_problema,
    bearer,
    ultimo_registro,
)

from portero.db.models import Environment, ServiceAccount, UserRoleAssignment
from portero.rbac.permissions import Role

CAMPOS_SA = {
    "id",
    "name",
    "project_id",
    "environment_id",
    "token_prefix",
    "created_at",
    "created_by",
    "last_used_at",
    "expires_at",
    "revoked_at",
}
VALOR = "marcador-valor-s12"


# --- Auxiliares ----------------------------------------------------------------------------------


def _coleccion(project_id: UUID) -> str:
    return f"/api/v1/projects/{project_id}/service-accounts"


def _sa(sid: UUID | str) -> str:
    return f"/api/v1/service-accounts/{sid}"


async def _crear_sa(
    cliente: AsyncClient,
    esc: Escenario,
    *,
    environment_id: UUID | None,
    usuario: str = "lider_a",
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Crea una service account en A por la API y devuelve el cuerpo del 201."""
    cuerpo: dict[str, Any] = {
        "name": "ci-despliegue",
        "environment_id": str(environment_id) if environment_id else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    respuesta = await cliente.post(_coleccion(esc.a.id), json=cuerpo, headers=esc.h(usuario))
    assert respuesta.status_code == 201, respuesta.text
    resultado: dict[str, Any] = respuesta.json()
    return resultado


async def _crear_secreto(cliente: AsyncClient, esc: Escenario, environment_id: UUID) -> str:
    respuesta = await cliente.post(
        f"/api/v1/projects/{esc.a.id}/environments/{environment_id}/secrets",
        json={"name": "DB_PASSWORD", "value": VALOR},
        headers=esc.h("lider_a"),
    )
    assert respuesta.status_code == 201, respuesta.text
    secret_id: str = respuesta.json()["id"]
    return secret_id


async def _cuenta(db_session: AsyncSession, sid: UUID | str) -> ServiceAccount:
    cuenta = await db_session.get(ServiceAccount, UUID(str(sid)), populate_existing=True)
    assert cuenta is not None
    return cuenta


def _claims(token: str) -> dict[str, Any]:
    """Claims sin verificar la firma: solo para inspeccionar ``exp`` (la firma la verifica la
    app en las pruebas que usan el PAT)."""
    claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
    return claims


# --- POST /projects/{pid}/service-accounts -------------------------------------------------------


async def test_lider_crea_service_account_y_recibe_el_token_una_vez(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    cuerpo = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)

    assert set(cuerpo) == CAMPOS_SA | {"token"}
    token, prefijo = cuerpo["token"], cuerpo["token_prefix"]
    assert prefijo == token[-8:]  # H-42: los últimos 8 caracteres (de la firma)
    assert (cuerpo["project_id"], cuerpo["environment_id"]) == (
        str(escenario.a.id),
        str(escenario.a.dev),
    )
    assert cuerpo["revoked_at"] is None

    cuenta = await _cuenta(db_session, cuerpo["id"])
    assert cuenta.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in (cuenta.token_hash, cuenta.token_prefix, cuenta.name)
    assert cuenta.created_by == escenario.ids["lider_a"]

    fila = await assert_escritura(
        db_session,
        verbo="create_service_account",
        actor_id=escenario.ids["lider_a"],
        resource_type="service_account",
        resource_id=cuenta.id,
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )
    assert token not in str(fila.details)
    assert cuenta.token_hash not in str(fila.details)


async def test_el_token_lleva_el_scope_y_sin_expires_at_no_lleva_exp(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """H-09: sin ``expires_at`` el claim ``exp`` se omite. Sin ambiente, el scope es todo A."""
    cuerpo = await _crear_sa(cliente, escenario, environment_id=None)

    claims = _claims(cuerpo["token"])
    assert "exp" not in claims
    assert (claims["actor_type"], claims["token_type"], claims["sub"]) == (
        "service",
        "service",
        cuerpo["id"],
    )
    assert claims["scope"] == {"project_id": str(escenario.a.id), "environment_id": None}


async def test_con_expires_at_el_token_lleva_exp(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    vence = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)

    cuerpo = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev, expires_at=vence)

    assert _claims(cuerpo["token"])["exp"] == int(vence.timestamp())
    assert datetime.fromisoformat(cuerpo["expires_at"]) == vence


async def test_expires_at_en_el_pasado_da_422(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={
            "name": "ci-vencida",
            "environment_id": str(escenario.a.dev),
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert await db_session.scalar(select(ServiceAccount.id)) is None


async def test_ambiente_de_otro_proyecto_da_422(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={"name": "ci-cruzada", "environment_id": str(escenario.b.dev)},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert await db_session.scalar(select(ServiceAccount.id)) is None


async def test_crear_con_campo_extra_da_400(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={"name": "ci", "environment_id": None, "token_hash": "0" * 64},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_desarrollador_no_crea_service_accounts(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={"name": "ci", "environment_id": str(escenario.a.dev)},
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
    )
    assert await db_session.scalar(select(ServiceAccount.id)) is None


async def test_lider_de_otro_proyecto_recibe_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={"name": "ci", "environment_id": str(escenario.a.dev)},
        headers=escenario.h("lider_b"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_b"],
        permiso="projects:manage",
        status=404,
        project_id=escenario.a.id,
    )
    assert await db_session.scalar(select(ServiceAccount.id)) is None


async def test_administrador_tambien_crea_service_accounts(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    cuerpo = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev, usuario="admin")

    assert cuerpo["created_by"] == str(escenario.ids["admin"])


# --- GET lista y detalle -------------------------------------------------------------------------


async def test_listar_y_consultar_no_devuelven_el_token(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)
    token_hash = (await _cuenta(db_session, creada["id"])).token_hash

    lista = await cliente.get(_coleccion(escenario.a.id), headers=escenario.h("lider_a"))
    detalle = await cliente.get(_sa(creada["id"]), headers=escenario.h("lider_a"))

    assert lista.status_code == 200
    assert [item["id"] for item in lista.json()] == [creada["id"]]
    assert all(set(item) == CAMPOS_SA for item in lista.json())
    assert detalle.status_code == 200
    assert set(detalle.json()) == CAMPOS_SA
    assert detalle.json()["token_prefix"] == creada["token_prefix"]
    for respuesta in (lista, detalle):
        assert creada["token"] not in respuesta.text
        assert token_hash not in respuesta.text


async def test_desarrollador_no_consulta_service_accounts(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)

    lista = await cliente.get(_coleccion(escenario.a.id), headers=escenario.h("dev_a"))
    assert_problema(lista, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
    )

    detalle = await cliente.get(_sa(creada["id"]), headers=escenario.h("dev_a"))
    assert_problema(detalle, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
        resource_type="service_account",
    )


async def test_lider_de_otro_proyecto_no_ve_la_service_account(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)

    respuesta = await cliente.get(_sa(creada["id"]), headers=escenario.h("lider_b"))

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_b"],
        permiso="projects:manage",
        status=404,
        project_id=escenario.a.id,
        resource_type="service_account",
    )


# --- Uso del PAT emitido ----------------------------------------------------------------------


async def test_el_pat_emitido_solo_lee_en_su_ambiente(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    dev = await _crear_secreto(cliente, escenario, escenario.a.dev)
    prod = await _crear_secreto(cliente, escenario, escenario.a.prod)
    pat = (await _crear_sa(cliente, escenario, environment_id=escenario.a.dev))["token"]

    lectura = await cliente.get(f"/api/v1/secrets/{dev}/value", headers=bearer(pat))
    otro_ambiente = await cliente.get(f"/api/v1/secrets/{prod}/value", headers=bearer(pat))
    rotacion = await cliente.post(
        f"/api/v1/secrets/{dev}/rotate",
        json={"new_value": "marcador-valor-s12-rotado"},
        headers=bearer(pat),
    )

    assert lectura.status_code == 200
    assert lectura.json()["value"] == VALOR
    assert_problema(otro_ambiente, 404, "resource-not-found")
    assert_problema(rotacion, 403, "permission-denied")


# --- DELETE /service-accounts/{sid} (H-21) ------------------------------------------------------


async def test_revocar_deja_sin_servicio_al_pat(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev = await _crear_secreto(cliente, escenario, escenario.a.dev)
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)
    pat = creada["token"]
    assert (
        await cliente.get(f"/api/v1/secrets/{dev}/value", headers=bearer(pat))
    ).status_code == 200

    respuesta = await cliente.delete(_sa(creada["id"]), headers=escenario.h("lider_a"))

    assert respuesta.status_code == 204
    cuenta = await _cuenta(db_session, creada["id"])
    assert cuenta.revoked_at is not None
    assert cuenta.revoked_by == escenario.ids["lider_a"]
    fila = await assert_escritura(
        db_session,
        verbo="revoke_service_account",
        actor_id=escenario.ids["lider_a"],
        resource_type="service_account",
        resource_id=cuenta.id,
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )
    assert pat not in str(fila.details)

    despues = await cliente.get(f"/api/v1/secrets/{dev}/value", headers=bearer(pat))
    assert_problema(despues, 401, "authentication-failed")  # H-21: revoked_at manda


async def test_revocar_dos_veces_es_idempotente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)
    primera = await cliente.delete(_sa(creada["id"]), headers=escenario.h("lider_a"))
    assert primera.status_code == 204
    revocada_en = (await _cuenta(db_session, creada["id"])).revoked_at

    segunda = await cliente.delete(_sa(creada["id"]), headers=escenario.h("admin"))

    assert segunda.status_code == 204
    cuenta = await _cuenta(db_session, creada["id"])
    assert cuenta.revoked_at == revocada_en  # la primera revocación no se sobrescribe
    assert cuenta.revoked_by == escenario.ids["lider_a"]


async def test_desarrollador_no_revoca(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creada = await _crear_sa(cliente, escenario, environment_id=escenario.a.dev)

    respuesta = await cliente.delete(_sa(creada["id"]), headers=escenario.h("dev_a"))

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
        resource_type="service_account",
    )
    assert (await _cuenta(db_session, creada["id"])).revoked_at is None


async def test_un_pat_no_gestiona_service_accounts(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Un service account solo tiene ``secrets:read`` (spec §4): no se crea otros PAT."""
    pat = (await _crear_sa(cliente, escenario, environment_id=None))["token"]

    respuesta = await cliente.post(
        _coleccion(escenario.a.id),
        json={"name": "ci-hija", "environment_id": None},
        headers=bearer(pat),
    )

    assert_problema(respuesta, 403, "permission-denied")
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.actor_type) == ("access_denied", "service")


# --- H-41: borrar un ambiente con service accounts -----------------------------------------------


async def test_borrar_ambiente_con_service_account_vigente_da_409(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    staging = escenario.a.ambientes["staging"]
    creada = await _crear_sa(cliente, escenario, environment_id=staging)

    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{staging}",
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 409, "conflict")
    assert await db_session.get(Environment, staging, populate_existing=True) is not None
    assert (await _cuenta(db_session, creada["id"])).revoked_at is None


async def test_borrar_ambiente_con_service_account_revocada_da_409(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """La revocada también cuenta: el CASCADE borraría su ``revoked_at`` y ``revoked_by``."""
    staging = escenario.a.ambientes["staging"]
    creada = await _crear_sa(cliente, escenario, environment_id=staging)
    revocar = await cliente.delete(_sa(creada["id"]), headers=escenario.h("lider_a"))
    assert revocar.status_code == 204

    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{staging}",
        headers=escenario.h("lider_a"),
    )

    cuerpo = assert_problema(respuesta, 409, "conflict")
    # H-49: no existe borrado de service accounts; el mensaje no puede pedir "bórralas".
    assert (
        cuerpo["detail"] == "el ambiente tiene o tuvo aplicaciones cliente y no se puede eliminar"
    )
    assert await db_session.get(Environment, staging, populate_existing=True) is not None
    assert await _cuenta(db_session, creada["id"]) is not None


async def test_borrar_ambiente_con_asignaciones_las_cuenta_en_la_bitacora(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Sin service accounts el borrado procede (H-39); las asignaciones del ambiente caen por
    CASCADE y ``delete_environment`` registra cuántas eran."""
    staging = escenario.a.ambientes["staging"]
    db_session.add(
        UserRoleAssignment(
            user_id=escenario.ids["dev_b"],
            role_id=Role.DESARROLLADOR,
            project_id=escenario.a.id,
            environment_id=staging,
        )
    )
    await db_session.commit()

    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{staging}",
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 204
    fila = await assert_escritura(
        db_session,
        verbo="delete_environment",
        actor_id=escenario.ids["lider_a"],
        resource_type="environment",
        resource_id=staging,
        project_id=escenario.a.id,
        environment_id=staging,
    )
    assert fila.details == {"removed_role_assignments": 1}
