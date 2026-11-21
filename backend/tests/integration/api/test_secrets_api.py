"""API de secretos (CU-02, CU-03, CU-04; spec Fase 5 §2, §4.1, §5.2–5.4, §6; H-11, H-13, H-14;
RNF-006).

Mismo escenario compartido (``conftest.escenario``). Las pruebas usan sobre todo tres usuarios:
el Líder de A (gestiona secretos en todo A), el Desarrollador de A/dev (solo ``secrets:read`` en
A/dev) y el Desarrollador de B/dev (A no le es visible).

Decisiones que fijan estas pruebas:

- Los secretos se siembran **por la API** (``POST`` como Líder de A), no llamando al
  ``SecretService``: así no dependen de la firma del servicio, que recibirá el actor de la
  bitácora.
- En las rutas de colección (``/projects/{pid}/environments/{eid}/secrets``) el recurso del
  ``access_denied`` es el ambiente padre (spec §4.1), igual que en las rutas de proyectos.
  En las rutas por identificador es el secreto.
- ``GET /secrets/{id}/versions`` lista de la versión más reciente a la más antigua, igual que
  ``/operations`` (la spec no fija el orden).
- Cada 404 de la regla H-14 se comprueba junto con su fila ``access_denied``. Un 404 de ruta
  inexistente no la produce, así que la prueba no pasa antes de que exista el endpoint.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    Escenario,
    assert_denegacion,
    assert_escritura,
    assert_problema,
    bearer,
    contar_registros,
    pat_de_a_dev,
    ultimo_registro,
)

from portero.config import Settings
from portero.crypto.signing import JwtSigner
from portero.db.models import AuditLog, Project, Secret
from portero.oplog.service import OperationEvent, OperationLogService

VALOR = "marcador-valor-s11-original"
VALOR_NUEVO = "marcador-valor-s11-rotado"
MAX_VALOR = 65_536  # 64 KiB (spec §1: SecretStr con max_length=65536)

CAMPOS_METADATOS = {
    "id",
    "name",
    "description",
    "version",
    "project_id",
    "environment_id",
    "created_at",
    "created_by",
    "updated_at",
}
CAMPOS_VALOR = {"id", "name", "value", "version"}
CAMPOS_ROTACION = {"id", "version", "rotated_at"}
CAMPOS_VERSION = {"version", "created_at", "created_by", "aead_algorithm"}
CAMPOS_ERROR_FIJOS = ("type", "title", "status", "detail")  # sin instance ni trace_id


# --- Auxiliares ----------------------------------------------------------------------------------


def _coleccion(project_id: UUID, environment_id: UUID) -> str:
    return f"/api/v1/projects/{project_id}/environments/{environment_id}/secrets"


def _secreto(secret_id: UUID | str, sufijo: str = "") -> str:
    return f"/api/v1/secrets/{secret_id}{sufijo}"


async def _crear(
    cliente: AsyncClient,
    esc: Escenario,
    environment_id: UUID,
    *,
    nombre: str = "DB_PASSWORD",
    valor: str = VALOR,
    usuario: str = "lider_a",
    project_id: UUID | None = None,
) -> dict[str, Any]:
    """Crea un secreto por la API y devuelve el cuerpo del 201."""
    respuesta = await cliente.post(
        _coleccion(project_id or esc.a.id, environment_id),
        json={"name": nombre, "value": valor},
        headers=esc.h(usuario),
    )
    assert respuesta.status_code == 201, respuesta.text
    cuerpo: dict[str, Any] = respuesta.json()
    return cuerpo


async def _rotar(
    cliente: AsyncClient, esc: Escenario, secret_id: str, valor: str, usuario: str = "lider_a"
) -> None:
    respuesta = await cliente.post(
        _secreto(secret_id, "/rotate"), json={"new_value": valor}, headers=esc.h(usuario)
    )
    assert respuesta.status_code == 200, respuesta.text


def _fijos(cuerpo: dict[str, Any]) -> dict[str, Any]:
    return {k: cuerpo[k] for k in CAMPOS_ERROR_FIJOS}


async def _contar_verbo(db_session: AsyncSession, verbo: str) -> int:
    stmt = select(func.count()).select_from(AuditLog).where(AuditLog.verb == verbo)
    return await db_session.scalar(stmt) or 0


# --- POST /projects/{pid}/environments/{eid}/secrets (CU-02) -------------------------------------


async def test_lider_crea_un_secreto_sin_devolver_el_valor(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    cuerpo = await _crear(cliente, escenario, escenario.a.dev)

    assert set(cuerpo) == CAMPOS_METADATOS  # sin value (spec §2)
    assert VALOR not in str(cuerpo)
    assert (cuerpo["name"], cuerpo["version"]) == ("DB_PASSWORD", 1)
    assert cuerpo["project_id"] == str(escenario.a.id)
    assert cuerpo["environment_id"] == str(escenario.a.dev)
    assert cuerpo["created_by"] == str(escenario.ids["lider_a"])
    await assert_escritura(
        db_session,
        verbo="create_secret",
        actor_id=escenario.ids["lider_a"],
        resource_type="secret",
        resource_id=UUID(cuerpo["id"]),
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )


async def test_desarrollador_no_crea_secretos(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """El Desarrollador solo tiene ``secrets:read``; su ambiente le es visible → 403."""
    respuesta = await cliente.post(
        _coleccion(escenario.a.id, escenario.a.dev),
        json={"name": "DB_PASSWORD", "value": VALOR},
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:write",
        status=403,
        project_id=escenario.a.id,
        resource_type="environment",
    )


@pytest.mark.parametrize("nombre", ["db_password", "1DB", "DB-PASS", "Db_Password", ""])
async def test_nombre_que_no_es_screaming_snake_case_es_400(
    cliente: AsyncClient, escenario: Escenario, nombre: str
) -> None:
    """Spec §1: ``name`` cumple ``^[A-Z][A-Z0-9_]*$``. Control: uno válido sí se crea."""
    respuesta = await cliente.post(
        _coleccion(escenario.a.id, escenario.a.dev),
        json={"name": nombre, "value": VALOR},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 400, "validation-error")
    await _crear(cliente, escenario, escenario.a.dev, nombre="API_KEY_2")


async def test_nombre_duplicado_en_el_ambiente_es_conflicto(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.post(
        _coleccion(escenario.a.id, escenario.a.dev),
        json={"name": "DB_PASSWORD", "value": VALOR_NUEVO},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 409, "conflict")
    assert VALOR_NUEVO not in respuesta.text


async def test_ambiente_de_otro_proyecto_en_la_ruta_es_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """El ambiente de B no existe "dentro" de A, ni siquiera para el Administrador."""
    respuesta = await cliente.post(
        _coleccion(escenario.a.id, escenario.b.dev),
        json={"name": "DB_PASSWORD", "value": VALOR},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    # Control: la ruta existe, el 404 no es de ruta inexistente.
    await _crear(cliente, escenario, escenario.b.dev, usuario="admin", project_id=escenario.b.id)


async def test_valor_de_mas_de_64_kib_es_400_sin_eco_del_valor(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """Spec §1 y §6: ``value`` con ``max_length=65536``; el 400 no repite la entrada."""
    largo = "m" * (MAX_VALOR + 1)
    respuesta = await cliente.post(
        _coleccion(escenario.a.id, escenario.a.dev),
        json={"name": "DB_PASSWORD", "value": largo},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 400, "validation-error")
    assert "m" * 100 not in respuesta.text
    # Control: exactamente 64 KiB sí se acepta.
    await _crear(cliente, escenario, escenario.a.dev, valor="m" * MAX_VALOR)


async def test_proyecto_inexistente_en_la_ruta_es_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Sin proyecto no hay recurso que proteger: 404 sin registro (spec §5.2)."""
    antes = await contar_registros(db_session)

    respuesta = await cliente.post(
        _coleccion(uuid4(), escenario.a.dev),
        json={"name": "DB_PASSWORD", "value": VALOR},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    assert await contar_registros(db_session) == antes


# --- GET /projects/{pid}/environments/{eid}/secrets (CU-03) --------------------------------------


async def test_listado_devuelve_solo_metadatos(cliente: AsyncClient, escenario: Escenario) -> None:
    await _crear(cliente, escenario, escenario.a.dev, nombre="DB_PASSWORD")
    await _crear(cliente, escenario, escenario.a.dev, nombre="API_KEY", valor=VALOR_NUEVO)
    await _crear(cliente, escenario, escenario.a.prod, nombre="SOLO_PROD")

    respuesta = await cliente.get(
        _coleccion(escenario.a.id, escenario.a.dev), headers=escenario.h("dev_a")
    )

    assert respuesta.status_code == 200
    lista = respuesta.json()
    assert isinstance(lista, list)
    assert {s["name"] for s in lista} == {"DB_PASSWORD", "API_KEY"}
    for item in lista:
        assert set(item) == CAMPOS_METADATOS
    assert VALOR not in respuesta.text
    assert VALOR_NUEVO not in respuesta.text


async def test_listado_de_un_ambiente_no_visible_es_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.get(
        _coleccion(escenario.a.id, escenario.a.prod), headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:read",
        status=404,
        project_id=escenario.a.id,
        resource_type="environment",
    )


# --- GET /secrets/{id} (CU-03) -------------------------------------------------------------------


async def test_desarrollador_lee_metadatos_de_su_ambiente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)
    antes = await contar_registros(db_session)

    respuesta = await cliente.get(_secreto(creado["id"]), headers=escenario.h("dev_a"))

    assert respuesta.status_code == 200
    assert set(respuesta.json()) == CAMPOS_METADATOS
    assert respuesta.json()["id"] == creado["id"]
    assert await contar_registros(db_session) == antes  # metadatos: no se registran (§5.2)


async def test_secreto_de_otro_ambiente_es_404_igual_que_uno_inexistente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-14: el Desarrollador de A/dev no distingue un secreto de A/prod de uno inexistente."""
    en_prod = await _crear(cliente, escenario, escenario.a.prod)

    oculto = await cliente.get(_secreto(en_prod["id"]), headers=escenario.h("dev_a"))
    cuerpo_oculto = assert_problema(oculto, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:read",
        status=404,
        project_id=escenario.a.id,
        resource_type="secret",
    )

    antes = await contar_registros(db_session)
    inexistente = await cliente.get(_secreto(uuid4()), headers=escenario.h("dev_a"))
    cuerpo_inexistente = assert_problema(inexistente, 404, "resource-not-found")

    assert _fijos(cuerpo_oculto) == _fijos(cuerpo_inexistente)
    assert await contar_registros(db_session) == antes  # inexistente: sin registro (§5.2)


async def test_secreto_de_un_proyecto_archivado_es_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Aunque el secreto siga activo, si su proyecto está archivado no existe para la API."""
    creado = await _crear(cliente, escenario, escenario.a.dev)
    visible = await cliente.get(_secreto(creado["id"]), headers=escenario.h("lider_a"))
    assert visible.status_code == 200

    proyecto = await db_session.get(Project, escenario.a.id)
    assert proyecto is not None
    proyecto.archived_at = datetime.now(UTC)
    await db_session.commit()

    for sufijo in ("", "/value"):
        respuesta = await cliente.get(
            _secreto(creado["id"], sufijo), headers=escenario.h("lider_a")
        )
        assert_problema(respuesta, 404, "resource-not-found")


# --- GET /secrets/{id}/value (CU-03; H-11, H-13) -------------------------------------------------


async def test_revelar_devuelve_el_valor_sin_cache_y_lo_registra(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.get(_secreto(creado["id"], "/value"), headers=escenario.h("dev_a"))

    assert respuesta.status_code == 200
    assert respuesta.json() == {
        "id": creado["id"],
        "name": "DB_PASSWORD",
        "value": VALOR,
        "version": 1,
    }
    assert set(respuesta.json()) == CAMPOS_VALOR
    assert "no-store" in respuesta.headers.get("cache-control", "")
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == ("read_secret", "success")
    assert (fila.actor_type, fila.actor_user_id) == ("human", escenario.ids["dev_a"])
    assert (fila.resource_type, fila.resource_id) == ("secret", UUID(creado["id"]))
    assert (fila.project_id, fila.environment_id) == (escenario.a.id, escenario.a.dev)
    assert fila.details is None or "value" not in fila.details


async def test_si_falla_el_registro_no_se_entrega_el_valor(
    cliente: AsyncClient,
    cliente_sin_relanzar: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H-11 (fail-closed): ``read_secret`` se registra antes de responder; si el registro falla,
    la respuesta es 500 y el valor no sale del servidor, ni al cliente ni al log."""
    creado = await _crear(cliente, escenario, escenario.a.dev)
    original = OperationLogService.record

    async def record_que_falla(
        self: OperationLogService, session: AsyncSession, event: OperationEvent
    ) -> AuditLog:
        if event.verb == "read_secret":
            raise RuntimeError("falla simulada del Servicio de Registro de Operaciones")
        return await original(self, session, event)

    monkeypatch.setattr(OperationLogService, "record", record_que_falla)
    caplog.set_level(logging.DEBUG)

    respuesta = await cliente_sin_relanzar.get(
        _secreto(creado["id"], "/value"), headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 500, "internal-error")
    assert VALOR not in respuesta.text
    assert await _contar_verbo(db_session, "read_secret") == 0
    assert VALOR not in caplog.text


async def test_un_pat_de_su_ambiente_revela_y_queda_registrado(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    """La lectura del SDK: el service account de A/dev revela; la bitácora lo registra como
    ``service``, sin ``actor_user_id`` (H-04)."""
    creado = await _crear(cliente, escenario, escenario.a.dev)
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.get(_secreto(creado["id"], "/value"), headers=bearer(pat))

    assert respuesta.status_code == 200
    assert respuesta.json()["value"] == VALOR
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.actor_type, fila.actor_user_id) == ("read_secret", "service", None)


# --- POST /secrets/{id}/rotate (CU-04) -----------------------------------------------------------


async def test_lider_rota_y_la_bitacora_guarda_ambas_versiones(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.post(
        _secreto(creado["id"], "/rotate"),
        json={"new_value": VALOR_NUEVO},
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert set(cuerpo) == CAMPOS_ROTACION
    assert (cuerpo["id"], cuerpo["version"]) == (creado["id"], 2)
    assert VALOR_NUEVO not in respuesta.text
    fila = await assert_escritura(
        db_session,
        verbo="rotate_secret",
        actor_id=escenario.ids["lider_a"],
        resource_type="secret",
        resource_id=UUID(creado["id"]),
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )
    assert fila.details == {"from_version": 1, "to_version": 2}

    revelado = await cliente.get(_secreto(creado["id"], "/value"), headers=escenario.h("dev_a"))
    assert (revelado.json()["value"], revelado.json()["version"]) == (VALOR_NUEVO, 2)


async def test_desarrollador_puede_leer_pero_no_rotar(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-14: el secreto le es visible (``secrets:read`` en A/dev) → 403, no 404."""
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.post(
        _secreto(creado["id"], "/rotate"),
        json={"new_value": VALOR_NUEVO},
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:rotate",
        status=403,
        project_id=escenario.a.id,
        resource_type="secret",
    )


async def test_desarrollador_de_otro_proyecto_no_ve_el_secreto_al_rotar(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-14: para el Desarrollador de B, el secreto de A no existe → 404."""
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.post(
        _secreto(creado["id"], "/rotate"),
        json={"new_value": VALOR_NUEVO},
        headers=escenario.h("dev_b"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_b"],
        permiso="secrets:rotate",
        status=404,
        project_id=escenario.a.id,
        resource_type="secret",
    )


# --- GET /secrets/{id}/versions ------------------------------------------------------------------


async def test_versiones_paginadas_por_cursor_sin_valores(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)
    await _rotar(cliente, escenario, creado["id"], VALOR_NUEVO)
    await _rotar(cliente, escenario, creado["id"], VALOR_NUEVO + "-3")
    ruta = _secreto(creado["id"], "/versions")

    primera = await cliente.get(ruta, params={"limit": 2}, headers=escenario.h("dev_a"))
    assert primera.status_code == 200
    pagina = primera.json()
    assert set(pagina) == {"items", "next_cursor"}
    assert [v["version"] for v in pagina["items"]] == [3, 2]  # la más reciente primero
    assert isinstance(pagina["next_cursor"], str)

    segunda = await cliente.get(
        ruta, params={"limit": 2, "cursor": pagina["next_cursor"]}, headers=escenario.h("dev_a")
    )
    assert segunda.status_code == 200
    assert [v["version"] for v in segunda.json()["items"]] == [1]
    assert segunda.json()["next_cursor"] is None

    for item in pagina["items"] + segunda.json()["items"]:
        assert set(item) == CAMPOS_VERSION
        assert item["aead_algorithm"] == "aes-256-gcm"
    for texto in (primera.text, segunda.text):
        assert VALOR not in texto
        assert VALOR_NUEVO not in texto


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"cursor": "no-es-un-cursor"},
        {"cursor": "azow"},  # base64url de "k:0": bien codificado, clave inválida
    ],
)
async def test_parametros_de_paginacion_invalidos_son_400(
    cliente: AsyncClient, escenario: Escenario, params: dict[str, object]
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.get(
        _secreto(creado["id"], "/versions"), params=params, headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_versiones_de_un_secreto_no_visible_son_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.get(_secreto(creado["id"], "/versions"), headers=escenario.h("dev_b"))

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_b"],
        permiso="secrets:read",
        status=404,
        project_id=escenario.a.id,
        resource_type="secret",
    )


# --- PATCH /secrets/{id} -------------------------------------------------------------------------


async def test_lider_actualiza_la_descripcion(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.patch(
        _secreto(creado["id"]),
        json={"description": "contraseña de la base de datos"},
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 200
    assert set(respuesta.json()) == CAMPOS_METADATOS
    assert respuesta.json()["description"] == "contraseña de la base de datos"
    fila = await assert_escritura(
        db_session,
        verbo="update_secret",
        actor_id=escenario.ids["lider_a"],
        resource_type="secret",
        resource_id=UUID(creado["id"]),
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )
    assert fila.details == {"fields": ["description"]}


async def test_desarrollador_no_actualiza_secretos(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.patch(
        _secreto(creado["id"]), json={"description": "x"}, headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:write",
        status=403,
        project_id=escenario.a.id,
        resource_type="secret",
    )


@pytest.mark.parametrize("campo", ["name", "value"])
async def test_patch_solo_admite_la_descripcion(
    cliente: AsyncClient, escenario: Escenario, campo: str
) -> None:
    """El valor solo cambia rotando (CU-04); ``extra="forbid"`` → 400."""
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.patch(
        _secreto(creado["id"]), json={campo: "OTRO_VALOR"}, headers=escenario.h("lider_a")
    )

    assert_problema(respuesta, 400, "validation-error")


# --- DELETE /secrets/{id} ------------------------------------------------------------------------


async def test_archivar_oculta_el_secreto_y_libera_el_nombre(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)
    secret_id = UUID(creado["id"])

    respuesta = await cliente.delete(_secreto(secret_id), headers=escenario.h("lider_a"))

    assert respuesta.status_code == 204
    await assert_escritura(
        db_session,
        verbo="archive_secret",
        actor_id=escenario.ids["lider_a"],
        resource_type="secret",
        resource_id=secret_id,
        project_id=escenario.a.id,
        environment_id=escenario.a.dev,
    )
    fila = await db_session.get(Secret, secret_id, populate_existing=True)
    assert fila is not None and fila.archived_at is not None  # archivado lógico, no borrado

    antes = await contar_registros(db_session)
    for sufijo in ("", "/value"):
        archivado = await cliente.get(_secreto(secret_id, sufijo), headers=escenario.h("lider_a"))
        assert_problema(archivado, 404, "resource-not-found")
    assert await contar_registros(db_session) == antes  # archivado: 404 sin registro

    nuevo = await _crear(cliente, escenario, escenario.a.dev, valor=VALOR_NUEVO)
    assert nuevo["id"] != creado["id"]


async def test_desarrollador_no_archiva_secretos(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    creado = await _crear(cliente, escenario, escenario.a.dev)

    respuesta = await cliente.delete(_secreto(creado["id"]), headers=escenario.h("dev_a"))

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="secrets:delete",
        status=403,
        project_id=escenario.a.id,
        resource_type="secret",
    )


# --- Sin fugas del valor (RNF-006; spec §6) ------------------------------------------------------


async def test_ni_value_ni_new_value_aparecen_en_los_logs(
    cliente: AsyncClient, escenario: Escenario, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    creado = await _crear(cliente, escenario, escenario.a.dev)
    revelado = await cliente.get(_secreto(creado["id"], "/value"), headers=escenario.h("dev_a"))
    assert revelado.status_code == 200
    await _rotar(cliente, escenario, creado["id"], VALOR_NUEVO)

    assert caplog.records, "se esperaba al menos un registro de log del flujo"
    assert VALOR not in caplog.text
    assert VALOR_NUEVO not in caplog.text


def test_los_esquemas_no_muestran_el_valor_en_su_repr() -> None:
    """``value`` y ``new_value`` son ``SecretStr``: ``repr`` y ``str`` muestran asteriscos.
    Import local: mientras el módulo no exista, solo falla esta prueba."""
    from pydantic import SecretStr

    from portero.api.v1.secrets import SecretCreate, SecretRotate

    crear = SecretCreate(name="DB_PASSWORD", value=VALOR)
    rotar = SecretRotate(new_value=VALOR_NUEVO)

    assert isinstance(crear.value, SecretStr)
    assert isinstance(rotar.new_value, SecretStr)
    for texto in (repr(crear), str(crear), repr(rotar), str(rotar)):
        assert VALOR not in texto
        assert VALOR_NUEVO not in texto
