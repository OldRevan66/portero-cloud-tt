"""API de proyectos y ambientes (CU-07; spec Fase 5 §2, §4.1, §4.2, §5; H-14, H-22, H-23c/d,
H-39; RF-030 a RF-032).

Escenario: proyectos A y B con sus tres ambientes, y cinco usuarios: Administrador global, Líder
de A, Desarrollador de A/dev, Líder de B y Desarrollador de B/dev. Los access tokens se emiten
directo con el firmante de la app (el login se prueba aparte), para no pagar un Argon2id por
usuario y por prueba.

Hoy toda ruta inexistente responde 404 ``resource-not-found``. Por eso cada 404 de la regla H-14
se comprueba **junto con** su fila ``access_denied``: sin eso, la prueba pasaría antes de que
existiera el endpoint.
"""

from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    AMBIENTES,
    Escenario,
    assert_denegacion,
    assert_escritura,
    assert_problema,
    bearer,
    contar_registros,
    pat_de_a_dev,
    ultimo_registro,
)
from tests.integration.conftest import actor_humano

from portero.config import Settings
from portero.crypto.signing import JwtSigner
from portero.db.models import Environment, Project, Secret
from portero.secrets_mgmt.service import SecretService

CAMPOS_PROYECTO = {"id", "name", "description", "created_at", "updated_at"}


async def _sembrar_secreto(
    db_session: AsyncSession, servicio: SecretService, esc: Escenario, environment_id: UUID
) -> UUID:
    ref = await servicio.create_secret(
        db_session,
        project_id=esc.a.id,
        environment_id=environment_id,
        name="DB_PASSWORD",
        value=bytearray(b"marcador-valor-de-prueba"),
        actor=actor_humano(esc.ids["admin"]),
    )
    return ref.secret_id


def _ids(respuesta_json: object) -> set[str]:
    assert isinstance(respuesta_json, list)
    return {item["id"] for item in respuesta_json}


# --- POST /projects ------------------------------------------------------------------------------


async def test_administrador_crea_proyecto_con_tres_ambientes(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        "/api/v1/projects",
        json={"name": "proyecto-nuevo", "description": "pruebas"},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201
    cuerpo = respuesta.json()
    assert set(cuerpo) == CAMPOS_PROYECTO
    assert (cuerpo["name"], cuerpo["description"]) == ("proyecto-nuevo", "pruebas")
    nuevo = UUID(cuerpo["id"])
    nombres = await db_session.scalars(
        select(Environment.name).where(Environment.project_id == nuevo)
    )
    assert set(nombres) == set(AMBIENTES)  # RF-031
    await assert_escritura(
        db_session,
        verbo="create_project",
        actor_id=escenario.ids["admin"],
        resource_type="project",
        resource_id=nuevo,
        project_id=nuevo,
    )


@pytest.mark.parametrize("usuario", ["lider_a", "dev_a"])
async def test_solo_el_administrador_crea_proyectos(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, usuario: str
) -> None:
    """``projects:manage`` con alcance de instancia (tabla maestra): un Líder no lo tiene."""
    respuesta = await cliente.post(
        "/api/v1/projects", json={"name": "proyecto-nuevo"}, headers=escenario.h(usuario)
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids[usuario],
        permiso="projects:manage",
        status=403,
        project_id=None,
    )


async def test_nombre_de_proyecto_repetido_es_conflicto(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        "/api/v1/projects", json={"name": "proyecto-a"}, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")


async def test_crear_proyecto_con_campo_extra_es_400(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        "/api/v1/projects",
        json={"name": "proyecto-nuevo", "owner": "otro"},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_crear_proyecto_sin_token_es_401(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await cliente.post("/api/v1/projects", json={"name": "proyecto-nuevo"})

    assert_problema(respuesta, 401, "authentication-failed")


# --- GET /projects -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("usuario", "visibles"),
    [
        ("admin", {"a", "b"}),
        ("lider_a", {"a"}),
        ("dev_a", {"a"}),
        ("dev_b", {"b"}),
    ],
)
async def test_cada_quien_ve_solo_sus_proyectos(
    cliente: AsyncClient, escenario: Escenario, usuario: str, visibles: set[str]
) -> None:
    """H-23c. El Administrador ve A y B y nada más: lo de otras pruebas se revierte."""
    respuesta = await cliente.get("/api/v1/projects", headers=escenario.h(usuario))

    assert respuesta.status_code == 200
    esperados = {str(getattr(escenario, p).id) for p in visibles}
    assert _ids(respuesta.json()) == esperados


async def test_un_proyecto_archivado_no_aparece_en_el_listado(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    borrado = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("lider_a")
    )
    assert borrado.status_code == 204

    respuesta = await cliente.get("/api/v1/projects", headers=escenario.h("admin"))

    assert _ids(respuesta.json()) == {str(escenario.b.id)}


# --- GET /projects/{pid} -------------------------------------------------------------------------


async def test_desarrollador_de_un_ambiente_ve_el_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    antes = await contar_registros(db_session)

    respuesta = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("dev_a")
    )

    assert respuesta.status_code == 200
    assert set(respuesta.json()) == CAMPOS_PROYECTO
    assert respuesta.json()["id"] == str(escenario.a.id)
    assert await contar_registros(db_session) == antes  # las lecturas de metadatos no se registran


async def test_proyecto_no_visible_es_404_y_se_registra(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-14: el Desarrollador de B no sabe si A existe (404, no 403)."""
    respuesta = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("dev_b")
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_b"],
        permiso="secrets:read",
        status=404,
        project_id=escenario.a.id,
    )


async def test_proyecto_inexistente_es_404_sin_registro(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """§5.2: si el recurso no existe, no hay nada que registrar."""
    antes = await contar_registros(db_session)
    # Primero una petición válida que demuestre que la ruta existe.
    existente = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("admin")
    )
    assert existente.status_code == 200

    respuesta = await cliente.get(f"/api/v1/projects/{uuid4()}", headers=escenario.h("admin"))

    assert_problema(respuesta, 404, "resource-not-found")
    assert await contar_registros(db_session) == antes


async def test_cuerpo_del_404_no_distingue_invisible_de_inexistente(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    # Control: la ruta existe (hoy, sin endpoint, ambos 404 serían de ruta inexistente).
    control = await cliente.get(f"/api/v1/projects/{escenario.b.id}", headers=escenario.h("dev_b"))
    assert control.status_code == 200

    invisible = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("dev_b")
    )
    inexistente = await cliente.get(f"/api/v1/projects/{uuid4()}", headers=escenario.h("dev_b"))

    sin_variables = [
        {k: v for k, v in r.json().items() if k not in ("instance", "trace_id")}
        for r in (invisible, inexistente)
    ]
    assert invisible.status_code == inexistente.status_code == 404
    assert sin_variables[0] == sin_variables[1]


@pytest.mark.parametrize("ruta", ["no-es-uuid", "11111111111141118111111111111111"])
async def test_uuid_mal_formado_en_la_ruta_es_400(
    cliente: AsyncClient, escenario: Escenario, ruta: str
) -> None:
    """Spec §1: solo la forma canónica de 36 caracteres; cualquier otra → 400 (no 422)."""
    respuesta = await cliente.get(f"/api/v1/projects/{ruta}", headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")


# --- PATCH /projects/{pid} -----------------------------------------------------------------------


async def test_lider_actualiza_su_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"description": "nueva descripción"},
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 200
    assert respuesta.json()["description"] == "nueva descripción"
    fila = await assert_escritura(
        db_session,
        verbo="update_project",
        actor_id=escenario.ids["lider_a"],
        resource_type="project",
        resource_id=escenario.a.id,
        project_id=escenario.a.id,
    )
    assert fila.details == {"fields": ["description"]}  # los nombres, no los valores


async def test_desarrollador_no_actualiza_el_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"description": "x"},
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


async def test_lider_de_otro_proyecto_recibe_404_al_actualizar(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"description": "x"},
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


async def test_actualizar_con_campo_extra_es_400(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"archived_at": None},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 400, "validation-error")


# --- DELETE /projects/{pid} (archivado lógico, RF-032) -------------------------------------------


async def test_lider_archiva_su_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("lider_a")
    )

    assert respuesta.status_code == 204
    await assert_escritura(
        db_session,
        verbo="archive_project",
        actor_id=escenario.ids["lider_a"],
        resource_type="project",
        resource_id=escenario.a.id,
        project_id=escenario.a.id,
    )
    proyecto = await db_session.get(Project, escenario.a.id, populate_existing=True)
    assert proyecto is not None and proyecto.archived_at is not None  # no se borra la fila

    despues = await cliente.get(f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("admin"))
    assert_problema(despues, 404, "resource-not-found")


async def test_desarrollador_no_archiva_el_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
    )


async def test_lider_de_otro_proyecto_recibe_404_al_archivar(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}", headers=escenario.h("lider_b")
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_b"],
        permiso="projects:manage",
        status=404,
        project_id=escenario.a.id,
    )


async def test_archivar_con_secretos_activos_exige_confirmacion(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    servicio_app: SecretService,
) -> None:
    """RF-032: sin ``?confirm=true`` → 409; con él se archivan el proyecto y sus secretos."""
    secret_id = await _sembrar_secreto(db_session, servicio_app, escenario, escenario.a.dev)
    ruta = f"/api/v1/projects/{escenario.a.id}"

    sin_confirmar = await cliente.delete(ruta, headers=escenario.h("lider_a"))
    assert_problema(sin_confirmar, 409, "conflict")

    confirmado = await cliente.delete(
        ruta, params={"confirm": "true"}, headers=escenario.h("lider_a")
    )
    assert confirmado.status_code == 204
    secreto = await db_session.get(Secret, secret_id, populate_existing=True)
    assert secreto is not None and secreto.archived_at is not None


# --- POST /projects/{pid}/environments -----------------------------------------------------------


async def test_lider_crea_un_ambiente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/environments",
        json={"name": "qa"},
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 201
    cuerpo = respuesta.json()
    assert (cuerpo["name"], cuerpo["project_id"]) == ("qa", str(escenario.a.id))
    nuevo = UUID(cuerpo["id"])
    await assert_escritura(
        db_session,
        verbo="create_environment",
        actor_id=escenario.ids["lider_a"],
        resource_type="environment",
        resource_id=nuevo,
        project_id=escenario.a.id,
        environment_id=nuevo,
    )


async def test_nombre_de_ambiente_duplicado_es_conflicto(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/environments",
        json={"name": "development"},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 409, "conflict")


async def test_desarrollador_no_crea_ambientes(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/environments",
        json={"name": "qa"},
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


async def test_lider_de_otro_proyecto_no_ve_el_padre_al_crear_ambiente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """§4.1: las rutas de colección aplican la regla 404/403 al recurso padre."""
    respuesta = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/environments",
        json={"name": "qa"},
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


# --- GET /projects/{pid}/environments ------------------------------------------------------------


async def test_desarrollador_de_dev_ve_solo_dev(cliente: AsyncClient, escenario: Escenario) -> None:
    """H-23d: con asignaciones solo de ambiente se listan únicamente esos ambientes."""
    respuesta = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}/environments", headers=escenario.h("dev_a")
    )

    assert respuesta.status_code == 200
    assert [e["name"] for e in respuesta.json()] == ["development"]


async def test_lider_ve_todos_los_ambientes(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}/environments", headers=escenario.h("lider_a")
    )

    assert respuesta.status_code == 200
    assert _ids(respuesta.json()) == {str(i) for i in escenario.a.ambientes.values()}


async def test_ambientes_de_un_proyecto_no_visible_son_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.get(
        f"/api/v1/projects/{escenario.a.id}/environments", headers=escenario.h("dev_b")
    )

    assert_problema(respuesta, 404, "resource-not-found")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_b"],
        permiso="secrets:read",
        status=404,
        project_id=escenario.a.id,
    )


# --- PATCH / DELETE /projects/{pid}/environments/{eid} -------------------------------------------


async def test_lider_actualiza_un_ambiente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    staging = escenario.a.ambientes["staging"]
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}/environments/{staging}",
        json={"description": "preproducción"},
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 200
    fila = await assert_escritura(
        db_session,
        verbo="update_environment",
        actor_id=escenario.ids["lider_a"],
        resource_type="environment",
        resource_id=staging,
        project_id=escenario.a.id,
        environment_id=staging,
    )
    assert fila.details == {"fields": ["description"]}


async def test_desarrollador_no_actualiza_su_ambiente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.a.dev}",
        json={"description": "x"},
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
        resource_type="environment",
    )


async def test_ambiente_de_otro_proyecto_en_la_ruta_es_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """El ambiente de B no existe "dentro" de A, ni siquiera para el Administrador."""
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.b.dev}",
        json={"description": "x"},
        headers=escenario.h("admin"),
    )
    valido = await cliente.patch(
        f"/api/v1/projects/{escenario.b.id}/environments/{escenario.b.dev}",
        json={"description": "x"},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    assert valido.status_code == 200  # la ruta existe: el 404 no es de ruta inexistente


async def test_lider_borra_un_ambiente_sin_secretos(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-39: los ambientes no tienen ``archived_at``; sin secretos se borran físicamente."""
    staging = escenario.a.ambientes["staging"]
    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{staging}",
        headers=escenario.h("lider_a"),
    )

    assert respuesta.status_code == 204
    await assert_escritura(
        db_session,
        verbo="delete_environment",
        actor_id=escenario.ids["lider_a"],
        resource_type="environment",
        resource_id=staging,
        project_id=escenario.a.id,
        environment_id=staging,
    )
    assert await db_session.get(Environment, staging, populate_existing=True) is None


async def test_desarrollador_no_borra_ambientes(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.a.dev}",
        headers=escenario.h("dev_a"),
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="projects:manage",
        status=403,
        project_id=escenario.a.id,
        resource_type="environment",
    )


async def test_borrar_un_ambiente_con_secretos_es_conflicto(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    servicio_app: SecretService,
) -> None:
    """H-39: ``secrets.environment_id`` no tiene CASCADE; con secretos → 409."""
    await _sembrar_secreto(db_session, servicio_app, escenario, escenario.a.dev)

    respuesta = await cliente.delete(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.a.dev}",
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 409, "conflict")
    assert await db_session.get(Environment, escenario.a.dev, populate_existing=True) is not None


# --- Aplicaciones Cliente (PAT) ------------------------------------------------------------------


async def test_pat_ve_solo_el_proyecto_de_su_scope(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.get("/api/v1/projects", headers=bearer(pat))

    assert respuesta.status_code == 200
    assert _ids(respuesta.json()) == {str(escenario.a.id)}


async def test_pat_no_gestiona_su_proyecto(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    """Un service account solo tiene ``secrets:read``: el proyecto le es visible → 403."""
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.post(
        f"/api/v1/projects/{escenario.a.id}/environments",
        json={"name": "qa"},
        headers=bearer(pat),
    )

    assert_problema(respuesta, 403, "permission-denied")
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.actor_type, fila.actor_user_id) == ("access_denied", "service", None)


# --- Renombres y nulos ---------------------------------------------------------------------------


async def test_renombrar_proyecto_a_un_nombre_existente_es_conflicto(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}",
        json={"name": "proyecto-b"},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 409, "conflict")


async def test_renombrar_ambiente_a_un_nombre_existente_es_conflicto(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}/environments/{escenario.a.ambientes['staging']}",
        json={"name": "production"},
        headers=escenario.h("lider_a"),
    )

    assert_problema(respuesta, 409, "conflict")


async def test_nombre_nulo_en_patch_es_400(cliente: AsyncClient, escenario: Escenario) -> None:
    """``name`` puede omitirse, pero no enviarse como ``null`` (la columna es NOT NULL)."""
    respuesta = await cliente.patch(
        f"/api/v1/projects/{escenario.a.id}", json={"name": None}, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 400, "validation-error")
