"""API del Servicio de Registro de Operaciones (CU-06; Cap. 6 §Endpoints de operaciones; spec
Fase 5 §2, §4.1, §4.3, §5; H-12, H-14, H-23b; RF-019 a RF-021; OWASP ASVS V7.3.3).

Mismo escenario compartido (``conftest.escenario``). La bitácora se siembra con
``OperationLogService.record`` y un reloj fijo, para controlar ``event_timestamp``; así los
registros quedan en la cadena real (con su hash) y ``verify-chain`` los puede comprobar.

Decisiones que fijan estas pruebas (plan de la sesión 13):

- Cada registro se devuelve con los 13 campos del JSON canónico (spec §5.1) más ``id``,
  ``previous_hash`` y ``current_hash``.
- ``from`` y ``to`` son inclusivos sobre ``event_timestamp``; ``from > to`` → 400.
- Un ``project_id`` fuera de lo permitido para un Líder da una lista vacía (intersección), no 403.
- ``/operations/{id}`` lleva un entero (``audit_logs.id`` es BIGSERIAL). Sin ``audit:read`` en
  ningún contexto → 403 antes de cargar el registro (no revela si existe). Con ``audit:read``
  pero fuera de alcance → 404 con ``access_denied`` (``resource_type="audit_log"``).
- La base de pruebas puede tener registros previos: las aserciones se hacen sobre los ids
  sembrados (o con un rango de fechas que solo los contiene a ellos).
"""

import csv
import io
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.integration.api.conftest import (
    Escenario,
    assert_denegacion,
    assert_problema,
    bearer,
    contar_registros,
    pat_de_a_dev,
    ultimo_registro,
)

from portero.config import Settings
from portero.crypto.errors import SigningKeyError
from portero.crypto.kek import KdfParams
from portero.crypto.signing import JwtSigner, public_key_pem
from portero.db.models import AuditLog
from portero.db.repositories.audit import AuditRepository
from portero.main import create_app
from portero.oplog.service import OperationEvent, OperationLogService

RUTA = "/api/v1/operations"
RUTA_VERIFICAR = "/api/v1/operations/verify-chain"
RUTA_EXPORTAR = "/api/v1/operations/export"
INICIO = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
FIN = INICIO + timedelta(hours=6)

CAMPOS_REGISTRO = {
    "id",
    "event_timestamp",
    "actor_user_id",
    "actor_type",
    "actor_ref",
    "verb",
    "resource_type",
    "resource_id",
    "result",
    "ip_address",
    "user_agent",
    "project_id",
    "environment_id",
    "details",
    "previous_hash",
    "current_hash",
}
CAMPOS_REPORTE = {
    "verified_from",
    "verified_to",
    "total",
    "ok",
    "broken",
    "last_hash",
    # H-81: firma diaria del cierre de la cadena.
    "signing_configured",
    "signatures_total",
    "invalid_signatures",
    "missing_signatures",
    "last_signed_at",
    "last_signed_audit_id",
}
CAMPOS_ERROR_FIJOS = ("type", "title", "status", "detail")


# --- Siembra -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Sembrados:
    """Ids de los registros sembrados, por nombre."""

    ids: dict[str, int]

    def __getitem__(self, nombre: str) -> int:
        return self.ids[nombre]

    @property
    def todos(self) -> set[int]:
        return set(self.ids.values())

    def de(self, *nombres: str) -> set[int]:
        return {self.ids[n] for n in nombres}


async def _registrar(
    session: AsyncSession,
    cuando: datetime,
    *,
    verbo: str,
    actor: str,
    esc: Escenario,
    result: str = "success",
    resource_type: str | None = None,
    project_id: UUID | None = None,
    environment_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    servicio = OperationLogService(clock=lambda: cuando)
    fila = await servicio.record(
        session,
        OperationEvent(
            actor_type="human",
            actor_ref=f"{actor}@example.com",
            actor_user_id=esc.ids[actor],
            verb=verbo,
            result=result,
            resource_type=resource_type,
            project_id=project_id,
            environment_id=environment_id,
            details=details,
        ),
    )
    await session.commit()
    return fila.id


@pytest.fixture
async def sembrados(db_session: AsyncSession, escenario: Escenario) -> Sembrados:
    """Siete registros entre ``INICIO`` y ``FIN``, una hora entre cada uno: dos de instancia
    (sin proyecto), tres de A y dos de B."""
    a, b = escenario.a, escenario.b
    plan: Sequence[tuple[str, dict[str, Any]]] = [
        ("login_admin", {"verbo": "login", "actor": "admin", "resource_type": "user"}),
        (
            "crear_a",
            {
                "verbo": "create_secret",
                "actor": "lider_a",
                "resource_type": "secret",
                "project_id": a.id,
                "environment_id": a.dev,
            },
        ),
        (
            "denegado_a",
            {
                "verbo": "access_denied",
                "actor": "dev_a",
                "result": "failure",
                "resource_type": "secret",
                "project_id": a.id,
                "environment_id": a.dev,
                "details": {"permission": "secrets:rotate", "status": 403},
            },
        ),
        (
            "crear_b",
            {
                "verbo": "create_secret",
                "actor": "lider_b",
                "resource_type": "secret",
                "project_id": b.id,
                "environment_id": b.dev,
            },
        ),
        (
            "leer_b",
            {
                "verbo": "read_secret",
                "actor": "dev_b",
                "resource_type": "secret",
                "project_id": b.id,
                "environment_id": b.dev,
            },
        ),
        (
            "rotar_a",
            {
                "verbo": "rotate_secret",
                "actor": "lider_a",
                "resource_type": "secret",
                "project_id": a.id,
                "environment_id": a.dev,
                "details": {"from_version": 1, "to_version": 2},
            },
        ),
        ("crear_usuario", {"verbo": "create_user", "actor": "admin", "resource_type": "user"}),
    ]
    ids = {}
    for i, (nombre, campos) in enumerate(plan):
        ids[nombre] = await _registrar(
            db_session, INICIO + timedelta(hours=i), esc=escenario, **campos
        )
    return Sembrados(ids)


# --- Auxiliares HTTP -----------------------------------------------------------------------------


def _iso(momento: datetime) -> str:
    return momento.isoformat().replace("+00:00", "Z")


VENTANA = {"from": _iso(INICIO), "to": _iso(FIN)}
"""Rango que contiene solo los registros sembrados."""


async def _todas_las_paginas(
    cliente: AsyncClient, headers: dict[str, str], params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Recorre ``GET /operations`` hasta ``next_cursor = null``."""
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        consulta = {**(params or {}), "limit": 100}
        if cursor is not None:
            consulta["cursor"] = cursor
        respuesta = await cliente.get(RUTA, params=consulta, headers=headers)
        assert respuesta.status_code == 200, respuesta.text
        pagina = respuesta.json()
        assert set(pagina) == {"items", "next_cursor"}
        items.extend(pagina["items"])
        cursor = pagina["next_cursor"]
        if cursor is None:
            return items


def _ids(items: Sequence[dict[str, Any]]) -> list[int]:
    return [item["id"] for item in items]


def _fijos(cuerpo: dict[str, Any]) -> dict[str, Any]:
    return {k: cuerpo[k] for k in CAMPOS_ERROR_FIJOS}


async def _max_id(db_session: AsyncSession) -> int | None:
    return await db_session.scalar(select(func.max(AuditLog.id)))


# --- GET /operations: alcance (H-23b) ------------------------------------------------------------


async def test_administrador_ve_todo(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    items = await _todas_las_paginas(cliente, escenario.h("admin"))

    assert sembrados.todos <= set(_ids(items))  # incluidos los de instancia (sin proyecto)
    assert len(items) == await contar_registros(db_session)


async def test_lider_ve_solo_los_registros_de_su_proyecto(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    items = await _todas_las_paginas(cliente, escenario.h("lider_a"))

    assert set(_ids(items)) & sembrados.todos == sembrados.de("crear_a", "denegado_a", "rotar_a")
    assert {item["project_id"] for item in items} == {str(escenario.a.id)}


async def test_lider_no_obtiene_otro_proyecto_aunque_lo_filtre(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    items = await _todas_las_paginas(
        cliente, escenario.h("lider_a"), {"project_id": str(escenario.b.id)}
    )

    assert items == []


async def test_administrador_filtra_por_proyecto(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    items = await _todas_las_paginas(
        cliente, escenario.h("admin"), {"project_id": str(escenario.b.id)}
    )

    assert set(_ids(items)) & sembrados.todos == sembrados.de("crear_b", "leer_b")
    assert {item["project_id"] for item in items} == {str(escenario.b.id)}


async def test_desarrollador_recibe_403_y_queda_registrado(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    respuesta = await cliente.get(RUTA, headers=escenario.h("dev_a"))

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="audit:read",
        status=403,
        project_id=None,
        resource_type="audit_log",
    )


async def test_una_aplicacion_cliente_recibe_403(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.get(RUTA, headers=bearer(pat))

    assert_problema(respuesta, 403, "permission-denied")


async def test_sin_token_es_401(cliente: AsyncClient) -> None:
    respuesta = await cliente.get(RUTA)

    assert_problema(respuesta, 401, "authentication-failed")


# --- GET /operations: forma, orden y filtros -----------------------------------------------------


async def test_orden_descendente_y_campos_sin_valores(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    respuesta = await cliente.get(RUTA, params=VENTANA, headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    items = respuesta.json()["items"]
    assert _ids(items) == sorted(sembrados.todos, reverse=True)
    for item in items:
        assert set(item) == CAMPOS_REGISTRO
        assert len(item["current_hash"]) == 64
    rotacion = next(i for i in items if i["id"] == sembrados["rotar_a"])
    assert rotacion["verb"] == "rotate_secret"
    assert rotacion["details"] == {"from_version": 1, "to_version": 2}
    assert rotacion["actor_user_id"] == str(escenario.ids["lider_a"])
    assert rotacion["event_timestamp"].startswith("2026-10-01T14:00:00")


async def test_lo_listado_coincide_con_la_bd(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    respuesta = await cliente.get(RUTA, params=VENTANA, headers=escenario.h("admin"))

    fila = await db_session.get(AuditLog, sembrados["crear_a"])
    assert fila is not None
    item = next(i for i in respuesta.json()["items"] if i["id"] == fila.id)
    assert (item["previous_hash"], item["current_hash"]) == (fila.previous_hash, fila.current_hash)


@pytest.mark.parametrize(
    ("filtro", "esperados"),
    [
        ({"verb": "create_secret"}, ("crear_a", "crear_b")),
        ({"resource_type": "user"}, ("login_admin", "crear_usuario")),
        ({"result": "failure"}, ("denegado_a",)),
        ({"verb": "verbo_que_no_existe"}, ()),
    ],
)
async def test_filtros_simples(
    cliente: AsyncClient,
    escenario: Escenario,
    sembrados: Sembrados,
    filtro: dict[str, str],
    esperados: tuple[str, ...],
) -> None:
    items = await _todas_las_paginas(cliente, escenario.h("admin"), {**VENTANA, **filtro})

    assert set(_ids(items)) == sembrados.de(*esperados)


async def test_filtro_por_actor(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    filtro = {**VENTANA, "actor_user_id": str(escenario.ids["lider_a"])}

    items = await _todas_las_paginas(cliente, escenario.h("admin"), filtro)

    assert set(_ids(items)) == sembrados.de("crear_a", "rotar_a")


async def test_filtros_combinados_con_el_alcance_del_lider(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    items = await _todas_las_paginas(
        cliente, escenario.h("lider_a"), {**VENTANA, "verb": "create_secret"}
    )

    assert set(_ids(items)) == sembrados.de("crear_a")


async def test_rango_de_fechas_inclusivo(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    """``from`` = 10:00 y ``to`` = 12:00 incluyen los registros de 10:00, 11:00 y 12:00."""
    filtro = {
        "from": _iso(INICIO + timedelta(hours=1)),
        "to": _iso(INICIO + timedelta(hours=3)),
    }

    items = await _todas_las_paginas(cliente, escenario.h("admin"), filtro)

    assert set(_ids(items)) == sembrados.de("crear_a", "denegado_a", "crear_b")


async def test_rango_abierto_por_un_lado(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    desde = await _todas_las_paginas(
        cliente, escenario.h("admin"), {"from": _iso(INICIO + timedelta(hours=5))}
    )
    hasta = await _todas_las_paginas(
        cliente, escenario.h("admin"), {"to": _iso(INICIO + timedelta(hours=1))}
    )

    assert set(_ids(desde)) & sembrados.todos == sembrados.de("rotar_a", "crear_usuario")
    assert set(_ids(hasta)) & sembrados.todos == sembrados.de("login_admin", "crear_a")


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"cursor": "no-es-un-cursor"},
        {"actor_user_id": "no-es-uuid"},
        {"project_id": "no-es-uuid"},
        {"result": "quizas"},
        {"from": "ayer"},
        {"from": _iso(FIN), "to": _iso(INICIO)},  # from > to
    ],
)
async def test_parametros_invalidos_son_400(
    cliente: AsyncClient, escenario: Escenario, params: dict[str, object]
) -> None:
    respuesta = await cliente.get(RUTA, params=params, headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")


# --- Paginación por cursor -----------------------------------------------------------------------


async def test_paginacion_estable_ante_inserciones_nuevas(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    """El cursor codifica el último ``id`` entregado; los registros nuevos tienen ``id`` mayor y
    quedan "arriba", así que las páginas siguientes no se recorren ni repiten registros."""
    admin = escenario.h("admin")
    primera = await cliente.get(RUTA, params={**VENTANA, "limit": 3}, headers=admin)
    assert primera.status_code == 200
    vistos = _ids(primera.json()["items"])
    cursor = primera.json()["next_cursor"]
    assert len(vistos) == 3
    assert isinstance(cursor, str)

    nuevos = {
        await _registrar(
            db_session,
            INICIO + timedelta(minutes=30),  # dentro de la ventana
            verbo="logout",
            actor="admin",
            esc=escenario,
            resource_type="user",
        )
        for _ in range(2)
    }

    while cursor is not None:
        pagina = await cliente.get(
            RUTA, params={**VENTANA, "limit": 3, "cursor": cursor}, headers=admin
        )
        assert pagina.status_code == 200
        vistos.extend(_ids(pagina.json()["items"]))
        cursor = pagina.json()["next_cursor"]

    assert vistos == sorted(sembrados.todos, reverse=True)  # sin huecos ni duplicados
    assert not nuevos & set(vistos)


async def test_la_ultima_pagina_no_trae_cursor(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    respuesta = await cliente.get(
        RUTA, params={**VENTANA, "limit": 7}, headers=escenario.h("admin")
    )

    cuerpo = respuesta.json()
    assert len(cuerpo["items"]) == 7
    assert cuerpo["next_cursor"] is None  # igual que en las versiones de un secreto


# --- GET /operations/{id} ------------------------------------------------------------------------


async def test_administrador_consulta_un_registro(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    respuesta = await cliente.get(f"{RUTA}/{sembrados['leer_b']}", headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert set(cuerpo) == CAMPOS_REGISTRO
    assert (cuerpo["id"], cuerpo["verb"]) == (sembrados["leer_b"], "read_secret")


async def test_lider_consulta_un_registro_de_su_proyecto(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    respuesta = await cliente.get(f"{RUTA}/{sembrados['rotar_a']}", headers=escenario.h("lider_a"))

    assert respuesta.status_code == 200
    assert respuesta.json()["id"] == sembrados["rotar_a"]


@pytest.mark.parametrize(("registro", "proyecto"), [("crear_b", "b"), ("login_admin", None)])
async def test_registro_fuera_del_alcance_es_404_igual_que_uno_inexistente(
    cliente: AsyncClient,
    escenario: Escenario,
    sembrados: Sembrados,
    db_session: AsyncSession,
    registro: str,
    proyecto: str | None,
) -> None:
    """H-14 y H-23b: un registro de B, o uno de instancia, no es visible para el Líder de A."""
    inexistente = await cliente.get(f"{RUTA}/{2**62}", headers=escenario.h("lider_a"))
    assert_problema(inexistente, 404, "resource-not-found")
    total = await contar_registros(db_session)  # el inexistente no se registra

    respuesta = await cliente.get(f"{RUTA}/{sembrados[registro]}", headers=escenario.h("lider_a"))

    cuerpo = assert_problema(respuesta, 404, "resource-not-found")
    assert _fijos(cuerpo) == _fijos(inexistente.json())
    assert await contar_registros(db_session) == total + 1
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_a"],
        permiso="audit:read",
        status=404,
        project_id=escenario.b.id if proyecto == "b" else None,
        resource_type="audit_log",
    )


async def test_inexistente_no_se_registra(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    total = await contar_registros(db_session)

    respuesta = await cliente.get(f"{RUTA}/{2**62}", headers=escenario.h("admin"))

    assert_problema(respuesta, 404, "resource-not-found")
    assert await contar_registros(db_session) == total


@pytest.mark.parametrize("registro", ["denegado_a", None])
async def test_desarrollador_recibe_403_por_identificador(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, registro: str | None
) -> None:
    """Sin ``audit:read`` en ningún contexto → 403 antes de cargar el registro, exista o no
    (incluso uno de su propio ambiente)."""
    log_id = sembrados[registro] if registro else 2**62

    respuesta = await cliente.get(f"{RUTA}/{log_id}", headers=escenario.h("dev_a"))

    assert_problema(respuesta, 403, "permission-denied")


@pytest.mark.parametrize("log_id", ["abc", "1.5", "3f2b8a4c-1d2e-4f5a-9b6c-7d8e9f0a1b2c"])
async def test_identificador_no_entero_es_400(
    cliente: AsyncClient, escenario: Escenario, log_id: str
) -> None:
    respuesta = await cliente.get(f"{RUTA}/{log_id}", headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")


# --- POST /operations/verify-chain ---------------------------------------------------------------


async def test_administrador_verifica_la_cadena_integra(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    total = await contar_registros(db_session)
    ultimo = await _max_id(db_session)

    respuesta = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    reporte = respuesta.json()
    assert set(reporte) == CAMPOS_REPORTE
    assert (reporte["ok"], reporte["broken"]) == (True, [])
    assert (reporte["total"], reporte["verified_to"]) == (total, ultimo)
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == ("verify_chain", "success")
    # H-46: el ancla es el hash de la última fila verificada, también en la bitácora.
    verificada = await db_session.scalar(select(AuditLog.current_hash).where(AuditLog.id == ultimo))
    assert reporte["last_hash"] == verificada
    assert fila.details == {
        "total": total,
        "broken_count": 0,
        "last_hash": verificada,
        "signatures_total": 0,
        "invalid_signatures_count": 0,
        "missing_signatures_count": 0,
    }
    # H-81: sin PORTERO_OPLOG_SIGNING_PUBLIC_KEY la firma diaria no está configurada.
    assert (reporte["signing_configured"], reporte["last_signed_at"]) == (False, None)
    assert (fila.actor_type, fila.actor_user_id) == ("human", escenario.ids["admin"])
    assert fila.project_id is None


async def test_con_la_llave_publica_el_reporte_trae_la_ultima_firma_valida(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
    escenario: Escenario,
    sembrados: Sembrados,
    db_session: AsyncSession,
) -> None:
    """H-81: la API carga solo la llave pública; la firma la hace ``sign-chain`` con la privada,
    que la API nunca recibe."""
    llave = Ed25519PrivateKey.generate()
    firma = await OperationLogService().sign_chain(db_session, llave)
    con_firma = settings_app.model_copy(
        update={"oplog_signing_public_key": public_key_pem(llave.public_key()).decode()}
    )
    aplicacion = create_app(
        con_firma, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas
    )
    async with (
        aplicacion.router.lifespan_context(aplicacion),
        AsyncClient(transport=ASGITransport(app=aplicacion), base_url="https://test") as cliente,
    ):
        respuesta = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    reporte = respuesta.json()
    assert reporte["ok"] is True
    assert reporte["signing_configured"] is True
    assert reporte["last_signed_audit_id"] == firma.last_audit_id
    assert datetime.fromisoformat(reporte["last_signed_at"]) == firma.created_at
    assert (reporte["invalid_signatures"], reporte["missing_signatures"]) == ([], [])


async def test_llave_publica_invalida_impide_arrancar(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    """Fallar temprano (OWASP ASVS V14.1): mejor no arrancar que reportar firmas "inválidas"."""
    mala = settings_app.model_copy(update={"oplog_signing_public_key": "marcador-no-es-pem"})
    aplicacion = create_app(
        mala, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas
    )

    with pytest.raises(SigningKeyError):
        async with aplicacion.router.lifespan_context(aplicacion):
            pass


async def test_una_fila_alterada_aparece_en_el_reporte(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    """Manipulación directa en la BD, como la haría alguien con acceso a PostgreSQL: la fila
    alterada (y solo ella) queda en ``broken`` (RF-021; OWASP ASVS V7.3.3)."""
    antes = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("admin"))
    assert antes.json()["ok"] is True
    alterada = sembrados["crear_b"]
    await db_session.execute(
        text("UPDATE audit_logs SET actor_ref = 'alterado@example.com' WHERE id = :id"),
        {"id": alterada},
    )
    await db_session.commit()

    respuesta = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    reporte = respuesta.json()
    assert (reporte["ok"], reporte["broken"]) == (False, [alterada])
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == ("verify_chain", "failure")


async def test_lider_no_verifica_la_cadena(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    """Solo con ``audit:read`` de instancia (spec §4.3): el Líder tiene ``audit:read`` en A, pero
    la cadena es de toda la instancia."""
    respuesta = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("lider_a"))

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_a"],
        permiso="audit:read",
        status=403,
        project_id=None,
        resource_type="audit_log",
    )


async def test_desarrollador_no_verifica_la_cadena(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(RUTA_VERIFICAR, headers=escenario.h("dev_a"))

    assert_problema(respuesta, 403, "permission-denied")


# --- GET /operations/export (RF-021; H-83) -------------------------------------------------------
#
# Mismos filtros, permiso y alcance que GET /operations (H-23b); descarga como adjunto; lotes con
# la paginación keyset del repositorio (no carga toda la tabla, a diferencia de H-50); el CSV
# neutraliza fórmulas (OWASP CSV Injection); la exportación se registra como
# ``export_operations`` y es una instantánea: solo lleva lo anterior a su propio registro.

ADJUNTO = re.compile(r'attachment; filename="bitacora-\d{8}T\d{6}Z\.(csv|json)"')
FORMULA = '=HYPERLINK("http://atacante.example/x","clic")'


def _filas_csv(texto: str) -> list[dict[str, str]]:
    assert texto.startswith("\ufeff")  # BOM de UTF-8 (Excel)
    return list(csv.DictReader(io.StringIO(texto.removeprefix("\ufeff"), newline="")))


async def _exportar(
    cliente: AsyncClient,
    headers: dict[str, str],
    formato: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """Exporta y devuelve las filas (CSV como dicts de texto, JSON como lista)."""
    respuesta = await cliente.get(
        RUTA_EXPORTAR, params={**(params or {}), "format": formato}, headers=headers
    )
    assert respuesta.status_code == 200, respuesta.text
    disposicion = ADJUNTO.fullmatch(respuesta.headers["content-disposition"])
    assert disposicion is not None, respuesta.headers["content-disposition"]
    assert disposicion.group(1) == formato
    assert respuesta.headers["cache-control"] == "no-store"
    if formato == "csv":
        assert respuesta.headers["content-type"] == "text/csv; charset=utf-8"
        return _filas_csv(respuesta.text)
    assert respuesta.headers["content-type"] == "application/json"
    return json.loads(respuesta.text)


def _ids_csv(filas: Sequence[dict[str, str]]) -> list[int]:
    return [int(f["id"]) for f in filas]


async def test_administrador_exporta_csv_lo_mismo_que_lista(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    listado = await _todas_las_paginas(cliente, escenario.h("admin"), VENTANA)

    filas = await _exportar(cliente, escenario.h("admin"), "csv", VENTANA)

    assert _ids_csv(filas) == _ids(listado)  # mismo orden: id descendente
    assert set(_ids(listado)) == sembrados.todos
    assert set(filas[0]) == CAMPOS_REGISTRO


async def test_administrador_exporta_json_con_los_campos_de_operation_out(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    listado = await _todas_las_paginas(cliente, escenario.h("admin"), VENTANA)

    items = await _exportar(cliente, escenario.h("admin"), "json", VENTANA)

    assert _ids(items) == _ids(listado)
    assert all(set(item) == CAMPOS_REGISTRO for item in items)
    rotado = next(item for item in items if item["id"] == sembrados["rotar_a"])
    assert rotado["details"] == {"from_version": 1, "to_version": 2}


async def test_lider_exporta_solo_su_proyecto(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    filas = await _exportar(cliente, escenario.h("lider_a"), "csv", VENTANA)

    assert set(_ids_csv(filas)) == sembrados.de("crear_a", "denegado_a", "rotar_a")
    assert {f["project_id"] for f in filas} == {str(escenario.a.id)}


@pytest.mark.parametrize("formato", ["csv", "json"])
async def test_lider_no_exporta_otro_proyecto_aunque_lo_filtre(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, formato: str
) -> None:
    filas = await _exportar(
        cliente, escenario.h("lider_a"), formato, {"project_id": str(escenario.b.id)}
    )

    assert filas == []  # CSV: solo el encabezado; JSON: []


async def test_exportacion_aplica_los_filtros(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados
) -> None:
    filas = await _exportar(
        cliente, escenario.h("admin"), "csv", {**VENTANA, "verb": "create_secret"}
    )

    assert set(_ids_csv(filas)) == sembrados.de("crear_a", "crear_b")


async def test_desarrollador_no_exporta_y_queda_registrado(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    respuesta = await cliente.get(
        RUTA_EXPORTAR, params={"format": "csv"}, headers=escenario.h("dev_a")
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["dev_a"],
        permiso="audit:read",
        status=403,
        project_id=None,
        resource_type="audit_log",
    )


async def test_una_aplicacion_cliente_no_exporta(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.get(RUTA_EXPORTAR, params={"format": "json"}, headers=bearer(pat))

    assert_problema(respuesta, 403, "permission-denied")


async def test_exportar_sin_token_es_401(cliente: AsyncClient) -> None:
    respuesta = await cliente.get(RUTA_EXPORTAR, params={"format": "csv"})

    assert_problema(respuesta, 401, "authentication-failed")


@pytest.mark.parametrize(
    "params",
    [
        {},  # sin format
        {"format": "xml"},
        {"format": "CSV"},
        {"format": "csv", "project_id": "no-es-uuid"},
        {"format": "csv", "from": _iso(FIN), "to": _iso(INICIO)},  # from > to
    ],
)
async def test_parametros_invalidos_de_exportacion_son_400(
    cliente: AsyncClient, escenario: Escenario, params: dict[str, object], db_session: AsyncSession
) -> None:
    antes = await contar_registros(db_session)

    respuesta = await cliente.get(RUTA_EXPORTAR, params=params, headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")
    assert await contar_registros(db_session) == antes  # un 400 no exporta ni registra


async def test_la_exportacion_se_registra_con_sus_filtros(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    params = {**VENTANA, "verb": "create_secret", "project_id": str(escenario.a.id)}

    await _exportar(cliente, escenario.h("lider_a"), "json", params)

    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == ("export_operations", "success")
    assert (fila.actor_type, fila.actor_user_id) == ("human", escenario.ids["lider_a"])
    assert (fila.resource_type, fila.resource_id) == (None, None)
    assert fila.project_id is None  # evento de instancia: lo supervisa el Administrador
    assert fila.details is not None
    assert set(fila.details) == {"format", "filters"}
    assert fila.details["format"] == "json"
    filtros = fila.details["filters"]
    assert set(filtros) == {"verb", "project_id", "from", "to"}  # solo los que se pidieron
    assert (filtros["verb"], filtros["project_id"]) == ("create_secret", str(escenario.a.id))
    assert datetime.fromisoformat(filtros["from"]) == INICIO
    assert datetime.fromisoformat(filtros["to"]) == FIN


async def test_la_exportacion_es_una_instantanea_anterior_a_su_registro(
    cliente: AsyncClient, escenario: Escenario, sembrados: Sembrados, db_session: AsyncSession
) -> None:
    filas = await _exportar(cliente, escenario.h("admin"), "csv")

    registro = await ultimo_registro(db_session)
    assert registro.verb == "export_operations"
    ids = _ids_csv(filas)
    assert ids == sorted(ids, reverse=True)
    assert max(ids) < registro.id  # no se incluye a sí misma
    assert len(ids) == await contar_registros(db_session) - 1  # todo lo anterior, sin huecos


async def test_la_exportacion_va_por_lotes(
    cliente: AsyncClient,
    escenario: Escenario,
    sembrados: Sembrados,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Con lotes de 2, los 7 registros de la ventana salen en 4 consultas de a lo más 2 filas:
    nunca se pide la tabla completa (H-50)."""
    monkeypatch.setattr("portero.oplog.service.EXPORT_BATCH_SIZE", 2)
    original = AuditRepository.list_page
    limites: list[int] = []

    async def espia(
        self: AuditRepository, query: Any, *, limit: int, before: int | None
    ) -> Sequence[AuditLog]:
        limites.append(limit)
        return await original(self, query, limit=limit, before=before)

    monkeypatch.setattr(AuditRepository, "list_page", espia)

    filas = await _exportar(cliente, escenario.h("admin"), "json", VENTANA)

    assert set(_ids(filas)) == sembrados.todos
    assert len(limites) >= 4
    assert all(limite <= 2 for limite in limites)


async def test_el_csv_neutraliza_un_user_agent_con_formula(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Vector realista: sin autenticarse, cualquiera deja su ``User-Agent`` en un
    ``login_failed``. En el CSV del Administrador debe salir como texto, no como fórmula."""
    fallido = await cliente.post(
        "/api/v1/auth/login",
        json={"email": "nadie@example.com", "password": "contrasena-equivocada"},
        headers={"User-Agent": FORMULA},
    )
    assert fallido.status_code == 401
    intento = await ultimo_registro(db_session)
    assert (intento.verb, intento.user_agent) == ("login_failed", FORMULA)

    filas = await _exportar(cliente, escenario.h("admin"), "csv", {"verb": "login_failed"})

    fila = next(f for f in filas if int(f["id"]) == intento.id)
    assert fila["user_agent"] == "'" + FORMULA
    json_items = await _exportar(cliente, escenario.h("admin"), "json", {"verb": "login_failed"})
    assert next(i for i in json_items if i["id"] == intento.id)["user_agent"] == FORMULA
