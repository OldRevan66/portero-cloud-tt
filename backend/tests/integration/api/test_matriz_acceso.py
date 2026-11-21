"""Matriz completa de control de acceso: endpoint × actor (spec Fase 5 §2 y §4; H-14, H-23,
H-25, H-21; OWASP ASVS V4.1.1, V4.1.3, V4.2.1).

Cada ruta de ``/api/v1`` tiene una fila en ``MATRIZ`` con el código esperado para cada uno de
los nueve actores. ``test_la_matriz_cubre_todas_las_rutas`` compara las llaves con
``app.routes``: agregar un endpoint sin decidir quién puede usarlo hace fallar la suite.

Recursos sembrados, todos del proyecto A (``recursos``): un secreto en A/development, una
service account de A/development (la del PAT vigente), la asignación de ``dev_a`` y un registro
de bitácora con ``project_id`` = A. ``A/staging`` queda vacío para poder borrarlo.

Actores:

- Cuatro que **no se autentican** (401 en toda ruta no pública): anónimo, access token con la
  firma alterada, refresh token usado como Bearer (H-25) y PAT de una service account revocada
  (H-21).
- Cinco autenticados: PAT de A/development, Desarrollador de A/development, Líder de A, Líder
  de B y Administrador (fixture ``escenario``).

Regla 404/403 (H-14, spec §4.1): sobre recursos de A, el Líder de B recibe 404 (no los ve) y el
Desarrollador de A o el PAT reciben 403 cuando ven el recurso pero les falta el permiso. Cada
celda 404 compara además su cuerpo con el de un identificador inexistente pedido por el mismo
actor: deben ser iguales salvo ``trace_id`` e ``instance``.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.routing import iter_route_contexts
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    CONTRASENA,
    Escenario,
    assert_problema,
    bearer,
    crear_usuario,
    pat_de_a_dev,
)
from tests.integration.conftest import actor_humano

from portero.auth.passwords import hash_password
from portero.auth.tokens import issue_refresh_token, issue_service_token
from portero.config import Settings
from portero.crypto.signing import JwtSigner
from portero.db.models import ServiceAccount, User, UserRoleAssignment
from portero.oplog.service import OperationEvent, OperationLogService
from portero.secrets_mgmt.service import SecretService

API = "/api/v1"

NO_AUTENTICABLES = ("anonimo", "firma_alterada", "refresh_como_bearer", "pat_revocado")
AUTENTICADOS = ("pat_a_dev", "dev_a", "lider_a", "lider_b", "admin")
HUMANOS = ("dev_a", "lider_a", "lider_b", "admin")
ACTORES = NO_AUTENTICABLES + AUTENTICADOS

TIPO_POR_ESTADO = {
    401: "authentication-failed",
    403: "permission-denied",
    404: "resource-not-found",
}

ID_REGISTRO_INEXISTENTE = 2_000_000_000


# --- Recursos ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Recursos:
    esc: Escenario
    secreto: UUID
    cuenta: UUID  # service account del PAT vigente (A/development)
    asignacion: UUID  # asignación de dev_a
    registro: int  # registro de bitácora del proyecto A
    cabeceras: dict[str, dict[str, str]]

    @property
    def a(self) -> UUID:
        return self.esc.a.id


def _firma_alterada(token: str) -> str:
    """Cambia un carácter **en medio** de la firma. El último carácter de una firma Ed25519 en
    base64url lleva bits de relleno: cambiarlo podría no alterar la firma decodificada."""
    cabecera, carga, firma = token.split(".")
    i = len(firma) // 2
    otro = "A" if firma[i] != "A" else "B"
    return ".".join((cabecera, carga, firma[:i] + otro + firma[i + 1 :]))


@pytest.fixture
async def recursos(
    db_session: AsyncSession,
    escenario: Escenario,
    signer_app: JwtSigner,
    settings_app: Settings,
    servicio_app: SecretService,
) -> Recursos:
    esc = escenario
    ref = await servicio_app.create_secret(
        db_session,
        project_id=esc.a.id,
        environment_id=esc.a.dev,
        name="DB_PASSWORD",
        value=bytearray(b"marcador-valor-de-prueba"),
        actor=actor_humano(esc.ids["admin"]),
    )
    pat_vigente = await pat_de_a_dev(db_session, signer_app, settings_app, esc)
    cuenta = await db_session.scalar(
        select(ServiceAccount.id).where(ServiceAccount.name == "ci-prueba")
    )
    assert cuenta is not None

    # PAT de una service account revocada (H-21).
    revocada_id = uuid4()
    pat_revocado = issue_service_token(
        signer_app,
        service_account_id=revocada_id,
        project_id=esc.a.id,
        environment_id=esc.a.dev,
        expires_at=None,
        issuer=settings_app.jwt_issuer,
    ).token
    db_session.add(
        ServiceAccount(
            id=revocada_id,
            name="ci-revocada",
            project_id=esc.a.id,
            environment_id=esc.a.dev,
            token_hash=hashlib.sha256(pat_revocado.encode()).hexdigest(),
            token_prefix=pat_revocado[-8:],
            created_by=esc.ids["admin"],
            revoked_at=datetime.now(UTC),
        )
    )

    asignacion = await db_session.scalar(
        select(UserRoleAssignment.id).where(UserRoleAssignment.user_id == esc.ids["dev_a"])
    )
    assert asignacion is not None
    fila = await OperationLogService().record(
        db_session,
        OperationEvent(
            actor_type="human",
            actor_ref="lider_a@example.com",
            actor_user_id=esc.ids["lider_a"],
            verb="create_secret",
            result="success",
            resource_type="secret",
            resource_id=ref.secret_id,
            project_id=esc.a.id,
            environment_id=esc.a.dev,
        ),
    )
    await db_session.commit()

    refresh = issue_refresh_token(
        signer_app, user_id=esc.ids["dev_a"], issuer=settings_app.jwt_issuer
    ).token
    cabeceras: dict[str, dict[str, str]] = {
        "anonimo": {},
        "firma_alterada": bearer(_firma_alterada(esc.tokens["dev_a"])),
        "refresh_como_bearer": bearer(refresh),
        "pat_revocado": bearer(pat_revocado),
        "pat_a_dev": bearer(pat_vigente),
        **{humano: esc.h(humano) for humano in HUMANOS},
    }
    return Recursos(esc, ref.secret_id, cuenta, asignacion, fila.id, cabeceras)


# --- La matriz -----------------------------------------------------------------------------------


Peticion = Callable[[Recursos], tuple[str, Any]]  # (URL, cuerpo JSON o None)


@dataclass(frozen=True)
class Celda:
    """Una ruta: cómo pedirla y qué recibe cada actor.

    - ``esperado``: código para los cinco actores autenticados. Los cuatro no autenticables
      reciben 401, salvo en las rutas públicas (``publica=True``), donde todos reciben el mismo
      código que ``esperado["admin"]``: la cabecera ``Authorization`` no cambia nada.
    - ``inexistente``: la misma petición con un identificador que no existe, para comparar el
      cuerpo de los 404.
    - ``hash_real``: el actor humano necesita una contraseña verificable (cambio de contraseña).
    """

    peticion: Peticion
    esperado: dict[str, int]
    inexistente: Peticion | None = None
    publica: bool = False
    hash_real: bool = False
    notas: str = field(default="", compare=False)

    def para(self, actor: str) -> int:
        if self.publica:
            return self.esperado["admin"]
        if actor in NO_AUTENTICABLES:
            return 401
        return self.esperado[actor]


def _por_actor(pat: int, dev_a: int, lider_a: int, lider_b: int, admin: int) -> dict[str, int]:
    return {
        "pat_a_dev": pat,
        "dev_a": dev_a,
        "lider_a": lider_a,
        "lider_b": lider_b,
        "admin": admin,
    }


def _todos(codigo: int) -> dict[str, int]:
    return dict.fromkeys(AUTENTICADOS, codigo)


def _solo_admin(exito: int) -> dict[str, int]:
    """``users:manage``, ``projects:manage`` de instancia o ``verify-chain``: recurso de
    instancia, no hay nada que ocultar → 403 para todos menos el Administrador."""
    return _por_actor(403, 403, 403, 403, exito)


def _humanos(exito: int) -> dict[str, int]:
    """Rutas de "yo" humano: un PAT se autentica, pero no tiene "yo" → 403 (spec §3.4)."""
    return _por_actor(403, exito, exito, exito, exito)


# Lectura de un recurso de A/development: la ven el PAT, dev_a, lider_a y admin.
LECTURA_A_DEV = _por_actor(200, 200, 200, 404, 200)


def _gestion_a(exito: int) -> dict[str, int]:
    """Escritura en A (``secrets:write|rotate|delete`` o ``projects:manage``): el PAT y dev_a ven
    el recurso pero no tienen el permiso → 403; lider_b no lo ve → 404."""
    return _por_actor(403, 403, exito, 404, exito)


def _secretos(r: Recursos, eid: UUID | None = None) -> str:
    return f"{API}/projects/{r.a}/environments/{eid or r.esc.a.dev}/secrets"


def _secreto(sid: UUID, sufijo: str = "") -> str:
    return f"{API}/secrets/{sid}{sufijo}"


NUEVO_SECRETO = {"name": "NUEVO_SECRETO", "value": "marcador-valor-nuevo"}
NUEVA_CONTRASENA = CONTRASENA + "-nueva"

MATRIZ: dict[tuple[str, str], Celda] = {
    # --- Salud y autenticación (spec §3) ---
    ("GET", f"{API}/health"): Celda(lambda r: (f"{API}/health", None), _todos(200), publica=True),
    ("GET", f"{API}/health/ready"): Celda(
        lambda r: (f"{API}/health/ready", None), _todos(200), publica=True
    ),
    ("POST", f"{API}/auth/login"): Celda(
        lambda r: (f"{API}/auth/login", {"email": "login@example.com", "password": CONTRASENA}),
        _todos(200),
        publica=True,
        notas="un Bearer en la petición no cambia el login",
    ),
    ("POST", f"{API}/auth/refresh"): Celda(
        lambda r: (f"{API}/auth/refresh", None),
        _todos(401),
        publica=True,
        notas="sin cookie: ningún Bearer, ni el refresh token, sustituye a la cookie (H-36)",
    ),
    ("POST", f"{API}/auth/logout"): Celda(lambda r: (f"{API}/auth/logout", None), _humanos(204)),
    ("GET", f"{API}/auth/me"): Celda(lambda r: (f"{API}/auth/me", None), _humanos(200)),
    # --- Secretos (spec §2; H-14) ---
    ("POST", f"{API}/projects/{{project_id}}/environments/{{environment_id}}/secrets"): Celda(
        lambda r: (_secretos(r), NUEVO_SECRETO),
        _gestion_a(201),
        inexistente=lambda r: (_secretos(r, uuid4()), NUEVO_SECRETO),
    ),
    ("GET", f"{API}/projects/{{project_id}}/environments/{{environment_id}}/secrets"): Celda(
        lambda r: (_secretos(r), None),
        LECTURA_A_DEV,
        inexistente=lambda r: (_secretos(r, uuid4()), None),
    ),
    ("GET", f"{API}/secrets/{{secret_id}}"): Celda(
        lambda r: (_secreto(r.secreto), None),
        LECTURA_A_DEV,
        inexistente=lambda r: (_secreto(uuid4()), None),
    ),
    ("GET", f"{API}/secrets/{{secret_id}}/value"): Celda(
        lambda r: (_secreto(r.secreto, "/value"), None),
        LECTURA_A_DEV,
        inexistente=lambda r: (_secreto(uuid4(), "/value"), None),
    ),
    ("PATCH", f"{API}/secrets/{{secret_id}}"): Celda(
        lambda r: (_secreto(r.secreto), {"description": "otra"}),
        _gestion_a(200),
        inexistente=lambda r: (_secreto(uuid4()), {"description": "otra"}),
    ),
    ("POST", f"{API}/secrets/{{secret_id}}/rotate"): Celda(
        lambda r: (_secreto(r.secreto, "/rotate"), {"new_value": "marcador-valor-rotado"}),
        _gestion_a(200),
        inexistente=lambda r: (_secreto(uuid4(), "/rotate"), {"new_value": "marcador-x"}),
    ),
    ("DELETE", f"{API}/secrets/{{secret_id}}"): Celda(
        lambda r: (_secreto(r.secreto), None),
        _gestion_a(204),
        inexistente=lambda r: (_secreto(uuid4()), None),
    ),
    ("GET", f"{API}/secrets/{{secret_id}}/versions"): Celda(
        lambda r: (_secreto(r.secreto, "/versions"), None),
        LECTURA_A_DEV,
        inexistente=lambda r: (_secreto(uuid4(), "/versions"), None),
    ),
    # --- Proyectos y ambientes (spec §2, §4.2; H-23c, H-23d, H-39) ---
    ("POST", f"{API}/projects"): Celda(
        lambda r: (f"{API}/projects", {"name": "proyecto-nuevo"}), _solo_admin(201)
    ),
    ("GET", f"{API}/projects"): Celda(
        lambda r: (f"{API}/projects", None),
        _todos(200),
        notas="lista filtrada por visible_projects (H-23c)",
    ),
    ("GET", f"{API}/projects/{{project_id}}"): Celda(
        lambda r: (f"{API}/projects/{r.a}", None),
        LECTURA_A_DEV,
        inexistente=lambda r: (f"{API}/projects/{uuid4()}", None),
    ),
    ("PATCH", f"{API}/projects/{{project_id}}"): Celda(
        lambda r: (f"{API}/projects/{r.a}", {"description": "otra"}),
        _gestion_a(200),
        inexistente=lambda r: (f"{API}/projects/{uuid4()}", {"description": "otra"}),
    ),
    ("DELETE", f"{API}/projects/{{project_id}}"): Celda(
        lambda r: (f"{API}/projects/{r.a}?confirm=true", None),
        _gestion_a(204),
        inexistente=lambda r: (f"{API}/projects/{uuid4()}?confirm=true", None),
    ),
    ("POST", f"{API}/projects/{{project_id}}/environments"): Celda(
        lambda r: (f"{API}/projects/{r.a}/environments", {"name": "qa"}),
        _gestion_a(201),
        inexistente=lambda r: (f"{API}/projects/{uuid4()}/environments", {"name": "qa"}),
    ),
    ("GET", f"{API}/projects/{{project_id}}/environments"): Celda(
        lambda r: (f"{API}/projects/{r.a}/environments", None),
        LECTURA_A_DEV,
        inexistente=lambda r: (f"{API}/projects/{uuid4()}/environments", None),
    ),
    ("PATCH", f"{API}/projects/{{project_id}}/environments/{{environment_id}}"): Celda(
        lambda r: (f"{API}/projects/{r.a}/environments/{r.esc.a.dev}", {"description": "otra"}),
        _gestion_a(200),
        inexistente=lambda r: (
            f"{API}/projects/{r.a}/environments/{uuid4()}",
            {"description": "otra"},
        ),
    ),
    ("DELETE", f"{API}/projects/{{project_id}}/environments/{{environment_id}}"): Celda(
        lambda r: (f"{API}/projects/{r.a}/environments/{r.esc.a.ambientes['staging']}", None),
        # staging no es visible para el PAT ni para dev_a (solo cubren A/development) → 404.
        _por_actor(404, 404, 204, 404, 204),
        inexistente=lambda r: (f"{API}/projects/{r.a}/environments/{uuid4()}", None),
    ),
    # --- Usuarios y asignaciones (spec §2, §4.4; H-23a): recurso de instancia, siempre 403 ---
    ("POST", f"{API}/users"): Celda(
        lambda r: (f"{API}/users", {"email": "nuevo@example.com", "password": NUEVA_CONTRASENA}),
        _solo_admin(201),
    ),
    ("GET", f"{API}/users"): Celda(lambda r: (f"{API}/users", None), _solo_admin(200)),
    ("GET", f"{API}/users/{{user_id}}"): Celda(
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}", None), _solo_admin(200)
    ),
    ("PATCH", f"{API}/users/{{user_id}}"): Celda(
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}", {"name": "Otro"}), _solo_admin(200)
    ),
    ("DELETE", f"{API}/users/{{user_id}}"): Celda(
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}", None), _solo_admin(204)
    ),
    ("POST", f"{API}/users/{{user_id}}/role-assignments"): Celda(
        lambda r: (
            f"{API}/users/{r.esc.ids['dev_a']}/role-assignments",
            {"role_id": 3, "project_id": str(r.a), "environment_id": str(r.esc.a.prod)},
        ),
        _solo_admin(201),
    ),
    ("GET", f"{API}/users/{{user_id}}/role-assignments"): Celda(  # H-73
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}/role-assignments", None), _solo_admin(200)
    ),
    ("DELETE", f"{API}/users/{{user_id}}/role-assignments/{{assignment_id}}"): Celda(
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}/role-assignments/{r.asignacion}", None),
        _solo_admin(204),
    ),
    ("POST", f"{API}/users/{{user_id}}/unlock"): Celda(  # H-78
        lambda r: (f"{API}/users/{r.esc.ids['dev_a']}/unlock", None), _solo_admin(204)
    ),
    ("POST", f"{API}/users/{{user_id}}/password-reset"): Celda(  # H-78
        lambda r: (
            f"{API}/users/{r.esc.ids['dev_a']}/password-reset",
            {"new_password": NUEVA_CONTRASENA},
        ),
        _solo_admin(204),
    ),
    ("POST", f"{API}/users/me/password"): Celda(
        lambda r: (
            f"{API}/users/me/password",
            {"current_password": CONTRASENA, "new_password": NUEVA_CONTRASENA},
        ),
        _humanos(204),
        hash_real=True,
    ),
    # --- Service accounts (spec §4.4; H-23a) ---
    ("POST", f"{API}/projects/{{project_id}}/service-accounts"): Celda(
        lambda r: (f"{API}/projects/{r.a}/service-accounts", {"name": "nueva"}),
        _gestion_a(201),
        inexistente=lambda r: (f"{API}/projects/{uuid4()}/service-accounts", {"name": "nueva"}),
    ),
    ("GET", f"{API}/projects/{{project_id}}/service-accounts"): Celda(
        lambda r: (f"{API}/projects/{r.a}/service-accounts", None),
        _gestion_a(200),
        inexistente=lambda r: (f"{API}/projects/{uuid4()}/service-accounts", None),
    ),
    ("GET", f"{API}/service-accounts/{{service_account_id}}"): Celda(
        lambda r: (f"{API}/service-accounts/{r.cuenta}", None),
        _gestion_a(200),
        inexistente=lambda r: (f"{API}/service-accounts/{uuid4()}", None),
    ),
    ("DELETE", f"{API}/service-accounts/{{service_account_id}}"): Celda(
        lambda r: (f"{API}/service-accounts/{r.cuenta}", None),
        _gestion_a(204),
        inexistente=lambda r: (f"{API}/service-accounts/{uuid4()}", None),
    ),
    # --- Bitácora (spec §4.3; H-23b) ---
    ("GET", f"{API}/operations"): Celda(
        lambda r: (f"{API}/operations", None),
        _por_actor(403, 403, 200, 200, 200),
        notas="lider_b recibe 200 con la lista filtrada a B",
    ),
    ("GET", f"{API}/operations/export"): Celda(
        lambda r: (f"{API}/operations/export?format=csv", None),
        _por_actor(403, 403, 200, 200, 200),
        notas="RF-021 (H-83): mismo alcance que GET /operations; lider_b exporta solo B",
    ),
    ("GET", f"{API}/operations/{{log_id}}"): Celda(
        lambda r: (f"{API}/operations/{r.registro}", None),
        _por_actor(403, 403, 200, 404, 200),
        inexistente=lambda r: (f"{API}/operations/{ID_REGISTRO_INEXISTENTE}", None),
    ),
    ("POST", f"{API}/operations/verify-chain"): Celda(
        lambda r: (f"{API}/operations/verify-chain", None), _solo_admin(200)
    ),
}


# --- Pruebas -------------------------------------------------------------------------------------


def _rutas_de_la_app(app: FastAPI) -> set[tuple[str, str]]:
    """``(método, ruta)`` de toda ruta HTTP bajo ``/api/v1``. Desde FastAPI 0.14x, ``app.routes``
    guarda cada ``include_router`` como un nodo; ``iter_route_contexts`` lo recorre hasta las
    rutas efectivas, con el prefijo ya aplicado."""
    return {
        (metodo, ctx.path)
        for ctx in iter_route_contexts(app.routes)
        if ctx.path is not None and ctx.path.startswith(API) and ctx.methods
        for metodo in ctx.methods
        if metodo not in {"HEAD", "OPTIONS"}
    }


async def test_la_matriz_cubre_todas_las_rutas(app: FastAPI) -> None:
    """Una ruta nueva sin fila en la matriz (o una fila de una ruta que ya no existe) falla."""
    rutas = _rutas_de_la_app(app)

    assert sorted(rutas - MATRIZ.keys()) == [], "rutas sin fila en MATRIZ"
    assert sorted(MATRIZ.keys() - rutas) == [], "filas de MATRIZ sin ruta"


def _sin_variables(cuerpo: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in cuerpo.items() if k not in {"trace_id", "instance"}}


CELDAS = [(llave, actor) for llave in MATRIZ for actor in ACTORES]


@pytest.mark.parametrize(
    ("llave", "actor"), CELDAS, ids=[f"{m} {p.removeprefix(API)} · {a}" for (m, p), a in CELDAS]
)
async def test_matriz_de_acceso(
    cliente: AsyncClient,
    db_session: AsyncSession,
    recursos: Recursos,
    llave: tuple[str, str],
    actor: str,
) -> None:
    metodo, _ = llave
    celda = MATRIZ[llave]
    esperado = celda.para(actor)
    if celda.hash_real and actor in HUMANOS:
        await db_session.execute(
            update(User)
            .where(User.id == recursos.esc.ids[actor])
            .values(password_hash=hash_password(CONTRASENA))
        )
        await db_session.commit()
    if llave == ("POST", f"{API}/auth/login"):
        await crear_usuario(db_session, "login@example.com")
    url, cuerpo = celda.peticion(recursos)
    cabeceras = recursos.cabeceras[actor]

    respuesta = await cliente.request(metodo, url, json=cuerpo, headers=cabeceras)

    assert respuesta.status_code == esperado, respuesta.text
    if esperado in TIPO_POR_ESTADO:
        assert_problema(respuesta, esperado, TIPO_POR_ESTADO[esperado])
    if esperado == 404 and celda.inexistente is not None:
        url_x, cuerpo_x = celda.inexistente(recursos)
        otra = await cliente.request(metodo, url_x, json=cuerpo_x, headers=cabeceras)
        assert otra.status_code == 404, otra.text
        assert otra.headers["content-type"] == respuesta.headers["content-type"]
        # "No visible" e "inexistente" son indistinguibles (H-14).
        assert _sin_variables(otra.json()) == _sin_variables(respuesta.json())
