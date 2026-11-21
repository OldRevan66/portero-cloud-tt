"""API de usuarios, asignaciones de rol, cambio de contraseña, desbloqueo y restablecimiento
(CU-05; spec Fase 5 §2, §3.5, §3.6, §4.4, §5, §6; H-22, H-23a, H-30, H-37, H-78; spec núcleo
§3.1).

Mismo escenario compartido (``conftest.escenario``). Las rutas de ``/users`` exigen
``users:manage`` de instancia: solo el Administrador (H-23a). Un usuario es un recurso de
instancia, así que el Líder y el Desarrollador reciben 403 (no 404) y la fila ``access_denied``
va sin ``project_id`` (spec §4.3: los registros de usuarios solo los ve el Administrador).

Decisiones que fijan estas pruebas (sesión 12):

- La política de contraseñas y un ambiente que no pertenece al proyecto dan **422**
  ``semantic-error`` (spec §1, §2, §6): el cuerpo pasa el esquema, pero viola una regla de
  negocio. La asignación de instancia para un rol que no es Administrador da **400** (H-22).
- ``GET /users`` devuelve una lista, igual que ``GET /projects`` (la spec solo pagina
  ``/operations`` y ``/versions``).
- H-37 se observa con ``GET /auth/me``: un token emitido antes del evento da 401.

Hoy toda ruta inexistente responde 404; por eso los 403 se comprueban junto con su fila
``access_denied``.
"""

import logging
import threading
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import (
    CONTRASENA,
    COOKIE_REFRESH,
    Escenario,
    assert_denegacion,
    assert_problema,
    atributos_refresh,
    bearer,
    crear_usuario,
    login,
    pat_de_a_dev,
    ultimo_registro,
    valor_refresh,
)

import portero.management.users as usuarios_mod
from portero.auth.passwords import MAX_LENGTH, MIN_LENGTH, common_passwords
from portero.config import Settings
from portero.crypto.signing import JwtSigner
from portero.db.models import AuditLog, User, UserRoleAssignment
from portero.rbac.permissions import Role

USUARIOS = "/api/v1/users"
CAMPOS_USUARIO = {"id", "email", "name", "is_active", "created_at", "updated_at", "locked_until"}
CAMPOS_ASIGNACION = {"id", "role_id", "project_id", "environment_id"}

NUEVA = "marcador-nueva-clave-larga"  # noqa: S105  # marcador de prueba, no un secreto
COMUN = "password1234"  # noqa: S105  # está en common-passwords.txt (se comprueba abajo)

CONTRASENAS_INVALIDAS = [
    pytest.param("x" * (MIN_LENGTH - 1), id="corta"),
    pytest.param(COMUN, id="comun"),
    pytest.param("x" * (MAX_LENGTH + 1), id="mayor-a-128"),
]


# --- Auxiliares ----------------------------------------------------------------------------------


def _usuario(uid: UUID | str, sufijo: str = "") -> str:
    return f"{USUARIOS}/{uid}{sufijo}"


def _asignaciones(uid: UUID | str) -> str:
    return f"{USUARIOS}/{uid}/role-assignments"


def _assert_sin_hash(texto: str) -> None:
    """Ninguna respuesta de usuarios incluye el hash ni su nombre de campo."""
    assert "password_hash" not in texto
    assert "$argon2" not in texto
    assert '"password"' not in texto


async def _assert_registro(
    db_session: AsyncSession,
    *,
    verbo: str,
    actor_id: UUID,
    resource_id: UUID,
    resource_type: str = "user",
) -> AuditLog:
    """Fila de la bitácora de una escritura sobre usuarios (spec §5.2–5.4)."""
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result) == (verbo, "success")
    assert fila.actor_type == "human"
    assert fila.actor_user_id == actor_id
    assert (fila.resource_type, fila.resource_id) == (resource_type, resource_id)
    return fila


async def _recargar(db_session: AsyncSession, user_id: UUID) -> User:
    user = await db_session.get(User, user_id, populate_existing=True)
    assert user is not None
    return user


async def _asignaciones_de(db_session: AsyncSession, user_id: UUID) -> list[UserRoleAssignment]:
    stmt = (
        select(UserRoleAssignment)
        .where(UserRoleAssignment.user_id == user_id)
        .execution_options(populate_existing=True)
    )
    return list(await db_session.scalars(stmt))


async def _me(cliente: AsyncClient, token: str) -> int:
    return (await cliente.get("/api/v1/auth/me", headers=bearer(token))).status_code


def _cuerpo_usuario(email: str = "nuevo@example.com", password: str = NUEVA) -> dict[str, Any]:
    return {"email": email, "name": "Nuevo", "password": password}


# --- POST /users ---------------------------------------------------------------------------------


async def test_administrador_crea_usuario_activo_sin_asignaciones(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    respuesta = await cliente.post(USUARIOS, json=_cuerpo_usuario(), headers=escenario.h("admin"))

    assert respuesta.status_code == 201
    cuerpo = respuesta.json()
    assert set(cuerpo) == CAMPOS_USUARIO
    assert (cuerpo["email"], cuerpo["name"], cuerpo["is_active"]) == (
        "nuevo@example.com",
        "Nuevo",
        True,
    )
    _assert_sin_hash(respuesta.text)
    assert NUEVA not in respuesta.text

    nuevo = await _recargar(db_session, UUID(cuerpo["id"]))
    assert nuevo.is_active
    assert nuevo.password_hash.startswith("$argon2id$")
    assert await _asignaciones_de(db_session, nuevo.id) == []
    fila = await _assert_registro(
        db_session, verbo="create_user", actor_id=escenario.ids["admin"], resource_id=nuevo.id
    )
    assert fila.project_id is None
    assert NUEVA not in str(fila.details)


async def test_el_hash_del_alta_se_calcula_fuera_del_ciclo_de_eventos(
    cliente: AsyncClient, escenario: Escenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H-72: el Argon2id del alta corre en otro hilo; el ciclo de eventos sigue atendiendo."""
    real = usuarios_mod.hash_password
    en_hilo_principal: list[bool] = []

    def _espia(password: str) -> str:
        en_hilo_principal.append(threading.current_thread() is threading.main_thread())
        return real(password)

    monkeypatch.setattr(usuarios_mod, "hash_password", _espia)
    assert threading.current_thread() is threading.main_thread()  # guarda de la prueba

    respuesta = await cliente.post(USUARIOS, json=_cuerpo_usuario(), headers=escenario.h("admin"))

    assert respuesta.status_code == 201
    assert en_hilo_principal == [False]


def test_la_contrasena_comun_de_prueba_esta_en_la_lista() -> None:
    """Guarda de la prueba siguiente: si la lista cambia, el caso ``comun`` no probaría nada."""
    assert COMUN in common_passwords()
    assert len(COMUN) >= MIN_LENGTH


@pytest.mark.parametrize("password", CONTRASENAS_INVALIDAS)
async def test_crear_usuario_con_contrasena_fuera_de_politica_da_422(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, password: str
) -> None:
    respuesta = await cliente.post(
        USUARIOS, json=_cuerpo_usuario(password=password), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert password not in respuesta.text
    existe = await db_session.scalar(select(User.id).where(User.email == "nuevo@example.com"))
    assert existe is None


async def test_crear_usuario_con_correo_duplicado_da_409(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        USUARIOS, json=_cuerpo_usuario(email="dev_a@example.com"), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")


async def test_crear_usuario_con_campo_extra_da_400(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    cuerpo = _cuerpo_usuario() | {"is_admin": True}
    respuesta = await cliente.post(USUARIOS, json=cuerpo, headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")
    assert NUEVA not in respuesta.text


# --- GET / PATCH /users --------------------------------------------------------------------------


async def test_administrador_lista_usuarios_sin_hash(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.get(USUARIOS, headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert isinstance(cuerpo, list)
    assert {UUID(u["id"]) for u in cuerpo} >= set(escenario.ids.values())
    assert all(set(u) == CAMPOS_USUARIO for u in cuerpo)
    _assert_sin_hash(respuesta.text)


async def test_administrador_consulta_un_usuario(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.get(_usuario(escenario.ids["dev_a"]), headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert set(cuerpo) == CAMPOS_USUARIO
    assert cuerpo["email"] == "dev_a@example.com"
    _assert_sin_hash(respuesta.text)


async def test_usuario_inexistente_da_404(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await cliente.get(_usuario(uuid4()), headers=escenario.h("admin"))
    valido = await cliente.get(_usuario(escenario.ids["dev_a"]), headers=escenario.h("admin"))

    assert_problema(respuesta, 404, "resource-not-found")
    assert valido.status_code == 200  # la ruta existe: el 404 no es de ruta inexistente


async def test_administrador_cambia_el_nombre(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_a = escenario.ids["dev_a"]
    respuesta = await cliente.patch(
        _usuario(dev_a), json={"name": "Desarrolladora A"}, headers=escenario.h("admin")
    )

    assert respuesta.status_code == 200
    assert respuesta.json()["name"] == "Desarrolladora A"
    _assert_sin_hash(respuesta.text)
    fila = await _assert_registro(
        db_session, verbo="update_user", actor_id=escenario.ids["admin"], resource_id=dev_a
    )
    assert fila.details == {"fields": ["name"]}


async def test_patch_no_acepta_cambiar_la_contrasena(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """La contraseña solo cambia por ``/users/me/password`` (spec §3.6), que reverifica la
    actual. ``extra="forbid"`` → 400."""
    respuesta = await cliente.patch(
        _usuario(escenario.ids["dev_a"]), json={"password": NUEVA}, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 400, "validation-error")


# --- Autorización: solo el Administrador (users:manage de instancia, H-23a) ----------------------


def _peticiones_de_gestion(uid: UUID) -> list[tuple[str, str, dict[str, Any] | None]]:
    return [
        ("POST", USUARIOS, _cuerpo_usuario()),
        ("GET", USUARIOS, None),
        ("GET", _usuario(uid), None),
        ("PATCH", _usuario(uid), {"name": "otro"}),
        ("DELETE", _usuario(uid), None),
        ("POST", _asignaciones(uid), {"role_id": Role.DESARROLLADOR, "project_id": None}),
        ("GET", _asignaciones(uid), None),  # H-73
        ("POST", _usuario(uid, "/unlock"), None),  # H-78
        ("POST", _usuario(uid, "/password-reset"), {"new_password": NUEVA}),  # H-78
    ]


@pytest.mark.parametrize("quien", ["lider_a", "dev_a"])
async def test_sin_users_manage_toda_la_gestion_da_403(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, quien: str
) -> None:
    objetivo = escenario.ids["dev_b"]
    for metodo, ruta, cuerpo in _peticiones_de_gestion(objetivo):
        respuesta = await cliente.request(metodo, ruta, json=cuerpo, headers=escenario.h(quien))

        assert_problema(respuesta, 403, "permission-denied")
        await assert_denegacion(
            db_session,
            actor_id=escenario.ids[quien],
            permiso="users:manage",
            status=403,
            project_id=None,
            resource_type="user",
        )
    assert (await _recargar(db_session, objetivo)).is_active


async def test_lider_no_ve_un_usuario_inexistente_como_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """Sin ``users:manage`` siempre 403, exista o no el usuario: el 404 enumeraría cuentas."""
    respuesta = await cliente.get(_usuario(uuid4()), headers=escenario.h("lider_a"))

    assert_problema(respuesta, 403, "permission-denied")


# --- Desactivación (PATCH is_active=false y DELETE; H-37) -----------------------------------------


async def _beto_con_sesion(cliente: AsyncClient, db_session: AsyncSession) -> tuple[User, str]:
    """Usuario sin asignaciones con una sesión real: access en mano y refresh en la cookie."""
    beto = await crear_usuario(db_session, "beto@example.com", name="Beto", asignaciones=())
    respuesta = await login(cliente, "beto@example.com")
    assert respuesta.status_code == 200
    access = respuesta.json()["access_token"]
    assert await _me(cliente, access) == 200
    return beto, access


async def test_desactivar_por_patch_invalida_access_y_refresh(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    beto, access = await _beto_con_sesion(cliente, db_session)

    respuesta = await cliente.patch(
        _usuario(beto.id), json={"is_active": False}, headers=escenario.h("admin")
    )

    assert respuesta.status_code == 200
    assert respuesta.json()["is_active"] is False
    recargado = await _recargar(db_session, beto.id)
    assert recargado.is_active is False
    assert recargado.tokens_invalid_before is not None  # H-37
    await _assert_registro(
        db_session, verbo="deactivate_user", actor_id=escenario.ids["admin"], resource_id=beto.id
    )
    assert await _me(cliente, access) == 401
    refresco = await cliente.post("/api/v1/auth/refresh")  # la cookie de Beto sigue en el jar
    assert_problema(refresco, 401, "authentication-failed")


async def test_delete_desactiva_sin_borrar_la_fila(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    beto, access = await _beto_con_sesion(cliente, db_session)

    respuesta = await cliente.delete(_usuario(beto.id), headers=escenario.h("admin"))

    assert respuesta.status_code == 204
    recargado = await _recargar(db_session, beto.id)  # la fila sigue: la refieren otras tablas
    assert recargado.is_active is False
    assert recargado.tokens_invalid_before is not None
    await _assert_registro(
        db_session, verbo="deactivate_user", actor_id=escenario.ids["admin"], resource_id=beto.id
    )
    assert await _me(cliente, access) == 401


@pytest.mark.parametrize("metodo", ["PATCH", "DELETE"])
async def test_administrador_no_se_desactiva_a_si_mismo(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, metodo: str
) -> None:
    admin = escenario.ids["admin"]
    cuerpo = {"is_active": False} if metodo == "PATCH" else None
    respuesta = await cliente.request(
        metodo, _usuario(admin), json=cuerpo, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")
    assert (await _recargar(db_session, admin)).is_active
    assert await _me(cliente, escenario.tokens["admin"]) == 200


# --- POST /users/{uid}/role-assignments (H-22, H-23a, H-37) ---------------------------------------


async def test_asignar_lider_en_un_proyecto(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_b = escenario.ids["dev_b"]
    respuesta = await cliente.post(
        _asignaciones(dev_b),
        json={"role_id": Role.LIDER_TECNICO, "project_id": str(escenario.a.id)},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201
    cuerpo = respuesta.json()
    assert CAMPOS_ASIGNACION <= set(cuerpo)
    assert (cuerpo["role_id"], cuerpo["project_id"], cuerpo["environment_id"]) == (
        Role.LIDER_TECNICO,
        str(escenario.a.id),
        None,
    )
    asignaciones = await _asignaciones_de(db_session, dev_b)
    assert (Role.LIDER_TECNICO, escenario.a.id, None) in {
        (a.role_id, a.project_id, a.environment_id) for a in asignaciones
    }
    fila = await _assert_registro(
        db_session, verbo="assign_role", actor_id=escenario.ids["admin"], resource_id=dev_b
    )
    assert fila.details == {
        "target_user_id": str(dev_b),
        "role_id": Role.LIDER_TECNICO,
        "project_id": str(escenario.a.id),
        "environment_id": None,
    }


async def test_asignar_roles_invalida_los_tokens_del_usuario(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    """H-37: los permisos se leen de la BD en cada petición (spec §4), pero el Cap. 6 pide
    además revocar los tokens vivos al cambiar roles."""
    assert await _me(cliente, escenario.tokens["dev_b"]) == 200

    respuesta = await cliente.post(
        _asignaciones(escenario.ids["dev_b"]),
        json={"role_id": Role.LIDER_TECNICO, "project_id": str(escenario.a.id)},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201
    assert await _me(cliente, escenario.tokens["dev_b"]) == 401


@pytest.mark.parametrize("role_id", [Role.LIDER_TECNICO, Role.DESARROLLADOR])
async def test_asignacion_de_instancia_para_rol_no_administrador_da_400(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, role_id: int
) -> None:
    """H-22: el alcance de instancia es solo del Administrador."""
    dev_b = escenario.ids["dev_b"]
    respuesta = await cliente.post(
        _asignaciones(dev_b),
        json={"role_id": role_id, "project_id": None, "environment_id": None},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 400, "validation-error")
    assert len(await _asignaciones_de(db_session, dev_b)) == 1


async def test_asignacion_de_instancia_de_administrador_se_admite(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        _asignaciones(escenario.ids["dev_b"]),
        json={"role_id": Role.ADMINISTRADOR, "project_id": None, "environment_id": None},
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 201


async def test_ambiente_sin_proyecto_da_400(cliente: AsyncClient, escenario: Escenario) -> None:
    respuesta = await cliente.post(
        _asignaciones(escenario.ids["dev_b"]),
        json={
            "role_id": Role.DESARROLLADOR,
            "project_id": None,
            "environment_id": str(escenario.a.dev),
        },
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 400, "validation-error")


async def test_ambiente_de_otro_proyecto_da_422(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_b = escenario.ids["dev_b"]
    respuesta = await cliente.post(
        _asignaciones(dev_b),
        json={
            "role_id": Role.DESARROLLADOR,
            "project_id": str(escenario.a.id),
            "environment_id": str(escenario.b.dev),
        },
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert len(await _asignaciones_de(db_session, dev_b)) == 1


async def test_asignacion_duplicada_da_409(cliente: AsyncClient, escenario: Escenario) -> None:
    """dev_a ya es Desarrollador de A/dev (escenario); UNIQUE NULLS NOT DISTINCT (H-19)."""
    respuesta = await cliente.post(
        _asignaciones(escenario.ids["dev_a"]),
        json={
            "role_id": Role.DESARROLLADOR,
            "project_id": str(escenario.a.id),
            "environment_id": str(escenario.a.dev),
        },
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 409, "conflict")


async def test_asignar_a_usuario_inexistente_da_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        _asignaciones(uuid4()),
        json={"role_id": Role.LIDER_TECNICO, "project_id": str(escenario.a.id)},
        headers=escenario.h("admin"),
    )
    valido = await cliente.post(
        _asignaciones(escenario.ids["dev_b"]),
        json={"role_id": Role.LIDER_TECNICO, "project_id": str(escenario.a.id)},
        headers=escenario.h("admin"),
    )

    assert_problema(respuesta, 404, "resource-not-found")
    assert valido.status_code == 201  # la ruta existe: el 404 no es de ruta inexistente


# --- GET /users/{uid}/role-assignments (H-73) -----------------------------------------------------
#
# El Cap. 6 tiene POST y DELETE de asignaciones, pero no un GET: sin él, el Dashboard no conoce el
# ``aid`` que pide el DELETE. Orden estable: ``role_id``, ``created_at`` e ``id``. ``created_at``
# es ``now()`` de PostgreSQL (inicio de la transacción), así que dos asignaciones creadas juntas
# empatan y ``id`` desempata.


def _agregar_asignacion(
    db_session: AsyncSession,
    user_id: UUID,
    role_id: int,
    project_id: UUID | None = None,
    environment_id: UUID | None = None,
) -> UserRoleAssignment:
    asignacion = UserRoleAssignment(
        user_id=user_id, role_id=role_id, project_id=project_id, environment_id=environment_id
    )
    db_session.add(asignacion)
    return asignacion


async def test_administrador_lista_las_asignaciones_en_orden_estable(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Una de instancia, una de proyecto y una de ambiente, insertadas en orden inverso al
    esperado: sale primero el Administrador, luego el Líder y al final el Desarrollador."""
    dev_b = escenario.ids["dev_b"]  # ya es Desarrollador de B/development (escenario)
    _agregar_asignacion(db_session, dev_b, Role.LIDER_TECNICO, escenario.a.id)
    await db_session.commit()
    _agregar_asignacion(db_session, dev_b, Role.ADMINISTRADOR)
    await db_session.commit()

    respuesta = await cliente.get(_asignaciones(dev_b), headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert all(set(a) == CAMPOS_ASIGNACION for a in cuerpo)
    assert [(a["role_id"], a["project_id"], a["environment_id"]) for a in cuerpo] == [
        (Role.ADMINISTRADOR, None, None),
        (Role.LIDER_TECNICO, str(escenario.a.id), None),
        (Role.DESARROLLADOR, str(escenario.b.id), str(escenario.b.dev)),
    ]
    en_bd = {a.id for a in await _asignaciones_de(db_session, dev_b)}
    assert {UUID(a["id"]) for a in cuerpo} == en_bd


async def test_asignaciones_empatadas_se_ordenan_por_id(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Mismo rol y misma transacción (mismo ``created_at``): decide el ``id``."""
    usuario = await crear_usuario(db_session, "empate@example.com", asignaciones=())
    _agregar_asignacion(db_session, usuario.id, Role.DESARROLLADOR, escenario.a.id, escenario.a.dev)
    _agregar_asignacion(
        db_session,
        usuario.id,
        Role.DESARROLLADOR,
        escenario.b.id,
        escenario.b.ambientes["staging"],
    )
    await db_session.commit()

    respuesta = await cliente.get(_asignaciones(usuario.id), headers=escenario.h("admin"))

    assert respuesta.status_code == 200
    ids = [a["id"] for a in respuesta.json()]
    assert len(ids) == 2
    assert ids == sorted(ids)  # PostgreSQL compara uuid byte a byte = orden del texto hex


async def test_la_respuesta_de_asignaciones_no_trae_datos_del_usuario(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.get(
        _asignaciones(escenario.ids["dev_a"]), headers=escenario.h("admin")
    )

    assert respuesta.status_code == 200
    (asignacion,) = respuesta.json()
    assert set(asignacion) == CAMPOS_ASIGNACION
    for campo in ("email", "name", "is_active", "failed_login_attempts", "locked_until"):
        assert campo not in respuesta.text
    _assert_sin_hash(respuesta.text)


async def test_asignaciones_de_usuario_inexistente_da_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.get(_asignaciones(uuid4()), headers=escenario.h("admin"))
    valido = await cliente.get(_asignaciones(escenario.ids["dev_a"]), headers=escenario.h("admin"))

    assert_problema(respuesta, 404, "resource-not-found")
    assert valido.status_code == 200  # la ruta existe: el 404 no es de ruta inexistente


@pytest.mark.parametrize("uid", ["no-es-uuid", "11111111111141118111111111111111"])
async def test_asignaciones_con_uuid_no_canonico_da_400(
    cliente: AsyncClient, escenario: Escenario, uid: str
) -> None:
    """Spec §1: solo la forma canónica de 36 caracteres; cualquier otra → 400 (no 422)."""
    respuesta = await cliente.get(_asignaciones(uid), headers=escenario.h("admin"))

    assert_problema(respuesta, 400, "validation-error")


@pytest.mark.parametrize("quien", ["lider_a", "dev_a"])
async def test_sin_users_manage_no_lista_asignaciones_ni_de_un_usuario_inexistente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, quien: str
) -> None:
    """403 exista o no el usuario: la dependencia se resuelve antes de buscarlo, así que no
    sirve para enumerar cuentas."""
    respuesta = await cliente.get(_asignaciones(uuid4()), headers=escenario.h(quien))

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids[quien],
        permiso="users:manage",
        status=403,
        project_id=None,
        resource_type="user",
    )


async def test_un_pat_no_lista_asignaciones(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.get(_asignaciones(uuid4()), headers=bearer(pat))

    assert_problema(respuesta, 403, "permission-denied")


async def test_listar_asignaciones_sin_token_da_401(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.get(_asignaciones(escenario.ids["dev_a"]))

    assert_problema(respuesta, 401, "authentication-failed")


# --- DELETE /users/{uid}/role-assignments/{aid} ---------------------------------------------------


async def test_quitar_una_asignacion_da_204_e_invalida_tokens(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_a = escenario.ids["dev_a"]
    (asignacion,) = await _asignaciones_de(db_session, dev_a)
    assert await _me(cliente, escenario.tokens["dev_a"]) == 200

    respuesta = await cliente.delete(
        f"{_asignaciones(dev_a)}/{asignacion.id}", headers=escenario.h("admin")
    )

    assert respuesta.status_code == 204
    assert await _asignaciones_de(db_session, dev_a) == []
    fila = await _assert_registro(
        db_session, verbo="revoke_role", actor_id=escenario.ids["admin"], resource_id=dev_a
    )
    assert fila.details == {
        "target_user_id": str(dev_a),
        "role_id": Role.DESARROLLADOR,
        "project_id": str(escenario.a.id),
        "environment_id": str(escenario.a.dev),
    }
    assert await _me(cliente, escenario.tokens["dev_a"]) == 401  # H-37


async def test_quitar_asignacion_de_otro_usuario_da_404(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """La asignación debe pertenecer al ``uid`` de la ruta."""
    (asignacion,) = await _asignaciones_de(db_session, escenario.ids["dev_a"])

    respuesta = await cliente.delete(
        f"{_asignaciones(escenario.ids['dev_b'])}/{asignacion.id}", headers=escenario.h("admin")
    )

    assert_problema(respuesta, 404, "resource-not-found")
    assert len(await _asignaciones_de(db_session, escenario.ids["dev_a"])) == 1
    valido = await cliente.delete(
        f"{_asignaciones(escenario.ids['dev_a'])}/{asignacion.id}", headers=escenario.h("admin")
    )
    assert valido.status_code == 204  # con su uid correcto sí se quita


async def test_lider_no_quita_asignaciones(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_a = escenario.ids["dev_a"]
    (asignacion,) = await _asignaciones_de(db_session, dev_a)

    respuesta = await cliente.delete(
        f"{_asignaciones(dev_a)}/{asignacion.id}", headers=escenario.h("lider_a")
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_a"],
        permiso="users:manage",
        status=403,
        project_id=None,
        resource_type="user",
    )
    assert len(await _asignaciones_de(db_session, dev_a)) == 1


# --- POST /users/me/password (spec §3.6; H-37) ----------------------------------------------------

CAMBIO = "/api/v1/users/me/password"


async def test_contrasena_actual_incorrecta_da_401_generico(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    access = (await login(cliente)).json()["access_token"]
    hash_previo = usuario.password_hash

    respuesta = await cliente.post(
        CAMBIO,
        json={"current_password": "marcador-clave-equivocada", "new_password": NUEVA},
        headers=bearer(access),
    )

    assert_problema(respuesta, 401, "authentication-failed")
    assert "marcador-clave-equivocada" not in respuesta.text
    recargado = await _recargar(db_session, usuario.id)
    assert recargado.failed_login_attempts == 1  # cuenta como fallo para el bloqueo
    assert recargado.password_hash == hash_previo


async def test_cinco_fallos_en_el_cambio_bloquean_la_cuenta(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    """Spec §3.6: el fallo cuenta para el bloqueo del login (NIST SP 800-63B §5.2.2). Así un
    access token robado no sirve para adivinar la contraseña actual sin límite."""
    access = (await login(cliente)).json()["access_token"]
    equivocada = {"current_password": "marcador-clave-equivocada", "new_password": NUEVA}
    for _ in range(5):
        fallo = await cliente.post(CAMBIO, json=equivocada, headers=bearer(access))
        assert_problema(fallo, 401, "authentication-failed")
    hash_previo = (await _recargar(db_session, usuario.id)).password_hash

    correcta = await cliente.post(
        CAMBIO,
        json={"current_password": CONTRASENA, "new_password": NUEVA},
        headers=bearer(access),
    )

    assert_problema(correcta, 401, "authentication-failed")  # bloqueada aunque sea correcta
    recargado = await _recargar(db_session, usuario.id)
    assert recargado.locked_until is not None
    assert recargado.password_hash == hash_previo
    fila = await ultimo_registro(db_session)
    assert (fila.verb, fila.result, fila.details) == (
        "change_password",
        "failure",
        {"reason": "bloqueada"},
    )
    assert (await login(cliente)).status_code == 401


@pytest.mark.parametrize("password", CONTRASENAS_INVALIDAS)
async def test_nueva_contrasena_fuera_de_politica_da_422(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession, password: str
) -> None:
    access = (await login(cliente)).json()["access_token"]
    hash_previo = usuario.password_hash

    respuesta = await cliente.post(
        CAMBIO,
        json={"current_password": CONTRASENA, "new_password": password},
        headers=bearer(access),
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert password not in respuesta.text
    assert (await _recargar(db_session, usuario.id)).password_hash == hash_previo
    assert await _me(cliente, access) == 200  # sin cambio no hay corte H-37


async def test_cambio_de_contrasena_invalida_access_y_refresh(
    cliente: AsyncClient, usuario: User, db_session: AsyncSession
) -> None:
    sesion = await login(cliente)
    access = sesion.json()["access_token"]
    refresh = valor_refresh(sesion)

    respuesta = await cliente.post(
        CAMBIO,
        json={"current_password": CONTRASENA, "new_password": NUEVA},
        headers=bearer(access),
    )

    assert respuesta.status_code == 204
    assert atributos_refresh(respuesta)["max-age"] == "0"  # hay que iniciar sesión de nuevo
    fila = await _assert_registro(
        db_session, verbo="change_password", actor_id=usuario.id, resource_id=usuario.id
    )
    assert CONTRASENA not in str(fila.details)
    assert NUEVA not in str(fila.details)

    assert await _me(cliente, access) == 401
    refresco = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={refresh}"}
    )
    assert_problema(refresco, 401, "authentication-failed")

    assert (await login(cliente, password=CONTRASENA)).status_code == 401
    assert (await login(cliente, password=NUEVA)).status_code == 200


async def test_cambio_de_contrasena_sin_token_da_401(cliente: AsyncClient) -> None:
    respuesta = await cliente.post(
        CAMBIO, json={"current_password": CONTRASENA, "new_password": NUEVA}
    )

    assert_problema(respuesta, 401, "authentication-failed")


async def test_un_pat_no_cambia_contrasenas(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
) -> None:
    """Solo humanos (spec §3.6): un service account no tiene contraseña."""
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.post(
        CAMBIO,
        json={"current_password": CONTRASENA, "new_password": NUEVA},
        headers=bearer(pat),
    )

    assert_problema(respuesta, 403, "permission-denied")


# --- POST /users/{uid}/unlock (H-78) --------------------------------------------------------------

EQUIVOCADA = "marcador-clave-equivocada"  # noqa: S105  # marcador de prueba, no un secreto


def _desbloqueo(uid: UUID | str) -> str:
    return _usuario(uid, "/unlock")


async def _beto_bloqueado(cliente: AsyncClient, db_session: AsyncSession) -> User:
    """Beto, sin asignaciones, bloqueado por 5 logins fallidos reales (Cap. 6 §Política de
    bloqueo; NIST SP 800-63B §5.2.2): ni con la contraseña correcta entra."""
    beto = await crear_usuario(db_session, "beto@example.com", name="Beto", asignaciones=())
    for _ in range(5):
        assert (await login(cliente, "beto@example.com", EQUIVOCADA)).status_code == 401
    recargado = await _recargar(db_session, beto.id)
    assert recargado.locked_until is not None  # guarda de la prueba
    assert (await login(cliente, "beto@example.com")).status_code == 401
    return recargado


async def test_administrador_desbloquea_una_cuenta(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    beto = await _beto_bloqueado(cliente, db_session)

    respuesta = await cliente.post(_desbloqueo(beto.id), headers=escenario.h("admin"))

    assert respuesta.status_code == 204
    assert respuesta.content == b""
    recargado = await _recargar(db_session, beto.id)
    assert recargado.failed_login_attempts == 0
    assert recargado.locked_until is None
    fila = await _assert_registro(
        db_session, verbo="unlock_user", actor_id=escenario.ids["admin"], resource_id=beto.id
    )
    assert fila.project_id is None
    assert fila.details == {"was_locked": True}
    assert (await login(cliente, "beto@example.com")).status_code == 200


async def test_el_detalle_muestra_el_bloqueo_y_el_desbloqueo_lo_quita(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """``UserOut.locked_until``: el Dashboard lo usa para "Bloqueada hasta" y el botón."""
    beto = await _beto_bloqueado(cliente, db_session)

    antes = await cliente.get(_usuario(beto.id), headers=escenario.h("admin"))
    assert antes.status_code == 200
    assert antes.json()["locked_until"] is not None
    assert "failed_login_attempts" not in antes.text

    await cliente.post(_desbloqueo(beto.id), headers=escenario.h("admin"))

    despues = await cliente.get(_usuario(beto.id), headers=escenario.h("admin"))
    assert despues.json()["locked_until"] is None


async def test_desbloquear_no_corta_las_sesiones(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """El bloqueo no afecta a los tokens vivos, así que desbloquear no aplica H-37."""
    beto, access = await _beto_con_sesion(cliente, db_session)

    respuesta = await cliente.post(_desbloqueo(beto.id), headers=escenario.h("admin"))

    assert respuesta.status_code == 204
    assert (await _recargar(db_session, beto.id)).tokens_invalid_before is None
    assert await _me(cliente, access) == 200


async def test_desbloquear_una_cuenta_no_bloqueada_es_idempotente(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_a = escenario.ids["dev_a"]

    respuesta = await cliente.post(_desbloqueo(dev_a), headers=escenario.h("admin"))

    assert respuesta.status_code == 204
    fila = await _assert_registro(
        db_session, verbo="unlock_user", actor_id=escenario.ids["admin"], resource_id=dev_a
    )
    assert fila.details == {"was_locked": False}


async def test_desbloquear_con_cuatro_fallos_reinicia_el_contador(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Sin bloqueo vigente también limpia el contador: el quinto fallo ya no bloquearía."""
    beto = await crear_usuario(db_session, "beto@example.com", name="Beto", asignaciones=())
    for _ in range(4):
        await login(cliente, "beto@example.com", EQUIVOCADA)

    await cliente.post(_desbloqueo(beto.id), headers=escenario.h("admin"))

    assert (await _recargar(db_session, beto.id)).failed_login_attempts == 0


async def test_desbloquear_a_un_usuario_inexistente_da_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(_desbloqueo(uuid4()), headers=escenario.h("admin"))

    assert_problema(respuesta, 404, "resource-not-found")


async def test_el_administrador_no_se_desbloquea_a_si_mismo(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-78: con un access robado del Administrador, desbloquearse reiniciaría el contador y
    dejaría seguir adivinando su contraseña en ``/users/me/password`` (spec §3.6)."""
    admin = escenario.ids["admin"]
    usuario = await _recargar(db_session, admin)
    usuario.failed_login_attempts = 3
    await db_session.commit()

    respuesta = await cliente.post(_desbloqueo(admin), headers=escenario.h("admin"))

    assert_problema(respuesta, 409, "conflict")
    assert (await _recargar(db_session, admin)).failed_login_attempts == 3


# --- POST /users/{uid}/password-reset (H-78) ------------------------------------------------------

TEMPORAL = "marcador-temporal-larga"  # noqa: S105  # marcador de prueba, no un secreto


def _restablecimiento(uid: UUID | str) -> str:
    return _usuario(uid, "/password-reset")


def _cuerpo_restablecer(password: str = TEMPORAL) -> dict[str, Any]:
    return {"new_password": password}


async def test_restablecer_cambia_la_contrasena_y_corta_las_sesiones(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-78 con H-37: caen el access y el refresh previos, también los de quien se los robó."""
    beto, access = await _beto_con_sesion(cliente, db_session)
    refresh = cliente.cookies.get(COOKIE_REFRESH)
    assert refresh is not None
    hash_previo = beto.password_hash

    respuesta = await cliente.post(
        _restablecimiento(beto.id), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    assert respuesta.status_code == 204
    assert respuesta.content == b""
    recargado = await _recargar(db_session, beto.id)
    assert recargado.password_hash != hash_previo
    assert recargado.password_hash.startswith("$argon2id$")
    assert recargado.tokens_invalid_before is not None
    assert await _me(cliente, access) == 401
    refresco = await cliente.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE_REFRESH}={refresh}"}
    )
    assert_problema(refresco, 401, "authentication-failed")
    assert (await login(cliente, "beto@example.com")).status_code == 401
    assert (await login(cliente, "beto@example.com", TEMPORAL)).status_code == 200


async def test_restablecer_registra_sin_la_contrasena(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    dev_a = escenario.ids["dev_a"]

    await cliente.post(
        _restablecimiento(dev_a), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    fila = await _assert_registro(
        db_session, verbo="reset_password", actor_id=escenario.ids["admin"], resource_id=dev_a
    )
    assert fila.project_id is None
    assert fila.details is None
    filas = (await db_session.scalars(select(AuditLog))).all()
    assert all(TEMPORAL not in str(f.details) for f in filas)
    assert all("$argon2" not in str(f.details) for f in filas)


async def test_restablecer_limpia_el_bloqueo(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    beto = await _beto_bloqueado(cliente, db_session)

    respuesta = await cliente.post(
        _restablecimiento(beto.id), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    assert respuesta.status_code == 204
    recargado = await _recargar(db_session, beto.id)
    assert recargado.failed_login_attempts == 0
    assert recargado.locked_until is None
    assert (await login(cliente, "beto@example.com", TEMPORAL)).status_code == 200


@pytest.mark.parametrize("password", CONTRASENAS_INVALIDAS)
async def test_restablecer_con_contrasena_fuera_de_politica_da_422(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, password: str
) -> None:
    dev_a = escenario.ids["dev_a"]
    hash_previo = (await _recargar(db_session, dev_a)).password_hash

    respuesta = await cliente.post(
        _restablecimiento(dev_a), json=_cuerpo_restablecer(password), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 422, "semantic-error")
    assert password not in respuesta.text
    recargado = await _recargar(db_session, dev_a)
    assert recargado.password_hash == hash_previo
    assert recargado.tokens_invalid_before is None  # sin cambio no hay corte H-37


@pytest.mark.parametrize(
    "cuerpo",
    [
        pytest.param({}, id="sin-contrasena"),
        pytest.param({"new_password": TEMPORAL, "is_active": True}, id="campo-extra"),
        pytest.param({"password": TEMPORAL}, id="nombre-equivocado"),
        pytest.param({"new_password": ""}, id="vacia"),
    ],
)
async def test_restablecer_con_cuerpo_invalido_da_400(
    cliente: AsyncClient, escenario: Escenario, cuerpo: dict[str, Any]
) -> None:
    respuesta = await cliente.post(
        _restablecimiento(escenario.ids["dev_a"]), json=cuerpo, headers=escenario.h("admin")
    )

    assert_problema(respuesta, 400, "validation-error")
    assert TEMPORAL not in respuesta.text


async def test_restablecer_a_un_usuario_inexistente_da_404(
    cliente: AsyncClient, escenario: Escenario
) -> None:
    respuesta = await cliente.post(
        _restablecimiento(uuid4()), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 404, "resource-not-found")


async def test_el_administrador_no_restablece_su_propia_contrasena(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """H-78: la propia se cambia con ``/users/me/password``, que reverifica la actual; aquí un
    access robado bastaría para adueñarse de la cuenta (spec §3.6)."""
    admin = escenario.ids["admin"]
    hash_previo = (await _recargar(db_session, admin)).password_hash

    respuesta = await cliente.post(
        _restablecimiento(admin), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    assert_problema(respuesta, 409, "conflict")
    recargado = await _recargar(db_session, admin)
    assert recargado.password_hash == hash_previo
    assert recargado.tokens_invalid_before is None
    assert await _me(cliente, escenario.tokens["admin"]) == 200


async def test_restablecer_a_un_usuario_inactivo_se_admite(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession
) -> None:
    """Se puede preparar la contraseña antes de reactivar la cuenta; sigue inactiva."""
    dev_a = escenario.ids["dev_a"]
    await cliente.delete(_usuario(dev_a), headers=escenario.h("admin"))

    respuesta = await cliente.post(
        _restablecimiento(dev_a), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )

    assert respuesta.status_code == 204
    assert (await _recargar(db_session, dev_a)).is_active is False


async def test_el_hash_del_restablecimiento_se_calcula_fuera_del_ciclo_de_eventos(
    cliente: AsyncClient, escenario: Escenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H-72: igual que en el alta, el Argon2id corre en otro hilo."""
    real = usuarios_mod.hash_password
    en_hilo_principal: list[bool] = []

    def _espia(password: str) -> str:
        en_hilo_principal.append(threading.current_thread() is threading.main_thread())
        return real(password)

    monkeypatch.setattr(usuarios_mod, "hash_password", _espia)

    respuesta = await cliente.post(
        _restablecimiento(escenario.ids["dev_a"]),
        json=_cuerpo_restablecer(),
        headers=escenario.h("admin"),
    )

    assert respuesta.status_code == 204
    assert en_hilo_principal == [False]


async def test_la_contrasena_temporal_no_llega_a_los_logs(
    cliente: AsyncClient, escenario: Escenario, caplog: pytest.LogCaptureFixture
) -> None:
    """Sin secretos en claro (RNF-006): ni en el éxito ni en el 422."""
    caplog.set_level(logging.DEBUG)
    uid = escenario.ids["dev_a"]

    await cliente.post(
        _restablecimiento(uid), json=_cuerpo_restablecer(), headers=escenario.h("admin")
    )
    await cliente.post(
        _restablecimiento(uid), json=_cuerpo_restablecer(COMUN), headers=escenario.h("admin")
    )

    assert TEMPORAL not in caplog.text
    assert COMUN not in caplog.text


# --- Autorización de unlock y password-reset (H-14, H-23a, H-78) ----------------------------------


@pytest.mark.parametrize("sufijo", ["/unlock", "/password-reset"])
async def test_sin_users_manage_es_403_aunque_el_usuario_no_exista(
    cliente: AsyncClient, escenario: Escenario, db_session: AsyncSession, sufijo: str
) -> None:
    """Recurso de instancia: el 403 no depende de que exista el usuario (un 404 enumeraría
    cuentas). La dependencia se resuelve antes que el cuerpo."""
    respuesta = await cliente.post(
        _usuario(uuid4(), sufijo), json=_cuerpo_restablecer(), headers=escenario.h("lider_a")
    )

    assert_problema(respuesta, 403, "permission-denied")
    await assert_denegacion(
        db_session,
        actor_id=escenario.ids["lider_a"],
        permiso="users:manage",
        status=403,
        project_id=None,
        resource_type="user",
    )


@pytest.mark.parametrize("sufijo", ["/unlock", "/password-reset"])
async def test_un_pat_no_desbloquea_ni_restablece(
    cliente: AsyncClient,
    escenario: Escenario,
    db_session: AsyncSession,
    signer_app: JwtSigner,
    settings_app: Settings,
    sufijo: str,
) -> None:
    pat = await pat_de_a_dev(db_session, signer_app, settings_app, escenario)

    respuesta = await cliente.post(
        _usuario(escenario.ids["dev_a"], sufijo), json=_cuerpo_restablecer(), headers=bearer(pat)
    )

    assert_problema(respuesta, 403, "permission-denied")


@pytest.mark.parametrize("sufijo", ["/unlock", "/password-reset"])
async def test_desbloquear_y_restablecer_sin_token_da_401(
    cliente: AsyncClient, escenario: Escenario, sufijo: str
) -> None:
    respuesta = await cliente.post(
        _usuario(escenario.ids["dev_a"], sufijo), json=_cuerpo_restablecer()
    )

    assert_problema(respuesta, 401, "authentication-failed")
