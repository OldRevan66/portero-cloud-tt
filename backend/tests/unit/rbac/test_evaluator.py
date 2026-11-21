"""Pruebas del evaluador de permisos: Algoritmo 5 del Cap. 6 (spec §4; OWASP ASVS V4.1.3, V4.1.5).

El evaluador es una función pura: recibe las asignaciones ya cargadas, así que todo se prueba sin
base de datos. El oráculo de la matriz (``MATRIZ_CAP6``) se transcribe a mano de la tabla
"Matriz rol-permiso" del Cap. 6 y **no** se deriva de ``ROLE_PERMISSIONS``: si la constante del
código tuviera un error, la prueba lo detecta en vez de confirmarlo.
"""

import uuid
from collections.abc import Sequence
from typing import Any

import pytest

from portero.rbac.evaluator import (
    AccessContext,
    Actor,
    RoleAssignment,
    ServiceScope,
    evaluate,
    scope_matches,
)
from portero.rbac.permissions import Permission, Role

# Proyecto P con ambientes E1 y E2; proyecto ajeno Q con ambiente EQ.
P = uuid.UUID("11111111-1111-4111-8111-111111111111")
E1 = uuid.UUID("22222222-2222-4222-8222-222222222222")
E2 = uuid.UUID("33333333-3333-4333-8333-333333333333")
Q = uuid.UUID("44444444-4444-4444-8444-444444444444")
EQ = uuid.UUID("55555555-5555-4555-8555-555555555555")

HUMANO = Actor(actor_type="human")
CTX_INSTANCIA = AccessContext(project_id=None, environment_id=None)
CTX_P = AccessContext(project_id=P, environment_id=None)
CTX_P_E1 = AccessContext(project_id=P, environment_id=E1)
CTX_P_E2 = AccessContext(project_id=P, environment_id=E2)
CTX_Q_EQ = AccessContext(project_id=Q, environment_id=EQ)
TODOS_LOS_CTX = [CTX_INSTANCIA, CTX_P, CTX_P_E1, CTX_P_E2, CTX_Q_EQ]

# --- Oráculo: tabla "Matriz rol-permiso" del Cap. 6, transcrita a mano ---
_SI, _NO = True, False
MATRIZ_CAP6: dict[str, dict[str, bool]] = {
    #                    Administrador, Líder Técnico, Desarrollador
    "secrets:read": {"admin": _SI, "lider": _SI, "dev": _SI},
    "secrets:write": {"admin": _SI, "lider": _SI, "dev": _NO},
    "secrets:rotate": {"admin": _SI, "lider": _SI, "dev": _NO},
    "secrets:delete": {"admin": _SI, "lider": _SI, "dev": _NO},
    "projects:manage": {"admin": _SI, "lider": _SI, "dev": _NO},
    "users:manage": {"admin": _SI, "lider": _NO, "dev": _NO},
    "audit:read": {"admin": _SI, "lider": _SI, "dev": _NO},
    "system:configure": {"admin": _SI, "lider": _NO, "dev": _NO},
}
ROLES = {"admin": Role.ADMINISTRADOR, "lider": Role.LIDER_TECNICO, "dev": Role.DESARROLLADOR}

# Alcance de la asignación → (project_id, environment_id, ¿cubre el ctx (P, E1)?).
# El ctx de la petición es siempre el ambiente E1 del proyecto P.
ALCANCES: dict[str, tuple[uuid.UUID | None, uuid.UUID | None, bool]] = {
    "instancia": (None, None, True),
    "proyecto_propio": (P, None, True),
    "proyecto_ajeno": (Q, None, False),
    "ambiente_exacto": (P, E1, True),
    "otro_ambiente": (P, E2, False),
}


def _casos_matriz() -> list[Any]:
    casos = []
    for rol in ROLES:
        for permiso, por_rol in MATRIZ_CAP6.items():
            for alcance, (_, _, cubre) in ALCANCES.items():
                # H-22: una asignación global solo vale para el Administrador.
                global_valida = alcance != "instancia" or rol == "admin"
                esperado = por_rol[rol] and cubre and global_valida
                casos.append(
                    pytest.param(rol, permiso, alcance, esperado, id=f"{rol}-{permiso}-{alcance}")
                )
    return casos


def test_el_oraculo_cubre_el_catalogo_completo() -> None:
    """Si alguien agrega un permiso al enum, el oráculo debe actualizarse también."""
    assert set(MATRIZ_CAP6) == {p.value for p in Permission}


@pytest.mark.parametrize(("rol", "permiso", "alcance", "esperado"), _casos_matriz())
def test_matriz_rol_permiso_alcance(rol: str, permiso: str, alcance: str, esperado: bool) -> None:
    """3 roles × 8 permisos × 5 alcances = 120 casos contra el ctx (P, E1)."""
    project_id, environment_id, _ = ALCANCES[alcance]
    asignacion = RoleAssignment(
        role_id=ROLES[rol], project_id=project_id, environment_id=environment_id
    )
    assert evaluate(HUMANO, Permission(permiso), CTX_P_E1, [asignacion]) is esperado


# --- ScopeMatches ---


@pytest.mark.parametrize(
    ("proyecto", "ambiente", "ctx", "esperado"),
    [
        # Asignación de instancia: cubre cualquier contexto.
        (None, None, CTX_INSTANCIA, True),
        (None, None, CTX_P, True),
        (None, None, CTX_P_E1, True),
        (None, None, CTX_Q_EQ, True),
        # Asignación de proyecto: cubre el proyecto y todos sus ambientes, nada más.
        (P, None, CTX_INSTANCIA, False),
        (P, None, CTX_P, True),
        (P, None, CTX_P_E1, True),
        (P, None, CTX_P_E2, True),
        (P, None, CTX_Q_EQ, False),
        # Asignación de ambiente: coincidencia exacta de ambos campos.
        (P, E1, CTX_INSTANCIA, False),
        (P, E1, CTX_P, False),
        (P, E1, CTX_P_E1, True),
        (P, E1, CTX_P_E2, False),
        (P, E1, AccessContext(project_id=Q, environment_id=E1), False),
        # Formas inválidas (ambiente sin proyecto): nunca cubren (fallar de forma segura).
        (None, E1, CTX_P_E1, False),
        (None, None, AccessContext(project_id=None, environment_id=E1), False),
        (P, None, AccessContext(project_id=None, environment_id=E1), False),
    ],
)
def test_scope_matches(
    proyecto: uuid.UUID | None,
    ambiente: uuid.UUID | None,
    ctx: AccessContext,
    esperado: bool,
) -> None:
    assert scope_matches(proyecto, ambiente, ctx) is esperado


# --- Asignaciones múltiples (unión de asignaciones, Cap. 6 §Asignación múltiple) ---


def test_admin_global_mas_lider_en_un_proyecto() -> None:
    asignaciones = [
        RoleAssignment(role_id=Role.ADMINISTRADOR, project_id=None, environment_id=None),
        RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=P, environment_id=None),
    ]
    for ctx in TODOS_LOS_CTX:
        for permiso in Permission:
            assert evaluate(HUMANO, permiso, ctx, asignaciones) is True


def test_el_orden_de_las_asignaciones_no_importa() -> None:
    asignaciones = [
        RoleAssignment(role_id=Role.DESARROLLADOR, project_id=P, environment_id=None),
        RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=P, environment_id=None),
    ]
    assert evaluate(HUMANO, Permission.SECRETS_ROTATE, CTX_P_E1, asignaciones) is True
    assert evaluate(HUMANO, Permission.SECRETS_ROTATE, CTX_P_E1, asignaciones[::-1]) is True


def test_no_se_mezcla_el_rol_de_un_alcance_con_el_alcance_de_otro() -> None:
    """Líder en P y Desarrollador en Q: en Q solo lee, aunque "tenga" el rol de Líder."""
    asignaciones = [
        RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=P, environment_id=None),
        RoleAssignment(role_id=Role.DESARROLLADOR, project_id=Q, environment_id=None),
    ]
    assert evaluate(HUMANO, Permission.SECRETS_READ, CTX_Q_EQ, asignaciones) is True
    assert evaluate(HUMANO, Permission.SECRETS_WRITE, CTX_Q_EQ, asignaciones) is False
    assert evaluate(HUMANO, Permission.SECRETS_WRITE, CTX_P_E1, asignaciones) is True


def test_lider_no_crea_proyectos_ni_gestiona_usuarios() -> None:
    """Crear proyectos y gestionar usuarios tiene alcance de instancia (tabla de endpoints)."""
    asignaciones = [RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=P, environment_id=None)]
    assert evaluate(HUMANO, Permission.PROJECTS_MANAGE, CTX_INSTANCIA, asignaciones) is False
    assert evaluate(HUMANO, Permission.PROJECTS_MANAGE, CTX_P, asignaciones) is True
    assert evaluate(HUMANO, Permission.USERS_MANAGE, CTX_P, asignaciones) is False


# --- Denegación por omisión (ASVS V4.1.3, V4.1.5) ---


@pytest.mark.parametrize("permiso", list(Permission), ids=str)
@pytest.mark.parametrize("ctx", TODOS_LOS_CTX)
def test_sin_asignaciones_se_deniega(permiso: Permission, ctx: AccessContext) -> None:
    assert evaluate(HUMANO, permiso, ctx, []) is False


@pytest.mark.parametrize("role", [Role.LIDER_TECNICO, Role.DESARROLLADOR], ids=str)
@pytest.mark.parametrize("ctx", TODOS_LOS_CTX)
def test_asignacion_global_de_rol_no_administrador_se_ignora(
    role: Role, ctx: AccessContext
) -> None:
    """H-22: la BD no impide una asignación global de Líder o Desarrollador; el evaluador la
    ignora para que un dato erróneo no otorgue permisos sobre toda la instancia."""
    asignaciones = [RoleAssignment(role_id=role, project_id=None, environment_id=None)]
    for permiso in Permission:
        assert evaluate(HUMANO, permiso, ctx, asignaciones) is False


@pytest.mark.parametrize("role_id", [0, 4, 99])
def test_rol_desconocido_se_deniega(role_id: int) -> None:
    asignaciones = [RoleAssignment(role_id=role_id, project_id=P, environment_id=None)]
    for permiso in Permission:
        assert evaluate(HUMANO, permiso, CTX_P_E1, asignaciones) is False


def test_tipo_de_actor_desconocido_se_deniega() -> None:
    """Un ``actor_type`` fuera de {human, service} no llega a evaluar asignaciones."""
    actor = Actor(actor_type="robot")  # type: ignore[arg-type]
    admin_global = [
        RoleAssignment(role_id=Role.ADMINISTRADOR, project_id=None, environment_id=None)
    ]
    assert evaluate(actor, Permission.SECRETS_READ, CTX_P_E1, admin_global) is False


# --- Aplicaciones Cliente (actor service, claim scope del PAT) ---

PAT_AMBIENTE = Actor(actor_type="service", scope=ServiceScope(project_id=P, environment_id=E1))
PAT_PROYECTO = Actor(actor_type="service", scope=ServiceScope(project_id=P, environment_id=None))


@pytest.mark.parametrize(
    ("ctx", "esperado"),
    [
        (CTX_P_E1, True),
        (CTX_P_E2, False),
        (CTX_P, False),
        (CTX_Q_EQ, False),
        (CTX_INSTANCIA, False),
    ],
)
def test_service_con_scope_de_ambiente_solo_lee_su_ambiente(
    ctx: AccessContext, esperado: bool
) -> None:
    assert evaluate(PAT_AMBIENTE, Permission.SECRETS_READ, ctx, []) is esperado


@pytest.mark.parametrize(
    ("ctx", "esperado"),
    [
        (CTX_P, True),
        (CTX_P_E1, True),
        (CTX_P_E2, True),
        (CTX_Q_EQ, False),
        (CTX_INSTANCIA, False),
    ],
)
def test_service_con_scope_de_proyecto_lee_todos_sus_ambientes(
    ctx: AccessContext, esperado: bool
) -> None:
    """``service_accounts.environment_id`` es opcional: sin él, el PAT cubre todo el proyecto."""
    assert evaluate(PAT_PROYECTO, Permission.SECRETS_READ, ctx, []) is esperado


@pytest.mark.parametrize(
    "permiso", [p for p in Permission if p is not Permission.SECRETS_READ], ids=str
)
@pytest.mark.parametrize("actor", [PAT_AMBIENTE, PAT_PROYECTO], ids=["ambiente", "proyecto"])
def test_service_no_tiene_otro_permiso_que_secrets_read(actor: Actor, permiso: Permission) -> None:
    """Ni siquiera dentro de su propio ambiente (Cap. 6 §Modelo RBAC, Aplicaciones Cliente)."""
    assert evaluate(actor, permiso, CTX_P_E1, []) is False


def test_service_sin_scope_se_deniega() -> None:
    actor = Actor(actor_type="service")
    assert evaluate(actor, Permission.SECRETS_READ, CTX_P_E1, []) is False


def test_service_ignora_asignaciones_de_rol() -> None:
    """Las Aplicaciones Cliente no son sujetos del catálogo RBAC: solo cuenta su ``scope``."""
    admin_global: Sequence[RoleAssignment] = [
        RoleAssignment(role_id=Role.ADMINISTRADOR, project_id=None, environment_id=None)
    ]
    assert evaluate(PAT_AMBIENTE, Permission.SECRETS_WRITE, CTX_P_E1, admin_global) is False
    assert evaluate(PAT_AMBIENTE, Permission.SECRETS_READ, CTX_Q_EQ, admin_global) is False


def test_humano_ignora_el_scope() -> None:
    """Un ``scope`` en un actor humano no otorga nada: los humanos se evalúan por asignaciones."""
    actor = Actor(actor_type="human", scope=ServiceScope(project_id=P, environment_id=E1))
    assert evaluate(actor, Permission.SECRETS_READ, CTX_P_E1, []) is False
