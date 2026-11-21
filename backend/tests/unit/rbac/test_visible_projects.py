"""Pruebas de ``visible_projects``: proyectos que un actor puede ver (spec Fase 5 §4.2; H-22,
H-23c, H-23d; OWASP ASVS V4.1.3, V4.1.5).

Función pura, como ``evaluate``: recibe las asignaciones ya cargadas y se prueba sin base de
datos. Su resultado filtra ``GET /projects`` y decide el 404 de ``GET /projects/{pid}`` (H-14).
"""

import uuid

import pytest

from portero.rbac.evaluator import (
    ALL_PROJECTS,
    Actor,
    RoleAssignment,
    ServiceScope,
    visible_projects,
)
from portero.rbac.permissions import Role

# Proyecto A con ambientes A_DEV y A_PROD; proyecto B con ambiente B_DEV.
A = uuid.UUID("11111111-1111-4111-8111-111111111111")
A_DEV = uuid.UUID("22222222-2222-4222-8222-222222222222")
A_PROD = uuid.UUID("33333333-3333-4333-8333-333333333333")
B = uuid.UUID("44444444-4444-4444-8444-444444444444")
B_DEV = uuid.UUID("55555555-5555-4555-8555-555555555555")

HUMANO = Actor(actor_type="human")
ADMIN_GLOBAL = RoleAssignment(role_id=Role.ADMINISTRADOR, project_id=None, environment_id=None)
LIDER_A = RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=A, environment_id=None)
DEV_B_DEV = RoleAssignment(role_id=Role.DESARROLLADOR, project_id=B, environment_id=B_DEV)


# --- Humanos ---


def test_administrador_global_ve_todos() -> None:
    assert visible_projects(HUMANO, [ADMIN_GLOBAL]) is ALL_PROJECTS


def test_administrador_global_con_otro_rol_sigue_viendo_todos() -> None:
    assert visible_projects(HUMANO, [LIDER_A, ADMIN_GLOBAL]) is ALL_PROJECTS


def test_lider_de_a_ve_solo_a() -> None:
    assert visible_projects(HUMANO, [LIDER_A]) == frozenset({A})


def test_desarrollador_de_un_ambiente_de_b_ve_b() -> None:
    """H-23d: cubrir un solo ambiente basta para ver el proyecto."""
    assert visible_projects(HUMANO, [DEV_B_DEV]) == frozenset({B})


def test_union_de_asignaciones_en_proyectos_distintos() -> None:
    assert visible_projects(HUMANO, [LIDER_A, DEV_B_DEV]) == frozenset({A, B})


def test_dos_ambientes_del_mismo_proyecto_dan_un_solo_proyecto() -> None:
    asignaciones = [
        RoleAssignment(role_id=Role.DESARROLLADOR, project_id=A, environment_id=A_DEV),
        RoleAssignment(role_id=Role.DESARROLLADOR, project_id=A, environment_id=A_PROD),
    ]
    assert visible_projects(HUMANO, asignaciones) == frozenset({A})


def test_sin_asignaciones_no_ve_ninguno() -> None:
    assert visible_projects(HUMANO, []) == frozenset()


@pytest.mark.parametrize("role", [Role.LIDER_TECNICO, Role.DESARROLLADOR], ids=str)
def test_asignacion_global_de_rol_no_administrador_se_ignora(role: Role) -> None:
    """H-22: igual que en ``evaluate``, una asignación global solo vale para el Administrador."""
    asignaciones = [RoleAssignment(role_id=role, project_id=None, environment_id=None)]
    assert visible_projects(HUMANO, asignaciones) == frozenset()


def test_asignacion_global_ignorada_no_anula_las_demas() -> None:
    asignaciones = [
        RoleAssignment(role_id=Role.LIDER_TECNICO, project_id=None, environment_id=None),
        DEV_B_DEV,
    ]
    assert visible_projects(HUMANO, asignaciones) == frozenset({B})


@pytest.mark.parametrize("role_id", [0, 4, 99])
def test_rol_desconocido_no_da_visibilidad(role_id: int) -> None:
    """Un rol fuera del catálogo no tiene ``secrets:read``: denegación por omisión (V4.1.5)."""
    asignaciones = [RoleAssignment(role_id=role_id, project_id=A, environment_id=None)]
    assert visible_projects(HUMANO, asignaciones) == frozenset()


def test_ambiente_sin_proyecto_se_ignora() -> None:
    """Forma inválida que la BD impide con un CHECK; aquí se ignora (fallar de forma segura)."""
    asignaciones = [
        RoleAssignment(role_id=Role.DESARROLLADOR, project_id=None, environment_id=A_DEV)
    ]
    assert visible_projects(HUMANO, asignaciones) == frozenset()


def test_humano_ignora_el_scope() -> None:
    actor = Actor(actor_type="human", scope=ServiceScope(project_id=A, environment_id=None))
    assert visible_projects(actor, []) == frozenset()


def test_tipo_de_actor_desconocido_no_ve_ninguno() -> None:
    actor = Actor(actor_type="robot")  # type: ignore[arg-type]
    assert visible_projects(actor, [ADMIN_GLOBAL]) == frozenset()


def test_el_resultado_es_inmutable() -> None:
    assert isinstance(visible_projects(HUMANO, [LIDER_A]), frozenset)


# --- Aplicaciones Cliente (actor service) ---


@pytest.mark.parametrize("ambiente", [A_DEV, None], ids=["ambiente", "proyecto"])
def test_service_ve_solo_el_proyecto_de_su_scope(ambiente: uuid.UUID | None) -> None:
    actor = Actor(actor_type="service", scope=ServiceScope(project_id=A, environment_id=ambiente))
    assert visible_projects(actor, []) == frozenset({A})


def test_service_ignora_asignaciones_de_rol() -> None:
    actor = Actor(actor_type="service", scope=ServiceScope(project_id=A, environment_id=A_DEV))
    assert visible_projects(actor, [ADMIN_GLOBAL, DEV_B_DEV]) == frozenset({A})


def test_service_sin_scope_no_ve_ninguno() -> None:
    assert visible_projects(Actor(actor_type="service"), [ADMIN_GLOBAL]) == frozenset()
