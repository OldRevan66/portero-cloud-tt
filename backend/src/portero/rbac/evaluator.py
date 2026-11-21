"""Evaluación de autorización como función pura ``evaluate`` (Algoritmo 5 del Cap. 6;
OWASP ASVS V4.1.3, V4.1.5). Recibe las asignaciones ya cargadas; no consulta la base de datos.

Los tipos de entrada son propios de este módulo (no se importan de ``auth`` ni de ``db``): la
capa que lee el JWT y la que carga ``user_role_assignments`` los construyen. Así el módulo se
prueba completo sin base de datos (spec §4).

Para humanos se usan las asignaciones vigentes en la BD (``LoadAssignments`` del Algoritmo 5),
no el claim ``roles`` del JWT: quitar un rol surte efecto sin esperar a que expire el token.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal
from uuid import UUID

from portero.rbac.permissions import Permission, Role, permissions_of_role


@dataclass(frozen=True)
class AccessContext:
    """``ctx`` del Algoritmo 5: proyecto y ambiente del recurso; ambos pueden ser nulos
    (ambos nulos = operación de instancia, p. ej. crear proyectos o gestionar usuarios)."""

    project_id: UUID | None
    environment_id: UUID | None


@dataclass(frozen=True)
class RoleAssignment:
    """Una fila de ``user_role_assignments`` (Cap. 5): rol con alcance instancia (ambos nulos),
    proyecto (solo ``project_id``) o ambiente (ambos)."""

    role_id: int
    project_id: UUID | None
    environment_id: UUID | None


@dataclass(frozen=True)
class ServiceScope:
    """Claim ``scope`` del PAT de una Aplicación Cliente (Cap. 6, §Autenticación de
    Aplicaciones Cliente). El ambiente es opcional, como en ``service_accounts``."""

    project_id: UUID
    environment_id: UUID | None


@dataclass(frozen=True)
class Actor:
    """Actor autenticado, tomado de los claims del JWT validado (spec §3.2)."""

    actor_type: Literal["human", "service"]
    scope: ServiceScope | None = None


def scope_matches(project_id: UUID | None, environment_id: UUID | None, ctx: AccessContext) -> bool:
    """``ScopeMatches`` del Algoritmo 5: ¿el alcance (``project_id``, ``environment_id``) cubre
    el contexto de la petición?

    - Instancia (ambos nulos): cubre cualquier contexto.
    - Proyecto (solo ``project_id``): cubre el proyecto y todos sus ambientes.
    - Ambiente (ambos): exige coincidencia exacta de los dos campos.

    Un ambiente sin proyecto (en el alcance o en el contexto) es una forma inválida: la BD lo
    impide con un CHECK, pero aquí también se responde ``False`` (fallar de forma segura).
    """
    if ctx.environment_id is not None and ctx.project_id is None:
        return False
    if project_id is None:
        return environment_id is None
    if environment_id is None:
        return ctx.project_id == project_id
    return ctx.project_id == project_id and ctx.environment_id == environment_id


def _evaluate_service_scope(
    scope: ServiceScope | None, permission: Permission, ctx: AccessContext
) -> bool:
    """``EvaluateServiceScope`` del Algoritmo 5: una Aplicación Cliente solo puede leer
    secretos, y solo dentro del proyecto/ambiente de su PAT (spec §4)."""
    if scope is None or permission is not Permission.SECRETS_READ:
        return False
    return scope_matches(scope.project_id, scope.environment_id, ctx)


def _is_global(assignment: RoleAssignment) -> bool:
    return assignment.project_id is None and assignment.environment_id is None


def evaluate(
    actor: Actor,
    permission: Permission,
    ctx: AccessContext,
    assignments: Iterable[RoleAssignment],
) -> bool:
    """Decide si ``actor`` puede ejercer ``permission`` en ``ctx`` (Algoritmo 5 del Cap. 6).

    - Actor ``service``: se evalúa solo contra el ``scope`` del token; ``assignments`` se ignora
      (las Aplicaciones Cliente no son sujetos del catálogo RBAC).
    - Actor ``human``: unión de sus asignaciones; se permite si **alguna** cubre el contexto y
      su rol tiene el permiso. Una asignación global de un rol que no es Administrador se ignora
      (el Cap. 6 reserva ese alcance al Administrador; H-22).
    - En cualquier otro caso, denegación por omisión (OWASP ASVS V4.1.3, V4.1.5).
    """
    if actor.actor_type == "service":
        return _evaluate_service_scope(actor.scope, permission, ctx)
    if actor.actor_type != "human":
        return False
    for assignment in assignments:
        if _is_global(assignment) and assignment.role_id != Role.ADMINISTRADOR:
            continue
        if not scope_matches(assignment.project_id, assignment.environment_id, ctx):
            continue
        if permission in permissions_of_role(assignment.role_id):
            return True
    return False


class AllProjects(Enum):
    """Marca de "todos los proyectos" que devuelve ``visible_projects`` para un Administrador
    de instancia. Es un ``Enum`` de un solo miembro para que mypy distinga el caso con ``is``."""

    ALL = "all"


ALL_PROJECTS: Final = AllProjects.ALL


def visible_projects(
    actor: Actor, assignments: Iterable[RoleAssignment]
) -> AllProjects | frozenset[UUID]:
    """Proyectos que ``actor`` puede ver (spec Fase 5 §4.2; H-23c, H-23d; OWASP ASVS V4.1.3).

    ``GET /projects`` no es una evaluación puntual sino un filtrado (H-23c). Un proyecto es
    visible si el actor cubre el proyecto **o al menos uno de sus ambientes** con un rol que
    tenga ``secrets:read`` (H-23d):

    - Actor ``service``: solo el proyecto de su ``scope``; ``assignments`` se ignora.
    - Actor ``human``: una asignación de instancia de Administrador → ``ALL_PROJECTS``. En otro
      caso, los ``project_id`` de sus asignaciones de proyecto o de ambiente. Las asignaciones
      globales de otros roles se ignoran, igual que en ``evaluate`` (H-22).
    - Un rol fuera del catálogo, una forma inválida (ambiente sin proyecto) o un tipo de actor
      desconocido no otorgan nada: denegación por omisión (OWASP ASVS V4.1.3, V4.1.5).
    """
    if actor.actor_type == "service":
        return frozenset({actor.scope.project_id}) if actor.scope is not None else frozenset()
    if actor.actor_type != "human":
        return frozenset()
    visibles: set[UUID] = set()
    for assignment in assignments:
        if Permission.SECRETS_READ not in permissions_of_role(assignment.role_id):
            continue
        if _is_global(assignment):
            if assignment.role_id == Role.ADMINISTRADOR:
                return ALL_PROJECTS
            continue
        if assignment.project_id is not None:
            visibles.add(assignment.project_id)
    return frozenset(visibles)
