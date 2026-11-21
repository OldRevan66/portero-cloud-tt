"""Catálogo cerrado de permisos y matriz rol→permisos como constante en código
(políticas como código, OWASP ASVS V1.4.4).

Transcribe las tablas "Catálogo cerrado de permisos" y "Matriz rol-permiso" del Cap. 6
(§Modelo RBAC). La matriz no vive en la base de datos: cambiarla exige un cambio de código
con revisión y despliegue, no una operación de datos en caliente.
"""

from collections.abc import Mapping
from enum import IntEnum, StrEnum
from types import MappingProxyType


class Permission(StrEnum):
    """Permisos del sistema en notación ``recurso:accion`` (OWASP Authorization Cheat Sheet).

    Lista cerrada: el operador no puede agregar permisos (Cap. 6, §Catálogo de permisos).
    """

    SECRETS_READ = "secrets:read"
    SECRETS_WRITE = "secrets:write"
    SECRETS_ROTATE = "secrets:rotate"
    SECRETS_DELETE = "secrets:delete"
    PROJECTS_MANAGE = "projects:manage"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    SYSTEM_CONFIGURE = "system:configure"


class Role(IntEnum):
    """Roles humanos del catálogo (RF-011). Los valores son los ``roles.id`` que siembra la
    migración inicial (spec §2)."""

    ADMINISTRADOR = 1
    LIDER_TECNICO = 2
    DESARROLLADOR = 3


_LECTURA = frozenset({Permission.SECRETS_READ})
_GESTION_DE_SECRETOS = _LECTURA | {
    Permission.SECRETS_WRITE,
    Permission.SECRETS_ROTATE,
    Permission.SECRETS_DELETE,
}

ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.ADMINISTRADOR: frozenset(Permission),
        # "Solo sus proyectos" (superíndice a de la matriz) no se codifica aquí: lo garantiza
        # el alcance de la asignación, porque un Líder nunca tiene alcance global (H-22).
        Role.LIDER_TECNICO: _GESTION_DE_SECRETOS
        | {Permission.PROJECTS_MANAGE, Permission.AUDIT_READ},
        Role.DESARROLLADOR: _LECTURA,
    }
)
"""Matriz rol→permisos del Cap. 6. ``MappingProxyType`` + ``frozenset`` la hacen inmutable en
tiempo de ejecución."""


def permissions_of_role(role_id: int) -> frozenset[Permission]:
    """Permisos de un rol: ``PermissionsOfRole`` del Algoritmo 5 del Cap. 6.

    Recibe el ``int`` que guarda ``user_role_assignments.role_id``. Un id fuera del catálogo
    devuelve el conjunto vacío en lugar de lanzar ``KeyError``: denegación por omisión
    (OWASP ASVS V4.1.3, V4.1.5).
    """
    try:
        role = Role(role_id)
    except ValueError:
        return frozenset()
    return ROLE_PERMISSIONS[role]
