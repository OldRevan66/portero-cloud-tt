"""Excepciones de los Servicios de Gestión (proyectos, ambientes, usuarios y Aplicaciones
Cliente; CU-05, CU-07).

Los mensajes no incluyen datos internos (OWASP ASVS V7.4.1). El API REST Gateway traduce cada
una a su Problem Details (spec Fase 5 §6); ninguna se debe a un permiso, eso lo decide antes el
Módulo RBAC.
"""


class ManagementError(Exception):
    """Base de los errores de los Servicios de Gestión."""


class ConflictError(ManagementError):
    """La operación choca con el estado actual → 409 ``conflict`` (spec Fase 5 §6)."""


class SemanticError(ManagementError):
    """La entrada pasa el esquema pero viola una regla de negocio → 422 ``semantic-error``
    (spec Fase 5 §1, §6)."""


class ProjectNameConflictError(ConflictError):
    """Ya existe un proyecto con ese nombre (``projects.name`` es UNIQUE; RF-030)."""


class ProjectHasActiveSecretsError(ConflictError):
    """Archivar un proyecto con secretos activos exige ``?confirm=true`` (RF-032)."""


class EnvironmentNameConflictError(ConflictError):
    """Ya existe un ambiente con ese nombre en el proyecto (UNIQUE (project_id, name))."""


class EnvironmentHasSecretsError(ConflictError):
    """El ambiente tiene secretos, activos o archivados, y no se puede borrar (H-39)."""


class EnvironmentHasServiceAccountsError(ConflictError):
    """Alguna service account, vigente o revocada, apunta al ambiente (H-41): el CASCADE la
    borraría sin ``revoke_service_account`` en la bitácora."""


class UserEmailConflictError(ConflictError):
    """Ya existe un usuario con ese correo (``users.email`` es UNIQUE)."""


class SelfDeactivationError(ConflictError):
    """Un Administrador no puede desactivarse a sí mismo (spec Fase 5 §2, Usuarios)."""


class SelfUnlockError(ConflictError):
    """Un Administrador no puede desbloquearse a sí mismo (H-78): con un access robado bastaría
    para reiniciar el contador y seguir adivinando su contraseña en ``/users/me/password``."""


class SelfPasswordResetError(ConflictError):
    """Un Administrador no restablece su propia contraseña (H-78): la cambia con
    ``/users/me/password``, que reverifica la actual (spec Fase 5 §3.6)."""


class LastActiveAdministratorError(ConflictError):
    """La operación dejaría a la instancia sin Administradores activos (H-59): nadie tendría
    ``users:manage`` y solo se recuperaría con ``portero create-admin`` (H-38)."""


class RoleAssignmentConflictError(ConflictError):
    """La asignación ya existe (UNIQUE NULLS NOT DISTINCT, H-19)."""


class InvalidScopeError(SemanticError):
    """El proyecto no existe o está archivado, o el ambiente no pertenece al proyecto (spec
    Fase 5 §2: "un ambiente que no pertenece al proyecto → 422")."""


class ExpirationInPastError(SemanticError):
    """``expires_at`` de una service account no está en el futuro."""
