"""Servicios de Gestión: usuarios y asignaciones de rol (CU-05; Cap. 6 §Gestión de usuarios; spec
Fase 5 §2, §3.5; H-19, H-22, H-37).

Igual que ``management.projects``: sin HTTP ni permisos (``users:manage`` lo exige antes el API
REST Gateway, H-23a), y cada escritura se registra en el Servicio de Registro de Operaciones en
la misma transacción que el cambio (H-11). Los registros de usuarios van sin ``project_id``
(spec Fase 5 §4.3: solo los ve el Administrador). Jamás llevan contraseñas ni hashes.

**H-37.** Desactivar una cuenta y asignar o quitar roles fijan ``users.tokens_invalid_before``
con el reloj de la aplicación: los access y refresh emitidos antes dejan de servir. Los permisos
ya se leen de la BD en cada petición (spec Fase 5 §4); el corte cubre además el refresh (H-61).

**H-22.** Que una asignación de instancia sea solo de Administrador lo valida el esquema de la
API (400). Si aun así llegara una a la BD, ``rbac.evaluate`` la ignora.

**H-78.** El Administrador desbloquea una cuenta y restablece una contraseña olvidada, nunca
las propias. El restablecimiento fija el corte H-37 y quita el bloqueo; el desbloqueo no corta
sesiones.

**H-59.** La instancia conserva siempre al menos un Administrador **activo**. Desactivar a un
Administrador o quitarle su asignación de instancia toma antes el bloqueo de Administradores y,
si no quedaría otro activo, responde 409 sin cambiar nada.
"""

import asyncio
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.passwords import check_password_policy, hash_password
from portero.auth.tokens import cutoff_from
from portero.db.models import User, UserRoleAssignment
from portero.db.repositories.project import ProjectRepository
from portero.db.repositories.user import UserRepository
from portero.management.errors import (
    InvalidScopeError,
    LastActiveAdministratorError,
    RoleAssignmentConflictError,
    SelfDeactivationError,
    SelfPasswordResetError,
    SelfUnlockError,
    UserEmailConflictError,
)
from portero.oplog.service import OperationActor, OperationEvent, OperationLogService
from portero.rbac.permissions import Role

_UNIQUE_EMAIL = "uq_users_email"
_UNIQUE_ASSIGNMENT = "uq_user_role_assignments_alcance"

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class UserService:
    """Servicio de Gestión de usuarios (Cap. 5, diagrama de componentes: Servicios de Gestión).

    ``clock`` es el reloj de la aplicación, el mismo que pone ``iat`` en los tokens (spec Fase 5
    §3.5): el corte H-37 se calcula con él, no con ``now()`` de la BD.
    """

    def __init__(
        self, oplog: OperationLogService | None = None, *, clock: Clock = _utc_now
    ) -> None:
        self._oplog = oplog or OperationLogService()
        self._clock = clock

    # --- Consultas -------------------------------------------------------------------------------

    async def list_users(self, session: AsyncSession) -> Sequence[User]:
        """Todos los usuarios, activos e inactivos (CU-05)."""
        return await UserRepository(session).list_all()

    async def get_user(self, session: AsyncSession, user_id: UUID) -> User | None:
        """El usuario, o ``None`` (→ 404)."""
        return await UserRepository(session).get_by_id(user_id)

    async def get_assignment(
        self, session: AsyncSession, user_id: UUID, assignment_id: UUID
    ) -> UserRoleAssignment | None:
        """La asignación, solo si es de ``user_id``; si no, ``None`` (→ 404)."""
        return await UserRepository(session).get_assignment(user_id, assignment_id)

    async def list_assignments(
        self, session: AsyncSession, user_id: UUID
    ) -> Sequence[UserRoleAssignment]:
        """Asignaciones de rol del usuario en orden estable: rol, fecha de creación e ``id``
        (CU-05; H-73). La existencia del usuario la comprueba quien llama (→ 404)."""
        return await UserRepository(session).get_assignments(user_id)

    # --- Usuarios --------------------------------------------------------------------------------

    async def create_user(
        self,
        session: AsyncSession,
        actor: OperationActor,
        *,
        email: str,
        name: str | None,
        password: str,
    ) -> User:
        """CU-05: crea una cuenta activa y sin asignaciones, y registra ``create_user``.

        La contraseña pasa por la política del Cap. 6 (mínimo 12, máximo 128, no común; NIST SP
        800-63B §5.1.1; H-30, H-31) y se guarda solo su hash Argon2id (OWASP ASVS V2.4.1).

        Raises:
            PasswordPolicyError: la contraseña no cumple la política (→ 422).
            UserEmailConflictError: el correo ya existe (→ 409).
        """
        check_password_policy(password)
        repo = UserRepository(session)
        try:
            if await repo.email_exists(email):
                raise UserEmailConflictError("ya existe un usuario con ese correo")
            password_hash = await asyncio.to_thread(hash_password, password)  # H-72
            user = User(email=email, name=name, password_hash=password_hash)
            await repo.add(user)
            await self._oplog.record(session, _user_event(actor, "create_user", user.id))
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_EMAIL in str(exc.orig):  # carrera entre dos altas con el mismo correo
                raise UserEmailConflictError("ya existe un usuario con ese correo") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return user

    async def update_user(
        self,
        session: AsyncSession,
        actor: OperationActor,
        user: User,
        changes: Mapping[str, Any],
    ) -> User:
        """Aplica un ``PATCH`` (``name``, ``is_active``).

        Si ``is_active`` pasa a ``false`` es una desactivación: fija el corte H-37 y registra
        ``deactivate_user``. En otro caso registra ``update_user``. Ambos con los **nombres** de
        los campos cambiados en ``details`` (spec Fase 5 §5.3).

        Raises:
            SelfDeactivationError: el actor intenta desactivarse a sí mismo (→ 409).
            LastActiveAdministratorError: es el último Administrador activo (→ 409; H-59).
        """
        if changes.get("is_active") is False and user.id == actor.actor_user_id:
            raise SelfDeactivationError("no puedes desactivar tu propia cuenta")
        repo = UserRepository(session)
        try:
            fields = sorted(k for k, v in changes.items() if getattr(user, k) != v)
            deactivating = "is_active" in fields and changes["is_active"] is False
            if deactivating and await repo.assignment_exists(
                user.id, Role.ADMINISTRADOR, None, None
            ):
                await _ensure_another_active_admin(repo, user.id)
            for field in fields:
                setattr(user, field, changes[field])
            await repo.flush()
            if deactivating:
                await repo.set_tokens_invalid_before(user.id, cutoff_from(self._clock()))
            verb = "deactivate_user" if deactivating else "update_user"
            await self._oplog.record(
                session, _user_event(actor, verb, user.id, details={"fields": fields})
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        await session.refresh(user)  # updated_at y tokens_invalid_before los pone la BD
        return user

    async def deactivate_user(
        self, session: AsyncSession, actor: OperationActor, user: User
    ) -> None:
        """``DELETE /users/{uid}``: desactivación lógica, nunca borra la fila (la refieren
        secretos, service accounts y la bitácora). Igual que ``PATCH {"is_active": false}``.

        Raises:
            SelfDeactivationError: el actor intenta desactivarse a sí mismo (→ 409).
            LastActiveAdministratorError: es el último Administrador activo (→ 409; H-59).
        """
        await self.update_user(session, actor, user, {"is_active": False})

    # --- Desbloqueo y restablecimiento (H-78) ----------------------------------------------------

    async def unlock_user(self, session: AsyncSession, actor: OperationActor, user: User) -> None:
        """``POST /users/{uid}/unlock``: reinicia el contador de fallos y quita ``locked_until``
        (Cap. 6 §Política de bloqueo; NIST SP 800-63B §5.2.2) y registra ``unlock_user`` con
        ``details={was_locked}``. Idempotente.

        Toma la fila con ``FOR UPDATE``, como el login que suma los fallos. No fija el corte H-37:
        el bloqueo no afecta a los tokens vivos, así que no hay sesiones que cortar.

        Raises:
            SelfUnlockError: el actor intenta desbloquearse a sí mismo (→ 409).
        """
        if user.id == actor.actor_user_id:
            raise SelfUnlockError("no puedes desbloquear tu propia cuenta")
        repo = UserRepository(session)
        try:
            locked = await repo.get_by_id_for_update(user.id)
            if locked is None:  # quien llama acaba de cargarla; solo con una carrera
                raise LookupError("usuario inexistente")
            was_locked = locked.locked_until is not None and locked.locked_until > self._clock()
            await repo.clear_lockout(locked)
            await self._oplog.record(
                session,
                _user_event(actor, "unlock_user", user.id, details={"was_locked": was_locked}),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

    async def reset_password(
        self, session: AsyncSession, actor: OperationActor, user: User, new_password: str
    ) -> None:
        """``POST /users/{uid}/password-reset``: el Administrador fija una contraseña temporal
        (H-78; OWASP ASVS V2.5).

        1. La contraseña pasa por la política del Cap. 6, igual que en el alta (NIST SP 800-63B
           §5.1.1; H-30, H-31), y se guarda solo su hash Argon2id, calculado fuera del ciclo de
           eventos (H-72).
        2. Fija el corte H-37: todo access y refresh emitido antes deja de servir, también el
           de quien hubiera robado la sesión.
        3. Quita el bloqueo: la cuenta entra de inmediato con la contraseña temporal.
        4. Registra ``reset_password`` sin ``details`` en la misma transacción (H-11). La
           contraseña nunca va a la bitácora.

        Raises:
            SelfPasswordResetError: el actor intenta restablecer la propia (→ 409).
            PasswordPolicyError: la contraseña no cumple la política (→ 422).
        """
        if user.id == actor.actor_user_id:
            raise SelfPasswordResetError("usa Cambiar contraseña para la tuya")
        check_password_policy(new_password)
        repo = UserRepository(session)
        try:
            locked = await repo.get_by_id_for_update(user.id)
            if locked is None:  # quien llama acaba de cargarla; solo con una carrera
                raise LookupError("usuario inexistente")
            new_hash = await asyncio.to_thread(hash_password, new_password)  # H-72
            await repo.update_password_hash(locked, new_hash)
            await repo.set_tokens_invalid_before(user.id, cutoff_from(self._clock()))
            await repo.clear_lockout(locked)
            await self._oplog.record(session, _user_event(actor, "reset_password", user.id))
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

    # --- Asignaciones de rol ---------------------------------------------------------------------

    async def assign_role(
        self,
        session: AsyncSession,
        actor: OperationActor,
        user: User,
        *,
        role_id: int,
        project_id: UUID | None,
        environment_id: UUID | None,
    ) -> UserRoleAssignment:
        """CU-05: asigna un rol con su alcance, fija el corte H-37 y registra ``assign_role``.

        El proyecto debe existir y no estar archivado, y el ambiente debe pertenecer a él (la BD
        no lo garantiza, Cap. 5 §Tabla user_role_assignments).

        Raises:
            InvalidScopeError: proyecto inexistente o ambiente de otro proyecto (→ 422).
            RoleAssignmentConflictError: la asignación ya existe (→ 409; H-19).
        """
        await _check_scope(session, project_id, environment_id)
        repo = UserRepository(session)
        try:
            if await repo.assignment_exists(user.id, role_id, project_id, environment_id):
                raise RoleAssignmentConflictError("el usuario ya tiene esa asignación")
            assignment = UserRoleAssignment(
                user_id=user.id,
                role_id=role_id,
                project_id=project_id,
                environment_id=environment_id,
            )
            await repo.add_assignment(assignment)
            await repo.set_tokens_invalid_before(user.id, cutoff_from(self._clock()))
            await self._oplog.record(
                session,
                _user_event(actor, "assign_role", user.id, details=_assignment_details(assignment)),
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _UNIQUE_ASSIGNMENT in str(exc.orig):  # carrera entre dos asignaciones iguales
                raise RoleAssignmentConflictError("el usuario ya tiene esa asignación") from None
            raise
        except BaseException:
            await session.rollback()
            raise
        return assignment

    async def revoke_role(
        self, session: AsyncSession, actor: OperationActor, assignment: UserRoleAssignment
    ) -> None:
        """CU-05: quita la asignación, fija el corte H-37 y registra ``revoke_role``.

        Raises:
            LastActiveAdministratorError: es la asignación de instancia de Administrador del
                último Administrador activo (→ 409; H-59).
        """
        repo = UserRepository(session)
        details = _assignment_details(assignment)
        try:
            if assignment.role_id == Role.ADMINISTRADOR and assignment.project_id is None:
                await _ensure_another_active_admin(repo, assignment.user_id)
            await repo.delete_assignment(assignment)
            await repo.set_tokens_invalid_before(assignment.user_id, cutoff_from(self._clock()))
            await self._oplog.record(
                session, _user_event(actor, "revoke_role", assignment.user_id, details=details)
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def _ensure_another_active_admin(repo: UserRepository, user_id: UUID) -> None:
    """H-59: con el bloqueo de Administradores tomado, exige que quede **otro** Administrador
    activo además de ``user_id``. Un Administrador inactivo no cuenta: no puede iniciar sesión.

    El bloqueo serializa a dos Administradores que se desactivan o se quitan el rol entre sí al
    mismo tiempo: el segundo cuenta después de que el primero confirma. Se libera con el
    ``commit`` o el ``rollback`` de quien llama.
    """
    await repo.lock_administrators()
    if not await repo.active_user_with_role_exists(Role.ADMINISTRADOR, excluding=user_id):
        raise LastActiveAdministratorError("la instancia debe conservar un Administrador activo")


async def _check_scope(
    session: AsyncSession, project_id: UUID | None, environment_id: UUID | None
) -> None:
    """El proyecto existe y no está archivado; el ambiente, si viene, es de ese proyecto."""
    if project_id is None:
        return
    projects = ProjectRepository(session)
    if await projects.get_active(project_id) is None:
        raise InvalidScopeError("el proyecto no existe")
    if environment_id is not None and (
        await projects.get_environment(project_id, environment_id) is None
    ):
        raise InvalidScopeError("el ambiente no pertenece al proyecto")


def _assignment_details(assignment: UserRoleAssignment) -> dict[str, Any]:
    """``details`` de ``assign_role``/``revoke_role`` (spec Fase 5 §5.3)."""
    return {
        "target_user_id": str(assignment.user_id),
        "role_id": assignment.role_id,
        "project_id": str(assignment.project_id) if assignment.project_id else None,
        "environment_id": str(assignment.environment_id) if assignment.environment_id else None,
    }


def _user_event(
    actor: OperationActor,
    verb: str,
    user_id: UUID,
    *,
    details: dict[str, Any] | None = None,
) -> OperationEvent:
    """Evento sobre un usuario: ``resource_type=user``, sin proyecto ni ambiente."""
    return actor.event(verb, "success", resource_type="user", resource_id=user_id, details=details)
