"""``UserRepository`` y ``RevokedTokenRepository``: usuarios, asignaciones de rol y tokens
revocados (Capa de Persistencia, Cap. 5 §Componentes).

Todo acceso a ``users``, ``user_role_assignments`` y ``revoked_tokens`` pasa por aquí. Las
consultas usan el constructor de SQLAlchemy con parámetros enlazados, nunca cadenas concatenadas
(OWASP ASVS V5.3.4; riesgo P-04 del Cap. 5).

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import exists, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import RevokedToken, Role, User, UserRoleAssignment

ADMINISTRATORS_LOCK_KEY = 0x61646D696E
"""Llave de ``pg_advisory_xact_lock`` que serializa los cambios que pueden dejar a la instancia
sin Administradores activos (H-59).

Es ``b"admin"`` leído como entero, distinta de ``OPLOG_CHAIN_LOCK_KEY`` (``b"oplog"``). Quien la
toma lo hace antes de registrar la operación, así que el orden es siempre admin → oplog y no hay
interbloqueo entre las dos."""


class UserRepository:
    """Acceso a ``users`` y ``user_role_assignments`` (Cap. 5 §Tabla users; spec núcleo §3.1)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email_for_update(self, email: str) -> User | None:
        """``SELECT ... FROM users WHERE email = :email FOR UPDATE`` (paso inicial del login).

        Bloquea la fila hasta el fin de la transacción: dos logins fallidos simultáneos no pueden
        leer el mismo contador y perder un incremento, lo que permitiría superar el límite de
        intentos (NIST SP 800-63B §5.2.2).
        """
        stmt = (
            select(User)
            .where(User.email == email)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Usuario por id, con los valores vigentes en la base (``is_active`` y
        ``tokens_invalid_before`` se revisan en cada refresh; spec Fase 5 §3.5)."""
        stmt = select(User).where(User.id == user_id).execution_options(populate_existing=True)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_id_for_update(self, user_id: uuid.UUID) -> User | None:
        """Usuario por id con ``FOR UPDATE``: el cambio de contraseña lee y actualiza el
        contador de fallos sin perder incrementos concurrentes (como el login)."""
        stmt = (
            select(User)
            .where(User.id == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_all(self) -> Sequence[User]:
        """Todos los usuarios, activos e inactivos, por correo (CU-05; ``GET /users``)."""
        stmt = select(User).order_by(User.email)
        return (await self._session.execute(stmt)).scalars().all()

    async def add(self, user: User) -> None:
        """Inserta un usuario y lo envía a la BD sin confirmar."""
        self._session.add(user)
        await self._session.flush()

    async def email_exists(self, email: str) -> bool:
        """¿Hay ya un usuario con ese correo? (``users.email`` es UNIQUE)."""
        return bool(await self._session.scalar(select(exists().where(User.email == email))))

    async def increment_failed_attempts(self, user: User) -> int:
        """Suma un fallo consecutivo y devuelve el total (Cap. 6 §Política de bloqueo)."""
        user.failed_login_attempts += 1
        await self._session.flush()
        return user.failed_login_attempts

    async def lock_until(self, user: User, until: datetime) -> None:
        """Fija ``users.locked_until`` (Cap. 6 §Política de bloqueo)."""
        user.locked_until = until
        await self._session.flush()

    async def register_successful_login(self, user: User, now: datetime) -> None:
        """Login exitoso: reinicia el contador y el bloqueo y fija ``last_login_at``
        (Cap. 6 §Política de bloqueo: "se reinicia tras un intento exitoso")."""
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        await self._session.flush()

    async def clear_lockout(self, user: User) -> None:
        """Reinicia el contador de fallos y quita el bloqueo sin tocar ``last_login_at``: el
        desbloqueo y el restablecimiento por el Administrador (H-78)."""
        user.failed_login_attempts = 0
        user.locked_until = None
        await self._session.flush()

    async def update_password_hash(self, user: User, password_hash: str) -> None:
        """Reemplaza ``users.password_hash`` (rehash tras login; spec núcleo §3.1)."""
        user.password_hash = password_hash
        await self._session.flush()

    async def get_assignments(self, user_id: uuid.UUID) -> Sequence[UserRoleAssignment]:
        """Asignaciones de rol vigentes del usuario (Cap. 5 §Tabla user_role_assignments).

        Orden estable (H-73): rol, fecha de creación e ``id``. ``created_at`` es ``now()``, la
        hora de inicio de la transacción, así que dos asignaciones creadas juntas empatan y el
        ``id`` desempata. El Módulo RBAC no depende del orden."""
        stmt = (
            select(UserRoleAssignment)
            .where(UserRoleAssignment.user_id == user_id)
            .order_by(
                UserRoleAssignment.role_id,
                UserRoleAssignment.created_at,
                UserRoleAssignment.id,
            )
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def get_assignments_with_role_names(
        self, user_id: uuid.UUID
    ) -> list[tuple[UserRoleAssignment, str]]:
        """Asignaciones del usuario junto con el nombre de su rol, para ``GET /auth/me`` (spec
        Fase 5 §3.4). Orden estable: rol y luego fecha de creación."""
        stmt = (
            select(UserRoleAssignment, Role.name)
            .join(Role, UserRoleAssignment.role_id == Role.id)
            .where(UserRoleAssignment.user_id == user_id)
            .order_by(UserRoleAssignment.role_id, UserRoleAssignment.created_at)
        )
        return [(fila[0], fila[1]) for fila in (await self._session.execute(stmt)).all()]

    async def get_role_names(self, user_id: uuid.UUID) -> list[str]:
        """Nombres distintos de los roles del usuario, ordenados, para el claim ``roles`` del
        access token. Es informativo: el Módulo RBAC autoriza con las asignaciones de la BD."""
        stmt = (
            select(Role.name)
            .join(UserRoleAssignment, UserRoleAssignment.role_id == Role.id)
            .where(UserRoleAssignment.user_id == user_id)
            .distinct()
            .order_by(Role.name)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def add_assignment(self, assignment: UserRoleAssignment) -> None:
        """Inserta una asignación de rol y la envía a la BD sin confirmar."""
        self._session.add(assignment)
        await self._session.flush()

    async def get_assignment(
        self, user_id: uuid.UUID, assignment_id: uuid.UUID
    ) -> UserRoleAssignment | None:
        """Asignación ``assignment_id`` solo si pertenece a ``user_id`` (si no, ``None`` → 404)."""
        stmt = select(UserRoleAssignment).where(
            UserRoleAssignment.id == assignment_id, UserRoleAssignment.user_id == user_id
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def assignment_exists(
        self,
        user_id: uuid.UUID,
        role_id: int,
        project_id: uuid.UUID | None,
        environment_id: uuid.UUID | None,
    ) -> bool:
        """¿Ya existe esa asignación? Compara con ``IS NOT DISTINCT FROM``, igual que el
        ``UNIQUE NULLS NOT DISTINCT`` de la tabla (H-19): dos NULL cuentan como iguales."""
        stmt = select(
            exists().where(
                UserRoleAssignment.user_id == user_id,
                UserRoleAssignment.role_id == role_id,
                UserRoleAssignment.project_id.is_not_distinct_from(project_id),
                UserRoleAssignment.environment_id.is_not_distinct_from(environment_id),
            )
        )
        return bool(await self._session.scalar(stmt))

    async def delete_assignment(self, assignment: UserRoleAssignment) -> None:
        """Borra la asignación (``DELETE .../role-assignments/{aid}``) sin confirmar."""
        await self._session.delete(assignment)
        await self._session.flush()

    async def count_assignments_in_environment(self, environment_id: uuid.UUID) -> int:
        """Asignaciones de rol que caerán por CASCADE al borrar el ambiente (H-41)."""
        stmt = (
            select(func.count())
            .select_from(UserRoleAssignment)
            .where(UserRoleAssignment.environment_id == environment_id)
        )
        return await self._session.scalar(stmt) or 0

    async def flush(self) -> None:
        """Envía a la BD los cambios pendientes de las entidades cargadas, sin confirmar."""
        await self._session.flush()

    async def active_user_with_role_exists(
        self, role_id: int, *, excluding: uuid.UUID | None = None
    ) -> bool:
        """¿Hay un usuario activo con una asignación global de ``role_id``? (H-38).

        ``excluding`` deja fuera a ese usuario: "¿queda **otro** Administrador activo?" (H-59).
        """
        conditions = [
            UserRoleAssignment.role_id == role_id,
            UserRoleAssignment.project_id.is_(None),
            User.is_active.is_(True),
        ]
        if excluding is not None:
            conditions.append(User.id != excluding)
        stmt = select(exists().where(UserRoleAssignment.user_id == User.id).where(*conditions))
        return bool(await self._session.scalar(stmt))

    async def lock_administrators(self) -> None:
        """Toma ``pg_advisory_xact_lock(ADMINISTRATORS_LOCK_KEY)`` (H-59).

        Mismo razonamiento que ``AuditRepository.lock_chain``: si otra transacción lo tiene,
        espera a que confirme o revierta, y se libera solo al terminar la transacción. Debe ir
        **antes** de ``active_user_with_role_exists``: con READ COMMITTED el ``SELECT`` siguiente
        toma una instantánea nueva y ya ve lo que confirmó quien tenía el bloqueo.
        """
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMINISTRATORS_LOCK_KEY}
        )

    async def set_tokens_invalid_before(self, user_id: uuid.UUID, cutoff: datetime) -> None:
        """Invalida en bloque los tokens del usuario emitidos antes de ``cutoff`` (H-37).

        ``GREATEST`` conserva el mayor de los cortes si dos eventos coinciden (spec Fase 5 §3.5);
        en PostgreSQL ``GREATEST`` ignora el NULL inicial.
        """
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(tokens_invalid_before=func.greatest(User.tokens_invalid_before, cutoff))
        )
        await self._session.execute(stmt)


class RevokedTokenRepository:
    """Acceso a ``revoked_tokens`` (Cap. 5; Cap. 6 §Revocación y renovación; RF-015; H-03)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def is_revoked(self, jti: uuid.UUID) -> bool:
        """``True`` si el ``jti`` está en la lista de revocación (paso 9 del Algoritmo de
        verificación de un JWT entrante, Cap. 6). Se inyecta en ``validate_token``."""
        return bool(
            await self._session.scalar(select(exists().where(RevokedToken.token_jti == jti)))
        )

    async def revoke(
        self,
        jti: uuid.UUID,
        token_type: str,
        expires_at: datetime,
        *,
        user_id: uuid.UUID | None = None,
        revoked_by: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> bool:
        """Inserta el ``jti`` en ``revoked_tokens``. Devuelve ``True`` si lo revocó esta llamada
        y ``False`` si ya estaba revocado.

        ``INSERT ... ON CONFLICT (token_jti) DO NOTHING RETURNING``: el logout repetido no falla y,
        si dos peticiones canjean el mismo refresh a la vez, solo una obtiene ``True``; la otra
        se trata como reuso (OWASP JWT Cheat Sheet). ``user_id`` y ``revoked_by`` son nullable
        (H-03).
        """
        stmt = (
            insert(RevokedToken)
            .values(
                token_jti=jti,
                token_type=token_type,
                user_id=user_id,
                expires_at=expires_at,
                revoked_by=revoked_by,
                reason=reason,
            )
            .on_conflict_do_nothing(index_elements=[RevokedToken.token_jti])
            .returning(RevokedToken.token_jti)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none() is not None
