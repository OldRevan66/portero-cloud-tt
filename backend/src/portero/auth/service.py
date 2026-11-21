"""Servicio de Autenticación, casos de uso de CU-01: login con bloqueo, refresh con rotación,
logout, cambio de contraseña (H-37) y emisión de PAT de Aplicaciones Cliente (H-21) (Cap. 6
§Autenticación de actores humanos, §Revocación y renovación de tokens, §Autenticación de
Aplicaciones Cliente; spec núcleo §3.1–3.3; spec Fase 5 §3.1–3.7).

No sabe nada de HTTP: recibe la sesión de BD y devuelve tokens o lanza excepciones. El API REST
Gateway (sesión 8) traduce eso a respuestas, cookies y errores RFC 9457.

Cada método controla su transacción (``commit`` o ``rollback``), como ``SecretService``; los
repositorios nunca confirman.

Cada evento de CU-01 se registra en el Servicio de Registro de Operaciones **en la misma
transacción** que su efecto (spec Fase 5 §5.4; H-11): ``login`` con ``last_login_at``,
``login_failed`` con el contador de fallos (y se confirma aunque la respuesta sea 401),
``refresh``, ``refresh_reused`` y ``logout`` con la revocación. ``record`` va siempre justo antes
del ``commit``.

Argon2id (~17 ms de CPU por llamada) corre con ``asyncio.to_thread`` (H-72): argon2-cffi libera
el GIL, así que el hash se calcula en otro hilo y el ciclo de eventos sigue atendiendo las demás
peticiones (OWASP API4). El orden de H-08 y H-24 no cambia: siempre se espera el verify antes de
decidir.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.passwords import (
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_against_decoy,
    verify_password,
)
from portero.auth.tokens import (
    API_TOKEN_TYPES,
    REFRESH_TOKEN_TYPES,
    IssuedPersonalAccessToken,
    IssuedToken,
    TokenRejectedError,
    VerifiedToken,
    cutoff_from,
    issue_access_token,
    issue_personal_access_token,
    issue_refresh_token,
    predates_cutoff,
    validate_token,
)
from portero.crypto.signing import JwtSigner
from portero.db.models import User
from portero.db.repositories.service_account import ServiceAccountRepository
from portero.db.repositories.user import RevokedTokenRepository, UserRepository
from portero.oplog.service import NO_CLIENT, ClientInfo, OperationEvent, OperationLogService

INVALID_CREDENTIALS = "credenciales inválidas"
"""Mensaje único para correo inexistente, contraseña incorrecta, cuenta inactiva y cuenta
bloqueada (Cap. 6 §Autenticación de actores humanos; OWASP ASVS V2.2.1)."""

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
"""Política de bloqueo del Cap. 6 (NIST SP 800-63B §5.2.2): 5 fallos consecutivos bloquean la
cuenta 15 minutos. El contador solo lo reinicia un login exitoso, así que, vencido el bloqueo, el
siguiente fallo vuelve a bloquear ("bloqueo progresivo")."""

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InvalidCredentialsError(Exception):
    """Login rechazado. Siempre el mismo tipo y el mismo mensaje, sin importar la causa, para no
    revelar si la cuenta existe, está inactiva o bloqueada (OWASP ASVS V2.2.1)."""

    def __init__(self) -> None:
        super().__init__(INVALID_CREDENTIALS)


@dataclass(frozen=True)
class TokenPair:
    """Par de tokens de un humano (Cap. 6 §Emisión del par de tokens). ``issued_at`` es el
    ``iat`` de ambos."""

    access: IssuedToken
    refresh: IssuedToken
    issued_at: datetime

    @property
    def access_expires_in(self) -> int:
        """Segundos de vida del access, ``exp - iat``: 900, o menos al final de la sesión (H-61).
        Es el ``expires_in`` de la respuesta (RFC 6749 §5.1)."""
        return _seconds_until(cast(datetime, self.access.expires_at), self.issued_at)

    @property
    def refresh_expires_in(self) -> int:
        """Vida del refresh, ``exp - iat``: 1800, o menos cerca del tope de 12 h (H-61). Es el
        ``Max-Age`` de la cookie."""
        return _seconds_until(cast(datetime, self.refresh.expires_at), self.issued_at)


@dataclass(frozen=True)
class AssignmentView:
    """Una asignación de rol con su alcance, tal como la muestra ``GET /auth/me``."""

    id: UUID
    role_id: int
    role: str
    project_id: UUID | None
    environment_id: UUID | None


@dataclass(frozen=True)
class UserProfile:
    """Usuario autenticado para ``GET /auth/me`` (spec Fase 5 §3.4). Sin hash ni contadores."""

    id: UUID
    email: str
    name: str | None
    assignments: tuple[AssignmentView, ...]


class AuthService:
    """Casos de uso de autenticación de actores humanos (CU-01).

    ``clock`` es el reloj de la aplicación: el mismo pone ``iat`` en los tokens, fija
    ``locked_until`` y se compara con ``tokens_invalid_before`` (spec Fase 5 §3.5). Se inyecta
    para poder probar el bloqueo sin esperar 15 minutos. El Servicio de Registro de Operaciones
    usa ese mismo reloj para ``event_timestamp``.
    """

    def __init__(
        self,
        signer: JwtSigner,
        issuer: str,
        *,
        clock: Clock = _utc_now,
        oplog: OperationLogService | None = None,
    ) -> None:
        self._signer = signer
        self._issuer = issuer
        self._clock = clock
        self._oplog = oplog if oplog is not None else OperationLogService(clock=clock)

    # --- login -----------------------------------------------------------------------------------

    async def login(
        self, session: AsyncSession, email: str, password: str, *, client: ClientInfo = NO_CLIENT
    ) -> TokenPair:
        """CU-01: verifica las credenciales y emite un par de tokens (Cap. 6 §Autenticación de
        actores humanos).

        1. Busca al usuario con ``FOR UPDATE`` para que dos fallos simultáneos no pierdan un
           incremento del contador.
        2. **Siempre ejecuta un verify Argon2id antes de decidir** (H-08, H-24): contra el hash
           señuelo si el correo no existe, o contra el hash real aunque la cuenta esté inactiva o
           bloqueada. Así las cuatro causas de rechazo tardan lo mismo y no se puede enumerar
           cuentas por tiempo de respuesta.
        3. Cuenta inactiva o bloqueada (``locked_until > ahora``): rechaza sin tocar el contador,
           aunque la contraseña sea correcta.
        4. Contraseña incorrecta: suma un fallo; al llegar a 5, bloquea 15 minutos (NIST SP
           800-63B §5.2.2). Se confirma antes de lanzar la excepción.
        5. Éxito: rehash si los parámetros cambiaron, reinicia el contador, fija
           ``last_login_at`` y emite el par.

        Todo rechazo lanza ``InvalidCredentialsError`` con el mensaje único (OWASP ASVS V2.2.1).
        La causa real solo queda en la bitácora: ``login_failed`` con ``details.reason``
        (``no_existe``, ``inactiva``, ``bloqueada`` o ``hash``; spec Fase 5 §5.3).
        """
        now = self._clock()
        users = UserRepository(session)
        try:
            user = await users.get_by_email_for_update(email)
            if user is None:
                await asyncio.to_thread(verify_against_decoy, password)  # H-08, H-72
                await self._login_failed(session, email, None, "no_existe", client)
                raise InvalidCredentialsError()

            # H-24: siempre; H-72: fuera del ciclo de eventos.
            password_ok = await asyncio.to_thread(verify_password, user.password_hash, password)

            if not user.is_active or _is_locked(user, now):
                reason = "inactiva" if not user.is_active else "bloqueada"
                await self._login_failed(session, email, user.id, reason, client)
                raise InvalidCredentialsError()

            if not password_ok:
                attempts = await users.increment_failed_attempts(user)
                if attempts >= MAX_FAILED_ATTEMPTS:
                    await users.lock_until(user, now + LOCKOUT_DURATION)
                await self._login_failed(session, email, user.id, "hash", client)
                raise InvalidCredentialsError()

            if needs_rehash(user.password_hash):
                new_hash = await asyncio.to_thread(hash_password, password)  # H-72
                await users.update_password_hash(user, new_hash)
            await users.register_successful_login(user, now)
            pair = self._issue_pair(user.id, await users.get_role_names(user.id), now)
            await self._oplog.record(
                session, _user_event("login", "success", user.id, user.email, client)
            )
            await session.commit()
            return pair
        except InvalidCredentialsError:
            raise
        except BaseException:
            await session.rollback()
            raise

    # --- refresh ---------------------------------------------------------------------------------

    async def refresh(
        self, session: AsyncSession, refresh_token: str, *, client: ClientInfo = NO_CLIENT
    ) -> TokenPair:
        """Canjea un refresh token por un par nuevo con rotación (Cap. 6 §Renovación con refresh
        token; OWASP JWT Cheat Sheet).

        1. ``validate_token`` solo acepta ``token_type=refresh`` (H-25) y revisa la revocación.
        2. El usuario debe seguir activo y el token no puede ser anterior a
           ``tokens_invalid_before`` (H-37).
        3. En **una sola transacción** revoca el ``jti`` viejo y emite el par nuevo: si la
           emisión falla, la revocación se deshace.

        Un refresh ya revocado se rechaza con ``reason="refresh_reused"`` (posible robo). Lo
        mismo si otra petición lo canjeó al mismo tiempo: ``revoke`` devuelve ``False``. En ambos
        casos se invalidan todos los tokens del usuario (H-43), se registra ``refresh_reused`` y
        se confirma antes de lanzar. Los demás rechazos no
        se registran (no están en el catálogo de la spec Fase 5 §5.2). Todo rechazo lanza
        ``TokenRejectedError``; el mensaje nunca incluye el token.
        """
        now = self._clock()
        users = UserRepository(session)
        revoked = RevokedTokenRepository(session)
        try:
            try:
                verified = await validate_token(
                    refresh_token,
                    signer=self._signer,
                    issuer=self._issuer,
                    accepted_types=REFRESH_TOKEN_TYPES,
                    is_revoked=revoked.is_revoked,
                )
            except TokenRejectedError as exc:
                if exc.reason == "revocado":
                    await self._refresh_reused(session, exc.subject, client)
                    raise TokenRejectedError("refresh_reused", subject=exc.subject) from None
                raise

            user = await users.get_by_id(verified.sub)
            if user is None or not user.is_active:
                raise TokenRejectedError("usuario_inactivo")
            if predates_cutoff(verified.issued_at, user.tokens_invalid_before):
                raise TokenRejectedError("tokens_invalidados")

            # validate_token exige exp en todo token que no sea de servicio (H-09).
            expires_at = cast(datetime, verified.expires_at)
            if not await revoked.revoke(verified.jti, "refresh", expires_at, user_id=user.id):
                # Otra petición lo canjeó al mismo tiempo.
                await self._refresh_reused(session, user.id, client)
                raise TokenRejectedError("refresh_reused", subject=user.id)

            pair = self._issue_pair(
                user.id, await users.get_role_names(user.id), now, auth_time=verified.auth_time
            )
            await self._oplog.record(
                session, _user_event("refresh", "success", user.id, user.email, client)
            )
            await session.commit()
            return pair
        except BaseException:
            await session.rollback()
            raise

    # --- logout ----------------------------------------------------------------------------------

    async def logout(
        self,
        session: AsyncSession,
        access: VerifiedToken,
        refresh_token: str | None,
        *,
        client: ClientInfo = NO_CLIENT,
    ) -> None:
        """Cierre de sesión: revoca el access token actual y, si se presenta un refresh válido
        del mismo usuario, también ese (Cap. 6 §Casos que disparan revocación; spec Fase 5 §3.3).

        ``access`` ya lo validó la dependencia Bearer del API REST Gateway. Repetir el logout no
        falla (``revoke`` ignora un ``jti`` ya revocado), y un refresh inválido, revocado o de
        otro usuario se ignora. Solo para humanos: un PAT se revoca con
        ``service_accounts.revoked_at`` (H-21).
        """
        if access.actor_type != "human":
            raise TokenRejectedError("tipo")
        revoked = RevokedTokenRepository(session)
        try:
            # validate_token exige exp en todo token que no sea de servicio (H-09).
            await revoked.revoke(
                access.jti, "access", cast(datetime, access.expires_at), user_id=access.sub
            )
            if refresh_token is not None:
                try:
                    refresh = await validate_token(
                        refresh_token,
                        signer=self._signer,
                        issuer=self._issuer,
                        accepted_types=REFRESH_TOKEN_TYPES,
                        is_revoked=revoked.is_revoked,
                    )
                except TokenRejectedError:
                    refresh = None
                if refresh is not None and refresh.sub == access.sub:
                    await revoked.revoke(
                        refresh.jti,
                        "refresh",
                        cast(datetime, refresh.expires_at),
                        user_id=access.sub,
                    )
            actor_ref = await _actor_ref(UserRepository(session), access.sub)
            await self._oplog.record(
                session, _user_event("logout", "success", access.sub, actor_ref, client)
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

    # --- cambio de contraseña ---------------------------------------------------------------------

    async def change_password(
        self,
        session: AsyncSession,
        user_id: UUID,
        current_password: str,
        new_password: str,
        *,
        client: ClientInfo = NO_CLIENT,
    ) -> None:
        """``POST /users/me/password`` (spec Fase 5 §3.6; Cap. 6 §Casos que disparan revocación;
        OWASP ASVS V2.1.5–V2.1.6).

        1. Bloquea la fila (``FOR UPDATE``) y **reverifica la contraseña actual**: quien robe un
           access token no puede fijar una contraseña propia y adueñarse de la cuenta.
        2. Contraseña incorrecta o cuenta bloqueada: cuenta como fallo de login (suma al contador
           y bloquea al quinto, NIST SP 800-63B §5.2.2), registra ``change_password`` con
           ``result=failure`` y confirma antes de lanzar ``InvalidCredentialsError`` (401
           genérico).
        3. La nueva contraseña pasa por la política (``PasswordPolicyError`` → 422).
        4. Guarda el hash Argon2id nuevo y fija el corte H-37 (``tokens_invalid_before``): todo
           access y refresh emitido antes deja de servir. Registra ``change_password`` en la
           misma transacción (H-11). Las contraseñas nunca van a ``details``.
        """
        now = self._clock()
        users = UserRepository(session)
        try:
            user = await users.get_by_id_for_update(user_id)
            if user is None or not user.is_active:
                # La dependencia Bearer acaba de validar al usuario; solo pasa con una carrera.
                raise TokenRejectedError("usuario_inactivo")
            password_ok = await asyncio.to_thread(  # H-72
                verify_password, user.password_hash, current_password
            )
            locked = _is_locked(user, now)
            if locked or not password_ok:
                if not locked:
                    attempts = await users.increment_failed_attempts(user)
                    if attempts >= MAX_FAILED_ATTEMPTS:
                        await users.lock_until(user, now + LOCKOUT_DURATION)
                reason = "bloqueada" if locked else "hash"
                await self._oplog.record(
                    session,
                    _user_event(
                        "change_password",
                        "failure",
                        user.id,
                        user.email,
                        client,
                        {"reason": reason},
                    ),
                )
                await session.commit()
                raise InvalidCredentialsError()

            check_password_policy(new_password)
            new_hash = await asyncio.to_thread(hash_password, new_password)  # H-72
            await users.update_password_hash(user, new_hash)
            await users.set_tokens_invalid_before(user.id, cutoff_from(now))
            await self._oplog.record(
                session, _user_event("change_password", "success", user.id, user.email, client)
            )
            await session.commit()
        except InvalidCredentialsError:
            raise
        except BaseException:
            await session.rollback()
            raise

    # --- Aplicaciones Cliente ---------------------------------------------------------------------

    def issue_personal_access_token(
        self,
        service_account_id: UUID,
        project_id: UUID,
        environment_id: UUID | None,
        expires_at: datetime | None,
    ) -> IssuedPersonalAccessToken:
        """Emite el PAT de una service account con la clave de firma del servicio (Cap. 6
        §Autenticación de Aplicaciones Cliente; spec núcleo §3.3; H-42).

        Es el único punto por el que los Servicios de Gestión obtienen un PAT: así no necesitan
        la clave de firma ni el Motor Criptográfico (solo ``auth`` y ``secrets_mgmt`` lo usan).
        """
        return issue_personal_access_token(
            self._signer,
            service_account_id=service_account_id,
            project_id=project_id,
            environment_id=environment_id,
            expires_at=expires_at,
            issuer=self._issuer,
            now=self._clock(),
        )

    # --- autenticación del portador ---------------------------------------------------------------

    async def authenticate(self, session: AsyncSession, token: str) -> VerifiedToken:
        """Verifica el Bearer de una petición a la API (Cap. 6 §Algoritmo de verificación de un
        JWT entrante; RFC 6750; spec Fase 5 §3.5 y §3.7).

        1. ``validate_token`` con ``API_TOKEN_TYPES``: un refresh token no autentica peticiones
           (H-25); incluye firma, claims y ``jti`` no revocado.
        2. Humano: el usuario existe, está activo y el token no es anterior a
           ``tokens_invalid_before`` (H-37). Se lee la fila en cada petición, así que desactivar
           una cuenta surte efecto de inmediato.
        3. Aplicación Cliente: el service account existe y ``revoked_at`` es NULL (H-21). Si
           pasa, se actualiza ``last_used_at`` como máximo una vez por minuto.

        Todo rechazo lanza ``TokenRejectedError`` con un motivo interno; el API REST Gateway
        responde siempre el mismo 401.
        """
        revoked = RevokedTokenRepository(session)
        verified = await validate_token(
            token,
            signer=self._signer,
            issuer=self._issuer,
            accepted_types=API_TOKEN_TYPES,
            is_revoked=revoked.is_revoked,
        )
        if verified.actor_type == "human":
            user = await UserRepository(session).get_by_id(verified.sub)
            if user is None or not user.is_active:
                raise TokenRejectedError("usuario_inactivo")
            if predates_cutoff(verified.issued_at, user.tokens_invalid_before):
                raise TokenRejectedError("tokens_invalidados")
            return verified

        accounts = ServiceAccountRepository(session)
        account = await accounts.get_by_id(verified.sub)
        if account is None or account.revoked_at is not None:
            raise TokenRejectedError("service_account_revocada")
        try:
            if await accounts.touch_last_used(account.id, self._clock()):
                await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return verified

    # --- perfil ----------------------------------------------------------------------------------

    async def profile(self, session: AsyncSession, user_id: UUID) -> UserProfile:
        """Datos de ``GET /auth/me``: usuario y asignaciones vigentes con el nombre del rol
        (spec Fase 5 §3.4). Se leen de la BD, no del claim ``roles`` del token. El Dashboard
        arma su menú con esto; la autorización real la hace el Módulo RBAC en cada ruta."""
        users = UserRepository(session)
        user = await users.get_by_id(user_id)
        if user is None:
            # La dependencia Bearer acaba de validar al usuario; solo pasa con una carrera.
            raise TokenRejectedError("usuario_inactivo")
        assignments = tuple(
            AssignmentView(
                id=a.id,
                role_id=a.role_id,
                role=role,
                project_id=a.project_id,
                environment_id=a.environment_id,
            )
            for a, role in await users.get_assignments_with_role_names(user_id)
        )
        return UserProfile(id=user.id, email=user.email, name=user.name, assignments=assignments)

    # --- auxiliares ------------------------------------------------------------------------------

    async def _login_failed(
        self,
        session: AsyncSession,
        email: str,
        user_id: UUID | None,
        reason: str,
        client: ClientInfo,
    ) -> None:
        """Registra ``login_failed`` y confirma, junto con el contador de fallos si cambió (spec
        Fase 5 §5.4). ``actor_ref`` es el correo enviado; ``actor_user_id`` es ``None`` si no
        existe. ``reason`` solo queda en la bitácora; el cliente ve el 401 genérico."""
        await self._oplog.record(
            session,
            _user_event("login_failed", "failure", user_id, email, client, {"reason": reason}),
        )
        await session.commit()

    async def _refresh_reused(
        self, session: AsyncSession, user_id: UUID | None, client: ClientInfo
    ) -> None:
        """Reúso de un refresh ya canjeado: posible robo (spec Fase 5 §3.2; H-43).

        Fuerza la reautenticación completa (Cap. 6 §Renovación con refresh token; RFC 9700
        §4.14.2): fija el corte H-37 del dueño, así que todo access y refresh emitido antes deja
        de servir, también el que el atacante obtuvo al canjear primero el token robado. En la
        misma transacción registra ``refresh_reused`` y confirma. ``user_id`` viene de un token
        con firma válida.
        """
        if user_id is None:  # no ocurre: el motivo "revocado" siempre trae subject
            return
        users = UserRepository(session)
        await users.set_tokens_invalid_before(user_id, cutoff_from(self._clock()))
        actor_ref = await _actor_ref(users, user_id)
        await self._oplog.record(
            session, _user_event("refresh_reused", "failure", user_id, actor_ref, client)
        )
        await session.commit()

    def _issue_pair(
        self,
        user_id: UUID,
        roles: list[str],
        now: datetime,
        *,
        auth_time: datetime | None = None,
    ) -> TokenPair:
        """Emite access (15 min) y refresh con el mismo ``iat`` (Cap. 6 §Emisión del par de
        tokens).

        H-61 (OWASP ASVS V3.3.2): en el login ``auth_time`` es ``None`` y la sesión empieza
        ahora; en la rotación se pasa el del refresh canjeado. El refresh vence a los 30 min de
        inactividad o a las 12 h del login, lo que llegue antes, y el access no lo rebasa.
        """
        refresh = issue_refresh_token(
            self._signer, user_id=user_id, issuer=self._issuer, now=now, auth_time=auth_time
        )
        access = issue_access_token(
            self._signer,
            user_id=user_id,
            roles=roles,
            issuer=self._issuer,
            now=now,
            not_after=refresh.expires_at,
        )
        return TokenPair(access=access, refresh=refresh, issued_at=now)


def _user_event(
    verb: str,
    result: str,
    user_id: UUID | None,
    actor_ref: str,
    client: ClientInfo,
    details: dict[str, object] | None = None,
) -> OperationEvent:
    """Evento de autenticación de un humano sobre su propio usuario (spec Fase 5 §5.2–5.3):
    ``resource_type=user`` y ``resource_id`` = el mismo usuario, sin proyecto ni ambiente."""
    return OperationEvent(
        actor_type="human",
        actor_ref=actor_ref,
        verb=verb,
        result=result,
        actor_user_id=user_id,
        resource_type="user",
        resource_id=user_id,
        ip_address=client.ip_address,
        user_agent=client.user_agent,
        details=details,
    )


async def _actor_ref(users: UserRepository, user_id: UUID) -> str:
    """Correo del usuario para ``actor_ref`` (spec Fase 5 §5.3). Si la fila ya no existe (no se
    borran usuarios, pero por si acaso), el id."""
    user = await users.get_by_id(user_id)
    return user.email if user is not None else str(user_id)


def _seconds_until(expires_at: datetime, issued_at: datetime) -> int:
    """``exp - iat`` con los mismos segundos enteros que llevan los claims (RFC 7519)."""
    return int(expires_at.timestamp()) - int(issued_at.timestamp())


def _is_locked(user: User, now: datetime) -> bool:
    """``locked_until > ahora``; un bloqueo vencido ya no cuenta (Cap. 6 §Política de bloqueo)."""
    return user.locked_until is not None and user.locked_until > now
