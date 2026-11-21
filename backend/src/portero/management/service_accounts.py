"""Servicios de Gestión: Aplicaciones Cliente (A-04) y sus PAT (Cap. 6 §Autenticación de
Aplicaciones Cliente; spec núcleo §3.3; spec Fase 5 §2, §3.7; H-09, H-21, H-23a, H-42; RF-010;
OWASP ASVS V2.10).

Sin HTTP ni permisos: ``projects:manage`` en el proyecto lo exige antes el API REST Gateway
(H-23a). Cada escritura se registra en el Servicio de Registro de Operaciones en la misma
transacción (H-11), con el proyecto y el ambiente de la service account. Ni el token ni su hash
van jamás a ``details`` (``OperationEvent`` además rechaza esas llaves, H-12).

El PAT lo emite el Servicio de Autenticación (``PatIssuer``, inyectado al arrancar): este módulo
no conoce la clave de firma ni el Motor Criptográfico. Del token solo se guardan
``SHA-256(token)`` y ``token_prefix``; el token completo se devuelve **una sola vez**.
"""

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.tokens import IssuedPersonalAccessToken
from portero.db.models import ServiceAccount
from portero.db.repositories.project import ProjectRepository
from portero.db.repositories.service_account import ServiceAccountRepository
from portero.management.errors import ExpirationInPastError, InvalidScopeError
from portero.oplog.service import OperationActor, OperationEvent, OperationLogService

Clock = Callable[[], datetime]


class PatIssuer(Protocol):
    """Emisor de PAT (``AuthService.issue_personal_access_token``)."""

    def __call__(
        self,
        service_account_id: UUID,
        project_id: UUID,
        environment_id: UUID | None,
        expires_at: datetime | None,
    ) -> IssuedPersonalAccessToken: ...


@dataclass(frozen=True)
class CreatedServiceAccount:
    """Resultado de crear una service account: la fila y el token, que no se guarda."""

    account: ServiceAccount
    token: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ServiceAccountService:
    """Servicio de Gestión de Aplicaciones Cliente (Cap. 5, diagrama de componentes)."""

    def __init__(
        self,
        issue_pat: PatIssuer,
        oplog: OperationLogService | None = None,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._issue_pat = issue_pat
        self._oplog = oplog or OperationLogService()
        self._clock = clock

    async def list_service_accounts(
        self, session: AsyncSession, project_id: UUID
    ) -> Sequence[ServiceAccount]:
        """Service accounts del proyecto, vigentes y revocadas (solo metadatos)."""
        return await ServiceAccountRepository(session).list_by_project(project_id)

    async def get_service_account(
        self, session: AsyncSession, service_account_id: UUID
    ) -> ServiceAccount | None:
        """La service account, o ``None`` (→ 404)."""
        return await ServiceAccountRepository(session).get_by_id(service_account_id)

    async def create_service_account(
        self,
        session: AsyncSession,
        actor: OperationActor,
        project_id: UUID,
        *,
        name: str,
        environment_id: UUID | None,
        expires_at: datetime | None,
    ) -> CreatedServiceAccount:
        """Crea la service account, emite su PAT y registra ``create_service_account``.

        - ``environment_id`` nulo = acceso a todo el proyecto; si viene, debe ser del proyecto.
        - ``expires_at`` se trunca al segundo, que es la resolución de ``exp`` (RFC 7519): así la
          columna y el token dicen lo mismo. Debe estar en el futuro. Sin él, el PAT no tiene
          ``exp`` (H-09).
        - Se guardan ``token_hash = SHA-256(token)`` y ``token_prefix`` (spec núcleo §3.3; H-42).

        Raises:
            InvalidScopeError: el ambiente no pertenece al proyecto (→ 422).
            ExpirationInPastError: ``expires_at`` no está en el futuro (→ 422).
        """
        if actor.actor_user_id is None:
            # Solo un humano tiene projects:manage; un PAT no llega aquí.
            raise ValueError("crear una service account requiere un actor humano")
        if expires_at is not None:
            expires_at = expires_at.replace(microsecond=0)
            if expires_at <= self._clock():
                raise ExpirationInPastError("la fecha de vencimiento debe estar en el futuro")
        if environment_id is not None and (
            await ProjectRepository(session).get_environment(project_id, environment_id) is None
        ):
            raise InvalidScopeError("el ambiente no pertenece al proyecto")

        account_id = uuid.uuid4()
        pat = self._issue_pat(account_id, project_id, environment_id, expires_at)
        account = ServiceAccount(
            id=account_id,
            name=name,
            project_id=project_id,
            environment_id=environment_id,
            token_hash=pat.token_hash,
            token_prefix=pat.token_prefix,
            created_by=actor.actor_user_id,
            expires_at=pat.expires_at,
        )
        try:
            await ServiceAccountRepository(session).add(account)
            await self._oplog.record(session, _event(actor, "create_service_account", account))
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        await session.refresh(account)  # created_at lo pone la BD
        return CreatedServiceAccount(account=account, token=pat.token)

    async def revoke_service_account(
        self, session: AsyncSession, actor: OperationActor, account: ServiceAccount
    ) -> None:
        """Revoca el PAT: fija ``revoked_at`` y ``revoked_by`` y registra
        ``revoke_service_account`` (H-21).

        ``service_accounts.revoked_at`` es la fuente de verdad: la dependencia Bearer rechaza el
        PAT desde la siguiente petición. No se inserta en ``revoked_tokens`` (su ``expires_at``
        es NOT NULL y un PAT puede no tener ``exp``). Idempotente: si ya estaba revocada no
        cambia nada ni se vuelve a registrar.
        """
        try:
            revoked = await ServiceAccountRepository(session).revoke(
                account.id, self._clock(), actor.actor_user_id
            )
            if not revoked:
                await session.rollback()
                return
            await self._oplog.record(session, _event(actor, "revoke_service_account", account))
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


def _event(actor: OperationActor, verb: str, account: ServiceAccount) -> OperationEvent:
    """Evento sobre una service account, con su proyecto y ambiente como contexto."""
    return actor.event(
        verb,
        "success",
        resource_type="service_account",
        resource_id=account.id,
        project_id=account.project_id,
        environment_id=account.environment_id,
    )
