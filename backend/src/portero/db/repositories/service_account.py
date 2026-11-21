"""``ServiceAccountRepository``: Aplicaciones Cliente (A-04) y sus PAT (Capa de Persistencia,
Cap. 5 §Componentes; spec Fase 5 §3.7).

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy import exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import ServiceAccount

LAST_USED_GRANULARITY = timedelta(minutes=1)
"""``last_used_at`` se actualiza como máximo una vez por minuto (spec Fase 5 §3.7): evita una
escritura en cada petición de una Aplicación Cliente."""


class ServiceAccountRepository:
    """Acceso a ``service_accounts`` (Cap. 5 §Tabla service_accounts)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, service_account_id: uuid.UUID) -> ServiceAccount | None:
        """Service account por id, con los valores vigentes en la base: ``revoked_at`` es la
        fuente de verdad de la revocación de un PAT (H-21)."""
        stmt = (
            select(ServiceAccount)
            .where(ServiceAccount.id == service_account_id)
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def add(self, account: ServiceAccount) -> None:
        """Inserta la service account y la envía a la BD sin confirmar."""
        self._session.add(account)
        await self._session.flush()

    async def list_by_project(self, project_id: uuid.UUID) -> Sequence[ServiceAccount]:
        """Service accounts del proyecto, vigentes y revocadas, de la más antigua a la más
        reciente (``GET /projects/{pid}/service-accounts``)."""
        stmt = (
            select(ServiceAccount)
            .where(ServiceAccount.project_id == project_id)
            .order_by(ServiceAccount.created_at, ServiceAccount.id)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def revoke(
        self, service_account_id: uuid.UUID, now: datetime, revoked_by: uuid.UUID | None
    ) -> bool:
        """Fija ``revoked_at`` y ``revoked_by`` solo si seguía vigente (H-21). Devuelve ``True``
        si la revocó esta llamada; ``False`` si ya estaba revocada (``DELETE`` idempotente: la
        primera revocación no se sobrescribe)."""
        stmt = (
            update(ServiceAccount)
            .where(ServiceAccount.id == service_account_id, ServiceAccount.revoked_at.is_(None))
            .values(revoked_at=now, revoked_by=revoked_by)
            .returning(ServiceAccount.id)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none() is not None

    async def exists_in_environment(self, environment_id: uuid.UUID) -> bool:
        """¿Alguna service account, vigente o revocada, apunta al ambiente? (H-41)."""
        stmt = select(exists().where(ServiceAccount.environment_id == environment_id))
        return bool(await self._session.scalar(stmt))

    async def touch_last_used(self, service_account_id: uuid.UUID, now: datetime) -> bool:
        """Fija ``last_used_at = now`` solo si estaba vacío o tiene más de un minuto.

        Es un ``UPDATE`` condicional: dos peticiones simultáneas no escriben dos veces, y no hace
        falta leer antes de escribir. Devuelve ``True`` si actualizó la fila.
        """
        stmt = (
            update(ServiceAccount)
            .where(
                ServiceAccount.id == service_account_id,
                or_(
                    ServiceAccount.last_used_at.is_(None),
                    ServiceAccount.last_used_at < now - LAST_USED_GRANULARITY,
                ),
            )
            .values(last_used_at=now)
            .returning(ServiceAccount.id)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none() is not None
