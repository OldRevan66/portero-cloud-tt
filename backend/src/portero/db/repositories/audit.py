"""``AuditRepository``: inserción y consulta de ``audit_logs`` para el Servicio de Registro de
Operaciones (Capa de Persistencia, Cap. 5 §Componentes; spec núcleo §5; H-11).

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import AuditLog

OPLOG_CHAIN_LOCK_KEY = 0x6F706C6F67
"""Llave de ``pg_advisory_xact_lock`` que serializa las inserciones en la cadena (H-11).

Es ``b"oplog"`` leído como entero (478 660 388 711): un número fijo y reconocible. El único otro
*advisory lock* es ``ADMINISTRATORS_LOCK_KEY`` (``b"admin"``, H-59), con otra llave; uno nuevo
debe elegir también una llave distinta."""


@dataclass(frozen=True)
class AuditQuery:
    """Filtros de ``GET /operations`` (Cap. 6 §Endpoints de operaciones; spec Fase 5 §4.3).

    ``project_ids`` es el alcance ya decidido por la autorización: ``None`` = toda la bitácora
    (Administrador); un conjunto = solo los registros con ``project_id`` en él (vacío = nada).
    ``since`` y ``until`` son inclusivos sobre ``event_timestamp``. ``None`` = sin filtro.
    """

    project_ids: frozenset[UUID] | None = None
    actor_user_id: UUID | None = None
    verb: str | None = None
    resource_type: str | None = None
    result: str | None = None
    since: datetime | None = None
    until: datetime | None = None


class AuditRepository:
    """Acceso a ``audit_logs`` (Cap. 5 §Tabla audit_logs)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def lock_chain(self) -> None:
        """Toma ``pg_advisory_xact_lock(OPLOG_CHAIN_LOCK_KEY)`` (H-11).

        Si otra transacción lo tiene, espera a que confirme o revierta. El lock se libera solo
        al terminar la transacción. Debe ir en una sentencia **anterior** a ``last_hash``: con
        READ COMMITTED (el nivel por defecto), cada sentencia toma una instantánea nueva, así que
        el ``SELECT`` siguiente ya ve el registro que confirmó quien tenía el lock.
        """
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": OPLOG_CHAIN_LOCK_KEY}
        )

    async def last_hash(self) -> str | None:
        """``current_hash`` del último registro (mayor ``id``), o ``None`` si la tabla está
        vacía. Llamar solo con el lock de la cadena tomado."""
        stmt = select(AuditLog.current_hash).order_by(AuditLog.id.desc()).limit(1)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def add(self, entry: AuditLog) -> None:
        """Inserta el registro y hace ``flush``. Así un error de la BD (p. ej. ``UNIQUE`` de
        ``current_hash``) aparece aquí y no en el ``commit`` de quien llama."""
        self._session.add(entry)
        await self._session.flush()

    async def list_in_order(self) -> Sequence[AuditLog]:
        """Todos los registros por ``id`` ascendente, el orden de la cadena. Se leen de la BD
        (``populate_existing``), no de la caché de la sesión: es lo que se verifica."""
        stmt = select(AuditLog).order_by(AuditLog.id).execution_options(populate_existing=True)
        return (await self._session.execute(stmt)).scalars().all()

    async def get(self, log_id: int) -> AuditLog | None:
        """Un registro por ``id``, o ``None``."""
        return await self._session.get(AuditLog, log_id)

    async def list_page(
        self, query: AuditQuery, *, limit: int, before: int | None
    ) -> Sequence[AuditLog]:
        """Hasta ``limit`` registros que cumplen ``query``, por ``id`` descendente, con
        ``id < before`` si se da (paginación por cursor, spec Fase 5 §1). Como los ``id`` nuevos
        siempre son mayores, insertar registros no mueve las páginas siguientes."""
        if query.project_ids is not None and not query.project_ids:
            return []
        stmt = select(AuditLog)
        if query.project_ids is not None:
            stmt = stmt.where(AuditLog.project_id.in_(query.project_ids))
        if query.actor_user_id is not None:
            stmt = stmt.where(AuditLog.actor_user_id == query.actor_user_id)
        if query.verb is not None:
            stmt = stmt.where(AuditLog.verb == query.verb)
        if query.resource_type is not None:
            stmt = stmt.where(AuditLog.resource_type == query.resource_type)
        if query.result is not None:
            stmt = stmt.where(AuditLog.result == query.result)
        if query.since is not None:
            stmt = stmt.where(AuditLog.event_timestamp >= query.since)
        if query.until is not None:
            stmt = stmt.where(AuditLog.event_timestamp <= query.until)
        if before is not None:
            stmt = stmt.where(AuditLog.id < before)
        stmt = stmt.order_by(AuditLog.id.desc()).limit(limit)
        return (await self._session.execute(stmt)).scalars().all()
