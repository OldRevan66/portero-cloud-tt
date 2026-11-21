"""``ChainSignatureRepository``: firmas del cierre de la cadena de la bitácora (Capa de
Persistencia; H-81).

Los repositorios no hacen ``commit``: la transacción la controla el servicio que los usa.
"""

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portero.db.models import ChainSignature


class ChainSignatureRepository:
    """Acceso a ``chain_signatures`` (H-81)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, signature: ChainSignature) -> None:
        """Inserta la firma y hace ``flush``, para que un error de la BD (``UNIQUE`` de
        ``last_audit_id``, el ``CHECK`` del largo) aparezca aquí."""
        self._session.add(signature)
        await self._session.flush()

    async def list_in_order(self) -> Sequence[ChainSignature]:
        """Todas las firmas de la más antigua a la más reciente. Se leen de la BD
        (``populate_existing``), no de la caché de la sesión: es lo que se verifica."""
        stmt = (
            select(ChainSignature)
            .order_by(ChainSignature.created_at, ChainSignature.last_audit_id)
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalars().all()
