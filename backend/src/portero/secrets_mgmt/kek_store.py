"""Conexión entre el ``KeyManager`` del Motor Criptográfico y la tabla ``kek_versions``
(spec §1.6; H-06).

Vive en ``secrets_mgmt`` porque es uno de los dos servicios autorizados a usar ``crypto`` y a la
vez usa la Capa de Persistencia; así ni ``crypto`` importa ``db`` ni ``db`` importa ``crypto``
(regla de capas del Cap. 5).
"""

from sqlalchemy.ext.asyncio import AsyncSession

from portero.crypto.kek import PARAMETROS_KEK_PRODUCCION, KdfParams, KekVersionRecord, KeyManager
from portero.db.models import KekVersion
from portero.db.repositories.secret import KekVersionRepository


def kek_record_from_row(row: KekVersion) -> KekVersionRecord:
    """Fila ORM de ``kek_versions`` → ``KekVersionRecord`` del Motor Criptográfico."""
    return KekVersionRecord(
        id=row.id,
        version_number=row.version_number,
        source=row.source,
        kdf_algorithm=row.kdf_algorithm,
        kdf_params=row.kdf_params,
        verifier=row.verifier,
    )


def kek_row_from_record(record: KekVersionRecord) -> KekVersion:
    """``KekVersionRecord`` → fila ORM nueva y activa de ``kek_versions``."""
    return KekVersion(
        id=record.id,
        version_number=record.version_number,
        source=record.source,
        kdf_algorithm=record.kdf_algorithm,
        kdf_params=dict(record.kdf_params) if record.kdf_params is not None else None,
        verifier=record.verifier,
    )


class KekVersionStoreAdapter:
    """Implementa ``KekVersionStore`` traduciendo filas ORM ↔ ``KekVersionRecord``."""

    def __init__(self, repository: KekVersionRepository) -> None:
        self._repository = repository

    async def get_active(self) -> KekVersionRecord | None:
        row = await self._repository.get_active()
        return None if row is None else kek_record_from_row(row)

    async def add(self, record: KekVersionRecord) -> None:
        await self._repository.add(kek_row_from_record(record))


async def load_key_manager(
    session: AsyncSession,
    passphrase: bytes,
    *,
    new_params: KdfParams = PARAMETROS_KEK_PRODUCCION,
) -> KeyManager:
    """Arranque de la KEK: deriva la activa o crea la versión 1 y la confirma (spec §1.6).

    Se llama una vez al iniciar el proceso. Si lanza ``KekPassphraseError``, el proceso debe
    abortar (H-06). La derivación con los parámetros de producción tarda del orden de un segundo
    y bloquea el ciclo de eventos; es aceptable porque ocurre antes de atender peticiones.
    """
    try:
        manager = await KeyManager.bootstrap(
            KekVersionStoreAdapter(KekVersionRepository(session)),
            passphrase,
            new_params=new_params,
        )
    except BaseException:
        await session.rollback()
        raise
    try:
        await session.commit()
    except BaseException:
        manager.close()
        await session.rollback()
        raise
    return manager
