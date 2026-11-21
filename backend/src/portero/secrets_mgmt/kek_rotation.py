"""Rotación de la KEK: versión N+1 y re-envoltura de todas las DEKs en una sola transacción
(spec §1.6; H-07, H-05, H-06, H-40; NIST SP 800-57 Parte 1 §5.3, criptoperíodo).

**H-07.** El Cap. 6 permite descifrar con KEKs históricas "si permanecen accesibles", pero el
proceso solo conoce una passphrase (``PORTERO_KEK_PASSPHRASE``), así que solo puede derivar la
KEK activa. Por eso la rotación re-envuelve **todas** las DEKs bajo la KEK nueva: 60 B por versión
de secreto, sin tocar el valor cifrado (``ciphertext``, ``nonce`` y ``auth_tag``).

**H-40.** El proceso de la API guarda la KEK en memoria desde su arranque. Si sigue en marcha
durante o después de la rotación, cifraría versiones nuevas con la KEK ya desactivada y quedarían
indescifrables al reiniciar. Defensa: la transacción toma ``LOCK TABLE secret_versions IN
EXCLUSIVE MODE``, y el procedimiento operativo es detener la API → ``rotate-kek`` → actualizar
``PORTERO_KEK_PASSPHRASE`` → arrancar la API (la CLI lo advierte).

Vive en ``secrets_mgmt`` porque es uno de los dos servicios autorizados a usar ``crypto`` (regla
de capas del Cap. 5). La CLI solo pide las passphrases y llama a ``rotate_kek``.
"""

import secrets
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from portero.crypto.engine import CryptoEngine, SecretContext
from portero.crypto.kek import PARAMETROS_KEK_PRODUCCION, KdfParams, KeyManager
from portero.db.repositories.secret import KekVersionRepository, SecretRepository
from portero.oplog.service import OperationEvent, OperationLogService
from portero.secrets_mgmt.errors import KekRotationError
from portero.secrets_mgmt.kek_store import kek_record_from_row, kek_row_from_record
from portero.secrets_mgmt.service import bundle_from_row

CLI_ACTOR_REF: Final = "cli:rotate-kek"
"""``actor_ref`` del registro (spec Fase 5 §5.3). ``actor_type`` es ``human``: quien ejecuta la
CLI es un operador con acceso al servidor (humano en el bucle); ``actor_user_id`` es NULL."""


@dataclass(frozen=True)
class KekRotationResult:
    """Resumen de una rotación de KEK, sin material criptográfico."""

    from_version: int
    to_version: int
    new_kek_version_id: UUID
    rewrapped_deks: int


async def rotate_kek(
    session: AsyncSession,
    *,
    current_passphrase: bytes,
    new_passphrase: bytes,
    oplog: OperationLogService | None = None,
    new_params: KdfParams = PARAMETROS_KEK_PRODUCCION,
) -> KekRotationResult:
    """Rota la KEK de la versión N a la N+1 en **una sola transacción** (spec §1.6; H-07).

    1. ``SELECT ... FOR UPDATE`` de la KEK activa (serializa rotaciones simultáneas).
    2. Deriva la KEK N con ``current_passphrase`` y comprueba su verificador (H-06).
    3. Crea la versión N+1: sal nueva, Argon2id con ``new_params`` y verificador.
    4. ``LOCK TABLE secret_versions IN EXCLUSIVE MODE`` (H-40).
    5. Desactiva N e inserta N+1, en ese orden (índice único parcial, H-18).
    6. Re-envuelve cada DEK: AAD con el ``kek_version_id`` nuevo (H-05). Si una fila no
       pertenece a la KEK N o no autentica, falla todo.
    7. Registra ``rotate_kek`` en el Servicio de Registro de Operaciones (H-11) y confirma.

    Cualquier error revierte todo: la versión N sigue activa y ninguna DEK cambia. Las
    versiones se cargan en memoria de una vez; el volumen de una PyME lo permite. Ambas KEKs se
    borran de memoria al terminar (Algoritmo 4).

    Raises:
        KekRotationError: no hay KEK activa, o la passphrase nueva está vacía o es igual a la
            actual.
        KekPassphraseError: ``current_passphrase`` no es la de la KEK activa.
        CryptoError: una DEK no pudo re-envolverse (fila alterada o de otra KEK).
    """
    if not new_passphrase:
        raise KekRotationError("la passphrase nueva no puede estar vacía")
    if secrets.compare_digest(new_passphrase, current_passphrase):
        raise KekRotationError("la passphrase nueva debe ser distinta de la actual")
    oplog = oplog or OperationLogService()

    kek_repo = KekVersionRepository(session)
    secret_repo = SecretRepository(session)
    old_km: KeyManager | None = None
    new_km: KeyManager | None = None
    try:
        row = await kek_repo.get_active_for_update()
        if row is None:
            raise KekRotationError("no hay KEK activa que rotar")
        old_record = kek_record_from_row(row)
        old_km = KeyManager.load(old_record, current_passphrase)
        new_km, new_record = KeyManager.create_version(
            new_passphrase, version_number=old_record.version_number + 1, params=new_params
        )

        await secret_repo.lock_versions_for_kek_rotation()
        await kek_repo.deactivate(old_record.id)
        await kek_repo.add(kek_row_from_record(new_record))

        old_engine = CryptoEngine(old_km)
        versions = await secret_repo.list_all_versions()
        for version in versions:
            rewrapped = old_engine.rewrap_dek(
                bundle_from_row(version),
                ctx=SecretContext(version.secret_id, version.version_number),
                target=new_km,
            )
            await secret_repo.set_wrapped_dek(
                version,
                wrapped_dek=rewrapped.wrapped_dek,
                wrap_algorithm=rewrapped.wrap_algorithm,
                kek_version_id=rewrapped.kek_version_id,
            )

        result = KekRotationResult(
            from_version=old_record.version_number,
            to_version=new_record.version_number,
            new_kek_version_id=new_record.id,
            rewrapped_deks=len(versions),
        )
        await oplog.record(
            session,
            OperationEvent(
                actor_type="human",
                actor_ref=CLI_ACTOR_REF,
                verb="rotate_kek",
                result="success",
                resource_type="kek_version",
                resource_id=new_record.id,
                details={
                    "from_version": result.from_version,
                    "to_version": result.to_version,
                    "rewrapped_deks": result.rewrapped_deks,
                },
            ),
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        raise
    finally:
        for km in (old_km, new_km):
            if km is not None:
                km.close()
    return result
