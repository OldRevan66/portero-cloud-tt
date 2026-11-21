"""Firma diaria del cierre de la cadena del Servicio de Registro de Operaciones: funciones puras,
sin BD (conclusiones de TT1; H-81; H-46; OWASP ASVS V7.3.3).

Sin ancla, borrar el final de la cadena o reescribirla y recalcularla completa pasa
``verify_chain`` (H-46). Una vez al día, ``python -m portero.cli sign-chain`` firma con Ed25519
el ``current_hash`` del último registro. Para alterar lo que una firma cubre sin que se note hay
que tener la llave privada, que no vive en la API.

La firma la calcula el Motor Criptográfico (``portero.crypto.signing``); aquí solo se arma el
mensaje y se decide qué firmas son válidas.
"""

import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from portero.crypto.signing import public_key_thumbprint, verify_detached

CHECKPOINT_DOMAIN = b"portero-cloud/oplog-checkpoint/v1\n"
"""Etiqueta de dominio al inicio de cada mensaje firmado: una firma del cierre no sirve en
ningún otro contexto, y ``v1`` permite cambiar el formato sin ambigüedad."""


def checkpoint_message(
    *, created_at: datetime, last_audit_id: int, last_hash: str, public_key_thumbprint: str
) -> bytes:
    """Bytes que se firman: ``CHECKPOINT_DOMAIN`` + JSON canónico (llaves ordenadas, sin
    espacios, UTF-8) de los cuatro campos de la firma (H-81).

    ``created_at`` va en UTC con microsegundos, igual que ``event_timestamp`` en la cadena
    (``chain.canonical_json``): el texto es el mismo antes y después de pasar por la BD. Como la
    fecha entra en el mensaje, una firma vieja no se puede hacer pasar por reciente.

    Lanza ``ValueError`` si ``created_at`` no tiene zona horaria.
    """
    if created_at.tzinfo is None:
        raise ValueError("created_at debe tener zona horaria")
    record = {
        "created_at": created_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "last_audit_id": last_audit_id,
        "last_hash": last_hash,
        "public_key_thumbprint": public_key_thumbprint,
    }
    text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return CHECKPOINT_DOMAIN + text.encode("utf-8")


@dataclass(frozen=True)
class SignatureRow:
    """Una fila de ``chain_signatures`` tal como se verifica."""

    id: UUID
    created_at: datetime
    last_audit_id: int
    last_hash: str
    signature: bytes
    public_key_thumbprint: str


@dataclass(frozen=True)
class CheckpointVerification:
    """Resultado de ``verify_checkpoints``.

    ``invalid`` y ``missing`` son ids de firma en texto. ``last_signed_at`` y
    ``last_signed_audit_id`` son de la firma **válida** más reciente (``None`` si no hay).
    """

    signing_configured: bool
    total: int
    invalid: list[str]
    missing: list[str]
    last_signed_at: datetime | None
    last_signed_audit_id: int | None


def _is_valid(
    row: SignatureRow,
    *,
    stored_hashes: Mapping[int, str],
    broken: Collection[int],
    public_key: Ed25519PublicKey,
    thumbprint: str,
) -> bool:
    """Las tres condiciones de una firma válida (H-81)."""
    # 1. De la llave configurada. Otra llave cuenta como inválida, no se omite: si se omitiera,
    #    cambiar el thumbprint en la BD desactivaría el ancla.
    if row.public_key_thumbprint != thumbprint:
        return False
    # 2. Firma Ed25519 válida sobre el mensaje reconstruido con los datos de la fila.
    message = checkpoint_message(
        created_at=row.created_at,
        last_audit_id=row.last_audit_id,
        last_hash=row.last_hash,
        public_key_thumbprint=row.public_key_thumbprint,
    )
    if not verify_detached(public_key, message, row.signature):
        return False
    # 3. La fila firmada sigue ahí, íntegra y con el mismo ``current_hash`` almacenado. Si falta,
    #    alguien truncó lo firmado; si cambió, alguien reescribió y recalculó la cadena.
    return row.last_audit_id not in broken and stored_hashes.get(row.last_audit_id) == row.last_hash


def verify_checkpoints(
    signatures: Sequence[SignatureRow],
    *,
    stored_hashes: Mapping[int, str],
    broken: Collection[int],
    recorded_signature_ids: Collection[UUID],
    public_key: Ed25519PublicKey | None,
) -> CheckpointVerification:
    """Verifica las firmas del cierre contra la cadena ya recorrida por ``verify_chain`` (H-81).

    - ``signatures``: filas de ``chain_signatures`` de la más antigua a la más reciente.
    - ``stored_hashes``: ``id`` → ``current_hash`` **almacenado** de cada registro de la cadena.
    - ``broken``: los ``id`` que ``verify_chain`` marcó como rotos.
    - ``recorded_signature_ids``: ``resource_id`` de cada ``sign_chain`` exitoso de la
      bitácora. Si una de esas firmas ya no está en ``chain_signatures``, se reporta como
      faltante: alguien borró la firma sin tocar la cadena.
    - ``public_key``: la de ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY``; con ``None`` la firma no está
      configurada y no se revisa nada.
    """
    if public_key is None:
        return CheckpointVerification(False, len(signatures), [], [], None, None)

    thumbprint = public_key_thumbprint(public_key)
    invalid: list[str] = []
    last_valid: SignatureRow | None = None
    for row in signatures:
        if _is_valid(
            row,
            stored_hashes=stored_hashes,
            broken=broken,
            public_key=public_key,
            thumbprint=thumbprint,
        ):
            last_valid = row
        else:
            invalid.append(str(row.id))

    present = {row.id for row in signatures}
    missing = [str(sid) for sid in recorded_signature_ids if sid not in present]
    return CheckpointVerification(
        signing_configured=True,
        total=len(signatures),
        invalid=invalid,
        missing=missing,
        last_signed_at=last_valid.created_at if last_valid else None,
        last_signed_audit_id=last_valid.last_audit_id if last_valid else None,
    )
