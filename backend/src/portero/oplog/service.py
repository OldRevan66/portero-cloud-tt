"""Servicio de Registro de Operaciones: registro síncrono en ``audit_logs`` con cadena de hashes
SHA-256, serializado con ``pg_advisory_xact_lock`` (Cap. 5 §Componentes; spec núcleo §5; spec
Fase 5 §5; H-11, H-12; RF-016 a RF-018; OWASP ASVS V7.3.3).

**H-11.** Los diagramas del Cap. 5 notifican a la bitácora de forma asíncrona. Con una cadena de
hashes eso bifurcaría la cadena y dejaría operaciones sin rastro. Por eso aquí el registro es
síncrono y ``record`` **nunca confirma**: inserta dentro de la transacción de quien llama, y si
ésta se revierte, el registro se revierte con ella. Quien llama debe invocar ``record`` justo
antes de su ``commit``. Así el lock de la cadena se toma siempre al final, después de los locks
de fila, y dura lo menos posible.

**H-12.** ``details`` es para metadatos pequeños. Nunca lleva valores de secretos, contraseñas ni
tokens: ``OperationEvent`` rechaza esas llaves.

**H-81.** ``sign_chain`` firma con Ed25519 el cierre de la cadena (lo invoca el CLI una vez al
día) y ``verify_chain`` revisa esas firmas si recibe la llave pública. La firma la calcula el
Motor Criptográfico.
"""

import dataclasses
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Final
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.ext.asyncio import AsyncSession

from portero.crypto.signing import public_key_thumbprint, sign_detached
from portero.db.models import AuditLog, ChainSignature
from portero.db.repositories.audit import AuditQuery, AuditRepository
from portero.db.repositories.chain_signature import ChainSignatureRepository
from portero.oplog.chain import (
    GENESIS_HASH,
    ChainRow,
    ChainVerification,
    canonical_json,
    compute_hash,
    verify_chain,
)
from portero.oplog.checkpoint import SignatureRow, checkpoint_message, verify_checkpoints

VERBS: Final = frozenset(
    {
        # Autenticación
        "login",
        "login_failed",
        "refresh",
        "refresh_reused",
        "logout",
        "change_password",
        # Secretos
        "create_secret",
        "read_secret",
        "rotate_secret",
        "update_secret",
        "archive_secret",
        # Proyectos
        "create_project",
        "update_project",
        "archive_project",
        # Ambientes
        "create_environment",
        "update_environment",
        "delete_environment",
        # Usuarios
        "create_user",
        "update_user",
        "deactivate_user",
        "assign_role",
        "revoke_role",
        "unlock_user",  # H-78
        "reset_password",  # H-78
        # Aplicaciones Cliente
        "create_service_account",
        "revoke_service_account",
        # KEK (CLI, H-07)
        "rotate_kek",
        # Bitácora y autorización
        "verify_chain",
        "sign_chain",  # H-81
        "export_operations",  # RF-021, H-83
        "access_denied",
    }
)
"""Catálogo de verbos (spec Fase 5 §5.2). Cerrado: un verbo fuera de él es un error de
programación, no un dato del cliente."""

RESULTS: Final = frozenset({"success", "failure"})
ACTOR_TYPES: Final = frozenset({"human", "service"})  # H-04

FORBIDDEN_DETAIL_FRAGMENTS: Final = ("password", "token", "value")
"""Fragmentos que ninguna llave de ``details`` puede contener, en ningún nivel (spec Fase 5 §5.3:
"jamás valores de secretos, contraseñas, tokens ni hashes"; H-12; RNF-006). **[H-48]** Se busca
el fragmento, no la llave exacta: así también caen ``new_value``, ``current_password``,
``refresh_token``, ``token_hash`` o ``password_hash``."""

FORBIDDEN_DETAIL_KEYS: Final = frozenset({"secret"})
"""Llaves prohibidas por coincidencia exacta. ``secret`` no va entre los fragmentos porque
``archived_secrets`` (un conteo, en ``archive_project``) es legítima."""

USER_AGENT_MAX = 512
"""Largo de ``audit_logs.user_agent`` (spec Fase 5 §5.3)."""

EXPORT_BATCH_SIZE = 500
"""Registros por consulta al exportar la bitácora (RF-021, H-83): en memoria solo hay un lote,
no toda la tabla (a diferencia de H-50). Se lee en cada llamada, para que las pruebas lo bajen."""


class ForbiddenDetailError(ValueError):
    """``details`` contiene una llave prohibida. El mensaje nombra la llave, nunca el valor."""

    def __init__(self, key: str) -> None:
        super().__init__(f"details no puede contener la llave {key!r} (H-12)")
        self.key = key


def _forbidden_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in FORBIDDEN_DETAIL_KEYS or any(f in lowered for f in FORBIDDEN_DETAIL_FRAGMENTS)


def _check_details(value: object) -> None:
    """Recorre ``details`` (dicts y listas anidados) buscando llaves prohibidas."""
    if isinstance(value, Mapping):
        for key, inner in value.items():
            if isinstance(key, str) and _forbidden_key(key):
                raise ForbiddenDetailError(key)
            _check_details(inner)
    elif isinstance(value, list | tuple):
        for inner in value:
            _check_details(inner)


class ChainNotIntactError(Exception):
    """``sign_chain`` se negó a firmar: la cadena o una firma anterior no pasa la verificación.
    Firmarla "lavaría" la alteración (H-81). ``report`` trae el detalle."""

    def __init__(self, report: ChainVerification) -> None:
        super().__init__("la bitácora no está íntegra; no se firma el cierre (H-81)")
        self.report = report


class EmptyChainError(Exception):
    """``sign_chain`` no tiene qué firmar: la bitácora está vacía."""

    def __init__(self) -> None:
        super().__init__("la bitácora está vacía; no hay cierre que firmar")


@dataclass(frozen=True)
class ClientInfo:
    """Origen de la petición HTTP: IP del cliente (``request.client.host``) y ``User-Agent``
    (spec Fase 5 §5.3). Fuera de HTTP (CLI, pruebas del servicio) ambos son ``None``."""

    ip_address: str | None = None
    user_agent: str | None = None


NO_CLIENT: Final = ClientInfo()


@dataclass(frozen=True)
class OperationEvent:
    """Una operación por registrar (spec Fase 5 §5.3). Se valida al construirse: verbo del
    catálogo, ``result`` y ``actor_type`` válidos, y ``details`` sin llaves prohibidas (H-12).

    ``actor_user_id`` es ``None`` para un service account, para el CLI o para un
    ``login_failed`` con correo inexistente. ``project_id`` y ``environment_id`` son el contexto
    del recurso, sin FK, para que el registro sobreviva al recurso (H-12).
    """

    actor_type: str
    actor_ref: str
    verb: str
    result: str
    actor_user_id: UUID | None = None
    resource_type: str | None = None
    resource_id: UUID | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    project_id: UUID | None = None
    environment_id: UUID | None = None
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.verb not in VERBS:
            raise ValueError(f"verbo fuera del catálogo: {self.verb!r}")
        if self.result not in RESULTS:
            raise ValueError(f"result inválido: {self.result!r}")
        if self.actor_type not in ACTOR_TYPES:
            raise ValueError(f"actor_type inválido: {self.actor_type!r}")
        _check_details(self.details)


@dataclass(frozen=True)
class OperationActor:
    """Quién hace la operación y desde dónde (spec Fase 5 §5.3), para los servicios que
    registran eventos sobre recursos (Servicios de Gestión, Servicio de Gestión de Secretos).

    ``actor_ref`` es el correo de un humano o ``sa:<id>`` de un service account;
    ``actor_user_id`` es ``None`` para un service account (H-04).
    """

    actor_type: str
    actor_ref: str
    actor_user_id: UUID | None
    client: ClientInfo = NO_CLIENT

    def event(
        self,
        verb: str,
        result: str,
        *,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> OperationEvent:
        """``OperationEvent`` de este actor; valida verbo y ``details`` al construirse."""
        return OperationEvent(
            actor_type=self.actor_type,
            actor_ref=self.actor_ref,
            verb=verb,
            result=result,
            actor_user_id=self.actor_user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=self.client.ip_address,
            user_agent=self.client.user_agent,
            project_id=project_id,
            environment_id=environment_id,
            details=details,
        )


def _normalize_ip(value: str | None) -> str | None:
    """Forma canónica de la IP, la misma que devolverá ``INET``. Si no es una IP (p. ej. el
    ``"testclient"`` de Starlette), ``None``."""
    if value is None:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


SIGN_CHAIN_ACTOR: Final = OperationActor("human", "cli:sign-chain", None)
"""Actor de ``sign_chain`` (spec Fase 5 §5.3): el CLI, como ``cli:rotate-kek``."""

SIGNATURE_RESOURCE_TYPE: Final = "chain_signature"


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class OperationPage:
    """Una página de la bitácora. ``next_before`` es la clave del cursor siguiente (el último
    ``id`` entregado), o ``None`` si no hay más (spec Fase 5 §1)."""

    items: list[AuditLog]
    next_before: int | None


class OperationLogService:
    """Servicio de Registro de Operaciones (Cap. 5 §Componentes; RF-016 a RF-021).

    ``clock`` fija ``event_timestamp``. ``AuthService`` le pasa el suyo, para que las pruebas
    controlen el tiempo.
    """

    def __init__(self, *, clock: Clock = _utc_now) -> None:
        self._clock = clock

    async def record(self, session: AsyncSession, event: OperationEvent) -> AuditLog:
        """Agrega ``event`` a la cadena dentro de la transacción de ``session`` (H-11; RF-018).

        1. ``pg_advisory_xact_lock``: un solo registro a la vez en toda la instancia.
        2. Lee el último ``current_hash`` (o ``GENESIS_HASH``) ya con el lock tomado.
        3. Calcula ``current_hash = SHA-256(previous_hash || JSON canónico)`` e inserta.

        **No confirma.** El ``commit`` lo hace quien llama, en la misma transacción que el
        cambio. La IP se normaliza y el ``user_agent`` se trunca antes de calcular el hash, para
        que lo encadenado sea exactamente lo que se guarda.
        """
        audit = AuditRepository(session)
        await audit.lock_chain()
        previous_hash = await audit.last_hash() or GENESIS_HASH
        fields: dict[str, Any] = {
            "event_timestamp": self._clock(),
            "actor_user_id": event.actor_user_id,
            "actor_type": event.actor_type,
            "actor_ref": event.actor_ref,
            "verb": event.verb,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "result": event.result,
            "ip_address": _normalize_ip(event.ip_address),
            "user_agent": (
                event.user_agent[:USER_AGENT_MAX] if event.user_agent is not None else None
            ),
            "project_id": event.project_id,
            "environment_id": event.environment_id,
            "details": event.details,
        }
        entry = AuditLog(
            **fields,
            previous_hash=previous_hash,
            current_hash=compute_hash(previous_hash, canonical_json(fields)),
        )
        await audit.add(entry)
        return entry

    async def verify_chain(
        self, session: AsyncSession, *, public_key: Ed25519PublicKey | None = None
    ) -> ChainVerification:
        """Recalcula toda la cadena desde la BD, por ``id`` ascendente (spec Fase 5 §5.1;
        OWASP ASVS V7.3.3), y revisa las firmas del cierre (H-81). Solo lee. El evento
        ``verify_chain`` lo registra el endpoint que lo invoca (spec §5.4).

        Con ``public_key`` (la de ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY``), ``ok`` exige además que
        ninguna firma sea inválida ni falte. Sin ella, la firma no está configurada y el
        resultado es el de la cadena sola.
        """
        entries = await AuditRepository(session).list_in_order()
        rows = [
            ChainRow(
                id=e.id,
                previous_hash=e.previous_hash,
                current_hash=e.current_hash,
                fields={
                    "event_timestamp": e.event_timestamp,
                    "actor_user_id": e.actor_user_id,
                    "actor_type": e.actor_type,
                    "actor_ref": e.actor_ref,
                    "verb": e.verb,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "result": e.result,
                    "ip_address": e.ip_address,
                    "user_agent": e.user_agent,
                    "project_id": e.project_id,
                    "environment_id": e.environment_id,
                    "details": e.details,
                },
            )
            for e in entries
        ]
        chain = verify_chain(rows)
        signatures = [
            SignatureRow(
                id=sig.id,
                created_at=sig.created_at,
                last_audit_id=sig.last_audit_id,
                last_hash=sig.last_hash,
                signature=sig.signature,
                public_key_thumbprint=sig.public_key_thumbprint,
            )
            for sig in await ChainSignatureRepository(session).list_in_order()
        ]
        checkpoints = verify_checkpoints(
            signatures,
            stored_hashes={e.id: e.current_hash for e in entries},
            broken=set(chain.broken),
            recorded_signature_ids=[
                e.resource_id
                for e in entries
                if e.verb == "sign_chain" and e.result == "success" and e.resource_id is not None
            ],
            public_key=public_key,
        )
        return dataclasses.replace(
            chain,
            ok=chain.ok and not checkpoints.invalid and not checkpoints.missing,
            signing_configured=checkpoints.signing_configured,
            signatures_total=checkpoints.total,
            invalid_signatures=checkpoints.invalid,
            missing_signatures=checkpoints.missing,
            last_signed_at=checkpoints.last_signed_at,
            last_signed_audit_id=checkpoints.last_signed_audit_id,
        )

    async def sign_chain(
        self, session: AsyncSession, private_key: Ed25519PrivateKey
    ) -> ChainSignature:
        """Firma el cierre de la cadena: el ``current_hash`` del último registro (H-81).

        En una sola transacción:

        1. ``lock_chain()``: nadie agrega registros mientras se verifica y se firma.
        2. Verifica la cadena y las firmas anteriores con la llave pública de ``private_key``.
           Si algo no cuadra, **no firma**: registra ``sign_chain`` con ``failure``, confirma y
           lanza ``ChainNotIntactError``. Firmar una cadena alterada la "lavaría".
        3. Firma ``checkpoint_message`` del último registro y guarda la fila en
           ``chain_signatures``.
        4. Registra ``sign_chain`` con ``success`` y el id de la firma en ``resource_id``. Ese
           registro queda después del cierre: lo cubre la firma siguiente.
        5. ``commit``.

        Lanza ``EmptyChainError`` si la bitácora está vacía.
        """
        public_key = private_key.public_key()
        try:
            await AuditRepository(session).lock_chain()
            report = await self.verify_chain(session, public_key=public_key)
            if not report.ok:
                await self.record(
                    session,
                    SIGN_CHAIN_ACTOR.event(
                        "sign_chain",
                        "failure",
                        resource_type=SIGNATURE_RESOURCE_TYPE,
                        details={
                            "broken_count": len(report.broken),
                            "invalid_signatures_count": len(report.invalid_signatures),
                            "missing_signatures_count": len(report.missing_signatures),
                        },
                    ),
                )
                await session.commit()
                raise ChainNotIntactError(report)
            if report.verified_to is None or report.last_hash is None:
                raise EmptyChainError()

            thumbprint = public_key_thumbprint(public_key)
            created_at = self._clock()
            message = checkpoint_message(
                created_at=created_at,
                last_audit_id=report.verified_to,
                last_hash=report.last_hash,
                public_key_thumbprint=thumbprint,
            )
            signature = ChainSignature(
                created_at=created_at,
                last_audit_id=report.verified_to,
                last_hash=report.last_hash,
                signature=sign_detached(private_key, message),
                public_key_thumbprint=thumbprint,
            )
            await ChainSignatureRepository(session).add(signature)
            await self.record(
                session,
                SIGN_CHAIN_ACTOR.event(
                    "sign_chain",
                    "success",
                    resource_type=SIGNATURE_RESOURCE_TYPE,
                    resource_id=signature.id,
                    details={"last_audit_id": report.verified_to, "last_hash": report.last_hash},
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return signature

    async def list_operations(
        self, session: AsyncSession, query: AuditQuery, *, limit: int, before: int | None
    ) -> OperationPage:
        """Consulta de la bitácora para CU-06 (RF-019, RF-020), de la más reciente a la más
        antigua. Pide ``limit + 1`` filas para saber si hay otra página. El alcance
        (``query.project_ids``) lo decide la autorización (H-23b). Las consultas no se
        registran (spec §5.2)."""
        rows = await AuditRepository(session).list_page(query, limit=limit + 1, before=before)
        items = list(rows[:limit])
        next_before = items[-1].id if len(rows) > limit else None
        return OperationPage(items, next_before)

    async def export_and_record(
        self,
        session: AsyncSession,
        actor: OperationActor,
        *,
        export_format: str,
        filters: dict[str, str],
    ) -> int:
        """Registra ``export_operations`` y confirma **antes** de exportar (RF-021, H-83).

        Una exportación es una extracción masiva, así que se registra aunque las consultas no
        (spec Fase 5 §5.2). Fail-closed como ``read_secret``: si no se registra, no se exporta.
        ``details`` lleva el formato y los filtros pedidos (``filters``, solo los no nulos); es
        un evento de instancia (``project_id`` nulo) que supervisa el Administrador.

        Devuelve el ``id`` del registro: la exportación es la instantánea de lo anterior a él
        (``iter_operations(before=id)``). Se registra la solicitud, no la descarga completa: si
        el cliente corta la conexión, el registro ya dice ``success``.
        """
        try:
            entry = await self.record(
                session,
                actor.event(
                    "export_operations",
                    "success",
                    details={"format": export_format, "filters": filters},
                ),
            )
            entry_id = entry.id
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return entry_id

    async def iter_operations(
        self, session: AsyncSession, query: AuditQuery, *, before: int
    ) -> AsyncIterator[Sequence[AuditLog]]:
        """Los registros que cumplen ``query`` con ``id < before``, del más reciente al más
        antiguo, en lotes de ``EXPORT_BATCH_SIZE`` (RF-021, H-83). Cada lote es una consulta
        keyset (``list_page``): la memoria no crece con el tamaño de la bitácora. Como los ids
        nuevos siempre son mayores (H-11), lo que se inserte mientras tanto no entra."""
        audit = AuditRepository(session)
        batch_size = EXPORT_BATCH_SIZE
        while True:
            rows = await audit.list_page(query, limit=batch_size, before=before)
            if rows:
                yield rows
            if len(rows) < batch_size:
                return
            before = rows[-1].id

    async def get_operation(self, session: AsyncSession, log_id: int) -> AuditLog | None:
        """Un registro por ``id`` (CU-06), o ``None`` si no existe."""
        return await AuditRepository(session).get(log_id)

    async def verify_and_record(
        self,
        session: AsyncSession,
        actor: OperationActor,
        *,
        public_key: Ed25519PublicKey | None = None,
    ) -> ChainVerification:
        """``verify_chain`` y su registro (spec Fase 5 §5.4: "al terminar la verificación, con
        ``result`` según el resultado"; RF-021; OWASP ASVS V7.3.3).

        El reporte cubre la cadena tal como estaba al empezar; el registro ``verify_chain`` se
        agrega después y queda para la siguiente verificación. ``details`` lleva el total,
        cuántas filas están rotas (los ids van en la respuesta), el ancla ``last_hash``
        (H-46) y los conteos de firmas del cierre (H-81)."""
        try:
            report = await self.verify_chain(session, public_key=public_key)
            await self.record(
                session,
                actor.event(
                    "verify_chain",
                    "success" if report.ok else "failure",
                    details={
                        "total": report.total,
                        "broken_count": len(report.broken),
                        "last_hash": report.last_hash,
                        "signatures_total": report.signatures_total,
                        "invalid_signatures_count": len(report.invalid_signatures),
                        "missing_signatures_count": len(report.missing_signatures),
                    },
                ),
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        return report
