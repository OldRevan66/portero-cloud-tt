"""Endpoints del Servicio de Registro de Operaciones (CU-06; Cap. 6 §Endpoints de operaciones;
spec Fase 5 §1, §2, §4.1, §4.3, §5; H-12, H-14, H-23b; RF-019 a RF-021; OWASP ASVS V7.3.3).

El recurso se llama ``operations`` y no ``audit`` (Cap. 6, discusión P6).

**Autorización (H-23b).** ``Authorizer.audit_scope`` decide qué parte de la bitácora puede leer el
actor:

- ``audit:read`` de instancia (Administrador) → toda la bitácora, incluidos los registros sin
  ``project_id`` (login, usuarios, ``verify_chain``).
- ``audit:read`` en algunos proyectos (Líder Técnico) → solo los registros de esos proyectos.
- Sin ``audit:read`` en ningún contexto (Desarrollador, service account) → 403, **antes** de
  cargar nada: la respuesta no depende de si el registro pedido existe.

En ``GET /operations/{id}`` un registro fuera del alcance responde 404 igual que uno inexistente
(regla 4.1, H-14) y deja un ``access_denied``. ``verify-chain`` recorre toda la cadena, así que
exige ``audit:read`` de instancia.

Las consultas no se registran (spec §5.2); ``verify-chain`` sí (spec §5.4).

**Exportación (RF-021, H-83).** ``GET /operations/export`` usa los mismos filtros, el mismo permiso
y el mismo alcance que ``GET /operations`` (``OperationFilters``), pero sí se registra
(``export_operations``): es una extracción masiva. Se genera por lotes y el CSV neutraliza las
celdas que parecen fórmula (``oplog.export``).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator

from portero.api.deps import Authorizer, AuthorizerDep, ChainPublicKeyDep, SessionDep
from portero.api.errors import ApiProblem, problem_responses
from portero.api.pagination import decode_cursor, encode_cursor
from portero.api.params import CanonicalUUID, PlainText
from portero.db.repositories.audit import AuditQuery
from portero.oplog.chain import ChainVerification
from portero.oplog.export import csv_stream, json_stream
from portero.oplog.service import OperationLogService, OperationPage
from portero.rbac.evaluator import ALL_PROJECTS, AllProjects
from portero.rbac.permissions import Permission

router = APIRouter(prefix="/operations", tags=["operaciones"])

_oplog = OperationLogService()

RESOURCE_TYPE = "audit_log"
"""``resource_type`` de los ``access_denied`` sobre la bitácora."""

MAX_LOG_ID = 2**63 - 1
"""``audit_logs.id`` es BIGSERIAL: un id mayor no puede existir (y no se manda a la BD)."""


# --- Esquemas ------------------------------------------------------------------------------------


class OperationOut(BaseModel):
    """Un registro de la bitácora: los campos encadenados por el hash (spec §5.1) más ``id``,
    ``previous_hash`` y ``current_hash``. ``details`` nunca contiene valores (H-12)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_timestamp: datetime
    actor_user_id: UUID | None
    actor_type: str
    actor_ref: str
    verb: str
    resource_type: str | None
    resource_id: UUID | None
    result: str
    ip_address: str | None
    user_agent: str | None
    project_id: UUID | None
    environment_id: UUID | None
    details: dict[str, Any] | None
    previous_hash: str | None
    current_hash: str

    @field_validator("ip_address", mode="before")
    @classmethod
    def _ip_as_text(cls, value: object) -> object:
        """``INET`` llega como ``ipaddress.IPv4Address``/``IPv6Address``; se entrega como texto."""
        return None if value is None else str(value)


class OperationPageOut(BaseModel):
    """Página de la bitácora (spec §1): ``next_cursor`` nulo si no hay más."""

    items: list[OperationOut]
    next_cursor: str | None


class ChainReport(BaseModel):
    """Reporte de ``verify-chain`` (spec §5.1): rango verificado, total, filas rotas y
    ``last_hash``, el ancla que el Administrador anota fuera de la BD para detectar un truncado
    o una reescritura completa de la cadena (H-46).

    **[H-81]** Firma diaria del cierre: ``signing_configured`` (si la API tiene la llave
    pública), cuántas firmas hay, los ids de las inválidas y de las faltantes, y la fecha y el
    registro de la última firma válida. Lo posterior a esa fecha solo lo protege la cadena."""

    model_config = ConfigDict(from_attributes=True)

    verified_from: int | None
    verified_to: int | None
    total: int
    ok: bool
    broken: list[int]
    last_hash: str | None
    signing_configured: bool
    signatures_total: int
    invalid_signatures: list[str]
    missing_signatures: list[str]
    last_signed_at: datetime | None
    last_signed_audit_id: int | None


# --- Auxiliares ----------------------------------------------------------------------------------


async def _require_audit_scope(authz: Authorizer) -> AllProjects | frozenset[UUID]:
    """Alcance de lectura de la bitácora; vacío → 403 con ``access_denied`` (spec §4.3)."""
    scope = authz.audit_scope()
    if scope is not ALL_PROJECTS and not scope:
        await authz.deny(
            403,
            Permission.AUDIT_READ,
            resource_type=RESOURCE_TYPE,
            resource_id=None,
            project_id=None,
        )
    return scope


def _project_filter(
    scope: AllProjects | frozenset[UUID], project_id: UUID | None
) -> frozenset[UUID] | None:
    """Alcance ∩ filtro ``project_id``. Un proyecto fuera del alcance da el conjunto vacío
    (lista vacía), no un error: no revela si el proyecto existe."""
    if not isinstance(scope, frozenset):  # ALL_PROJECTS
        return None if project_id is None else frozenset({project_id})
    return scope if project_id is None else scope & {project_id}


@dataclass(frozen=True)
class OperationFilters:
    """Filtros de la bitácora (Cap. 6; spec §4.3), comunes a la consulta y a la exportación."""

    actor_user_id: UUID | None
    verb: str | None
    resource_type: str | None
    result: str | None
    project_id: UUID | None
    since: datetime | None
    until: datetime | None

    def query(self, scope: AllProjects | frozenset[UUID]) -> AuditQuery:
        """``AuditQuery`` con el alcance del actor ya aplicado (H-23b)."""
        return AuditQuery(
            project_ids=_project_filter(scope, self.project_id),
            actor_user_id=self.actor_user_id,
            verb=self.verb,
            resource_type=self.resource_type,
            result=self.result,
            since=self.since,
            until=self.until,
        )

    def as_details(self) -> dict[str, str]:
        """Los filtros pedidos, como texto y con los nombres de la URL, para ``details`` de
        ``export_operations``. Solo los no nulos."""
        pedidos = {
            "actor_user_id": self.actor_user_id,
            "verb": self.verb,
            "resource_type": self.resource_type,
            "result": self.result,
            "project_id": self.project_id,
            "from": self.since,
            "to": self.until,
        }
        return {
            k: v.isoformat() if isinstance(v, datetime) else str(v)
            for k, v in pedidos.items()
            if v is not None
        }


def operation_filters(
    actor_user_id: Annotated[CanonicalUUID | None, Query(description="Usuario actor.")] = None,
    verb: Annotated[
        PlainText | None, Query(max_length=32, description="Verbo (spec §5.2).")
    ] = None,
    resource_type: Annotated[PlainText | None, Query(max_length=32)] = None,
    result: Annotated[Literal["success", "failure"] | None, Query()] = None,
    project_id: Annotated[
        CanonicalUUID | None, Query(description="Proyecto, dentro del alcance del actor.")
    ] = None,
    since: Annotated[
        AwareDatetime | None,
        Query(alias="from", description="Desde (inclusivo), ISO 8601 con zona."),
    ] = None,
    until: Annotated[
        AwareDatetime | None,
        Query(alias="to", description="Hasta (inclusivo), ISO 8601 con zona."),
    ] = None,
) -> OperationFilters:
    """Lee y valida los filtros de la URL (los de ``GET /operations``); ``from > to`` → 400."""
    if since is not None and until is not None and since > until:
        raise ApiProblem(400, "validation-error", "El rango de fechas no es válido.")
    return OperationFilters(actor_user_id, verb, resource_type, result, project_id, since, until)


FiltersDep = Annotated[OperationFilters, Depends(operation_filters)]

EXPORT_MEDIA_TYPES: dict[str, str] = {"csv": "text/csv", "json": "application/json"}
"""Tipo de cada formato. Starlette agrega ``; charset=utf-8`` a ``text/csv``."""


def _page(page: OperationPage) -> OperationPageOut:
    return OperationPageOut(
        items=[OperationOut.model_validate(r) for r in page.items],
        next_cursor=None if page.next_before is None else encode_cursor(page.next_before),
    )


# --- Rutas ---------------------------------------------------------------------------------------


@router.get(
    "",
    response_model=OperationPageOut,
    summary="Consultar la bitácora",
    responses=problem_responses(400, 401, 403, 429),
)
async def list_operations(
    session: SessionDep,
    authz: AuthorizerDep,
    filters: FiltersDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=64)] = None,
) -> OperationPageOut:
    """CU-06: registros de la bitácora, del más reciente al más antiguo, paginados por cursor.
    Filtros por actor, verbo, tipo de recurso, resultado, proyecto y rango de
    ``event_timestamp``. ``audit:read``: el Administrador ve todo; el Líder Técnico, solo sus
    proyectos (H-23b)."""
    before = None if cursor is None else decode_cursor(cursor)
    scope = await _require_audit_scope(authz)
    return _page(
        await _oplog.list_operations(session, filters.query(scope), limit=limit, before=before)
    )


@router.get(
    "/export",
    response_class=StreamingResponse,
    summary="Exportar la bitácora",
    responses={
        200: {
            "description": "Archivo adjunto con los registros, del más reciente al más antiguo.",
            "content": {"text/csv": {}, "application/json": {}},
        },
        **problem_responses(400, 401, 403, 429),
    },
)
async def export_operations(
    session: SessionDep,
    authz: AuthorizerDep,
    filters: FiltersDep,
    export_format: Annotated[
        Literal["csv", "json"], Query(alias="format", description="`csv` o `json`.")
    ],
) -> StreamingResponse:
    """RF-021 (H-83): descarga la bitácora con los mismos filtros, permiso y alcance que
    ``GET /operations`` (H-23b), como adjunto. Primero registra ``export_operations`` (si no se
    registra, no se exporta) y luego transmite, por lotes, lo anterior a ese registro. En CSV,
    las celdas que parecen fórmula se prefijan con ``'`` (OWASP CSV Injection)."""
    scope = await _require_audit_scope(authz)
    snapshot = await _oplog.export_and_record(
        session,
        authz.operation_actor,
        export_format=export_format,
        filters=filters.as_details(),
    )
    batches = _oplog.iter_operations(session, filters.query(scope), before=snapshot)
    body = csv_stream(batches) if export_format == "csv" else json_stream(batches)
    filename = f"bitacora-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.{export_format}"
    return StreamingResponse(
        body,
        media_type=EXPORT_MEDIA_TYPES[export_format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/verify-chain",
    response_model=ChainReport,
    summary="Verificar la integridad de la bitácora",
    responses=problem_responses(401, 403, 429),
)
async def verify_chain(
    session: SessionDep, authz: AuthorizerDep, public_key: ChainPublicKeyDep
) -> ChainVerification:
    """CU-06, RF-021: recalcula la cadena de hashes desde el primer registro y reporta el rango
    verificado y las filas alteradas, borradas o reordenadas, y revisa las firmas diarias del
    cierre si la firma está configurada (H-81). Solo ``audit:read`` de instancia
    (Administrador). Registra ``verify_chain`` con ``result`` según el resultado."""
    if authz.audit_scope() is not ALL_PROJECTS:
        await authz.deny(
            403,
            Permission.AUDIT_READ,
            resource_type=RESOURCE_TYPE,
            resource_id=None,
            project_id=None,
        )
    return await _oplog.verify_and_record(session, authz.operation_actor, public_key=public_key)


@router.get(
    "/{log_id}",
    response_model=OperationOut,
    summary="Consultar un registro de la bitácora",
    responses=problem_responses(400, 401, 403, 404, 429),
)
async def get_operation(
    log_id: Annotated[int, Path(ge=1, le=MAX_LOG_ID, description="`id` del registro.")],
    session: SessionDep,
    authz: AuthorizerDep,
) -> OperationOut:
    """CU-06: un registro por ``id``. Fuera del alcance del actor → 404 igual que uno
    inexistente (H-14, H-23b)."""
    scope = await _require_audit_scope(authz)
    entry = await _oplog.get_operation(session, log_id)
    if entry is None:
        raise ApiProblem(404, "resource-not-found")
    if isinstance(scope, frozenset) and entry.project_id not in scope:
        await authz.deny(
            404,
            Permission.AUDIT_READ,
            resource_type=RESOURCE_TYPE,
            resource_id=None,  # resource_id es UUID; el id del registro es un entero
            project_id=entry.project_id,
            environment_id=entry.environment_id,
        )
    return OperationOut.model_validate(entry)
