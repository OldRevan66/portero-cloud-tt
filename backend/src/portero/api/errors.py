"""Manejo de errores con Problem Details (RFC 9457; Cap. 6 §Manejo de errores; spec Fase 5 §6).

Toda respuesta de error del API REST Gateway es ``application/problem+json`` con
``{type, title, status, detail, instance, trace_id}``:

- ``type`` = ``https://portero-cloud.example/errors/<tipo>``; ``title`` fijo por tipo.
- ``instance`` = ruta de la petición, sin query string (puede llevar datos del cliente).
- ``trace_id`` = uuid4 por petición, también en la cabecera ``X-Trace-Id``. Es lo único que
  relaciona la respuesta con el log interno.

Nunca salen en el cuerpo trazas, rutas de archivos, SQL, motivos internos de rechazo de un token
ni valores enviados por el cliente (OWASP ASVS V7.4.1). Eso va solo al log, con el ``trace_id``.
"""

import logging
import uuid
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("portero.api")

PROBLEM_TYPE_BASE = "https://portero-cloud.example/errors/"
PROBLEM_MEDIA_TYPE = "application/problem+json"
TRACE_HEADER = "X-Trace-Id"

SECURITY_HEADERS: Mapping[str, str] = {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}
"""Cabeceras de seguridad de toda respuesta (Cap. 6 §Cabeceras de seguridad; spec Fase 5 §7;
OWASP ASVS V14.4). Las agrega ``SecurityHeadersMiddleware``; el 500 las lleva directamente
porque Starlette lo envía desde ``ServerErrorMiddleware``, por fuera de los middlewares."""

TITLES: Mapping[str, str] = {
    "validation-error": "Solicitud inválida",
    "authentication-failed": "No autenticado",
    "permission-denied": "Acceso denegado",
    "resource-not-found": "Recurso no encontrado",
    "conflict": "Conflicto",
    "payload-too-large": "Solicitud demasiado grande",
    "semantic-error": "Entrada no procesable",
    "rate-limit-exceeded": "Demasiadas solicitudes",
    "internal-error": "Error interno",
}
"""Tabla de tipos de la spec Fase 5 §6 (``<tipo>`` → ``title`` en español)."""

_TYPE_OF_STATUS: Mapping[int, str] = {
    400: "validation-error",
    401: "authentication-failed",
    403: "permission-denied",
    404: "resource-not-found",
    409: "conflict",
    413: "payload-too-large",
    422: "semantic-error",
    429: "rate-limit-exceeded",
    500: "internal-error",
}

_DEFAULT_DETAIL: Mapping[str, str] = {
    "validation-error": "La solicitud no cumple el formato esperado.",
    "authentication-failed": "No autenticado.",
    "permission-denied": "No tienes permiso para esta operación.",
    "resource-not-found": "El recurso no existe.",
    "conflict": "La operación entra en conflicto con el estado actual.",
    "payload-too-large": "El cuerpo de la solicitud es demasiado grande.",
    "semantic-error": "La solicitud no se puede procesar.",
    "rate-limit-exceeded": "Demasiadas solicitudes; intenta más tarde.",
    "internal-error": "Ocurrió un error interno. Reporta el trace_id si el problema persiste.",
}


class ProblemDetails(BaseModel):
    """Esquema de un error en el OpenAPI (RFC 9457 §3). Solo documenta: las respuestas las
    construye ``problem_response``."""

    type: str
    title: str
    status: int
    detail: str
    instance: str
    trace_id: str


_RESPONSE_DESCRIPTIONS: Mapping[int, str] = {
    400: "Solicitud inválida: esquema, campos extra, UUID no canónico o parámetros.",
    401: "No autenticado: token ausente, inválido, expirado o revocado.",
    403: "Acceso denegado: el recurso es visible pero falta el permiso.",
    404: "Recurso no encontrado: inexistente, archivado o no visible para el actor.",
    409: "Conflicto con el estado actual.",
    413: "El cuerpo excede 1 MiB.",
    422: "Entrada no procesable: viola una regla de negocio.",
    429: "Demasiadas solicitudes; la cabecera `Retry-After` indica los segundos de espera.",
    500: "Error interno; el `trace_id` relaciona la respuesta con el log.",
}


def problem_responses(*statuses: int) -> dict[int | str, dict[str, Any]]:
    """Entradas ``responses`` del OpenAPI para los errores que puede dar una ruta, todas con
    ``application/problem+json`` y el esquema ``ProblemDetails`` (Cap. 6 §Manejo de errores)."""
    return {
        status: {
            "description": _RESPONSE_DESCRIPTIONS[status],
            "content": {PROBLEM_MEDIA_TYPE: {"schema": ProblemDetails.model_json_schema()}},
        }
        for status in statuses
    }


class ApiProblem(Exception):
    """Error de dominio que el API REST Gateway traduce a Problem Details.

    ``kind`` es un ``<tipo>`` de ``TITLES``; ``detail`` debe ser un texto amigable en español sin
    datos internos. ``headers`` permite, p. ej., ``WWW-Authenticate`` (RFC 6750).
    """

    def __init__(
        self,
        status: int,
        kind: str,
        detail: str | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if kind not in TITLES:
            raise ValueError(f"tipo de problema desconocido: {kind}")
        super().__init__(kind)
        self.status = status
        self.kind = kind
        self.detail = detail or _DEFAULT_DETAIL[kind]
        self.headers = dict(headers or {})


def get_trace_id(request: Request) -> str:
    """``trace_id`` de la petición; lo fija ``TraceIdMiddleware`` y, si no pasó por ahí (p. ej.
    un 500 atrapado fuera del middleware), se genera aquí y se guarda en el ``scope``."""
    state = request.scope.setdefault("state", {})
    if "trace_id" not in state:
        state["trace_id"] = str(uuid.uuid4())
    return str(state["trace_id"])


def problem_response(
    request: Request,
    status: int,
    kind: str | None,
    detail: str | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    extra: Mapping[str, Any] | None = None,
) -> JSONResponse:
    """Construye la respuesta ``application/problem+json`` (RFC 9457 §3).

    Con ``kind=None`` y un estado fuera de la tabla (p. ej. 405) se usa ``about:blank`` con
    el título genérico, como permite RFC 9457 §4.2.1.
    """
    trace_id = get_trace_id(request)
    if kind is None:
        body: dict[str, Any] = {"type": "about:blank", "title": "Error", "status": status}
        body["detail"] = detail or "La solicitud no se pudo procesar."
    else:
        body = {
            "type": PROBLEM_TYPE_BASE + kind,
            "title": TITLES[kind],
            "status": status,
            "detail": detail or _DEFAULT_DETAIL[kind],
        }
    body["instance"] = request.url.path
    body["trace_id"] = trace_id
    if extra:
        body.update(extra)
    return JSONResponse(
        body,
        status_code=status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers={**(headers or {}), TRACE_HEADER: trace_id},
    )


# --- Manejadores ---------------------------------------------------------------------------------


async def _api_problem(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, ApiProblem):  # lo garantiza el registro; se revisa para mypy
        raise exc
    return problem_response(request, exc.status, exc.kind, exc.detail, headers=exc.headers)


async def _validation(request: Request, exc: Exception) -> JSONResponse:
    """Errores de esquema → 400 ``validation-error`` en lugar del 422 de FastAPI (spec §1).

    Solo se devuelven ``loc`` y ``type`` de cada error: Pydantic incluye ``input`` (el valor
    enviado) y ``ctx``, que podrían contener una contraseña o el valor de un secreto (spec §6).
    """
    if not isinstance(exc, RequestValidationError):
        raise exc
    errors = [{"loc": list(e.get("loc", ())), "type": e.get("type")} for e in exc.errors()]
    return problem_response(request, 400, "validation-error", extra={"errors": errors})


async def _http_exception(request: Request, exc: Exception) -> JSONResponse:
    """``HTTPException`` de Starlette o FastAPI (p. ej. 404 de ruta inexistente, 405)."""
    if not isinstance(exc, StarletteHTTPException):
        raise exc
    kind = _TYPE_OF_STATUS.get(exc.status_code)
    # El detail de una HTTPException puede venir de una librería: solo se usa el genérico.
    return problem_response(request, exc.status_code, kind, headers=exc.headers)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Cualquier excepción no prevista → 500 ``internal-error``. La traza va solo al log, con el
    ``trace_id``; el cliente recibe un mensaje genérico (OWASP ASVS V7.4.1)."""
    trace_id = get_trace_id(request)
    logger.error(
        "excepción no controlada",
        extra={"trace_id": trace_id, "path": request.url.path},
        exc_info=exc,
    )
    return problem_response(request, 500, "internal-error", headers=SECURITY_HEADERS)


def register_error_handlers(app: FastAPI) -> None:
    """Registra los manejadores de Problem Details. ``TraceIdMiddleware`` lo agrega
    ``create_app`` como el middleware más externo (``api/middleware.py``)."""
    app.add_exception_handler(ApiProblem, _api_problem)
    app.add_exception_handler(RequestValidationError, _validation)
    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(Exception, _unhandled)


class TraceIdMiddleware:
    """Middleware ASGI que asigna un ``trace_id`` (uuid4) a cada petición y lo devuelve en
    ``X-Trace-Id`` en toda respuesta, también en las exitosas (spec Fase 5 §6).

    Es ASGI puro (no ``BaseHTTPMiddleware``) para no alterar el flujo de excepciones hacia el
    manejador del 500.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = scope.setdefault("state", {})
        trace_id = state.setdefault("trace_id", str(uuid.uuid4()))

        async def send_with_trace(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                name = TRACE_HEADER.lower().encode("latin-1")
                if not any(k.lower() == name for k, _ in headers):
                    headers.append((name, trace_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_trace)
