"""Middlewares transversales del API REST Gateway (Cap. 6 §Rate limiting y controles
transversales; spec Fase 5 §7; OWASP API Security API4, OWASP ASVS V13 y V14.4).

Todos son ASGI puros (no ``BaseHTTPMiddleware``) para no alterar el flujo de excepciones hacia el
manejador del 500 ni bufferizar las respuestas. Orden en ``create_app``, de afuera hacia adentro:

1. ``TraceIdMiddleware`` (``api/errors.py``): fija el ``trace_id`` que usan todos los demás.
2. ``SecurityHeadersMiddleware``: cabeceras en toda respuesta, también en 413 y 429.
3. ``AccessLogMiddleware``: una línea JSON por petición, incluidas las rechazadas por tamaño.
4. ``BodySizeLimitMiddleware``: corta los cuerpos de más de 1 MiB antes de deserializar.
5. ``CORSMiddleware`` (Starlette) y la aplicación.
"""

import json
import logging
import sys
import time
from collections.abc import Mapping
from typing import Any, Final

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from portero.api.errors import SECURITY_HEADERS, problem_response

MAX_BODY_BYTES: Final = 1024 * 1024
"""1 MiB (Cap. 6 §Validación de tamaño de cuerpo): tres órdenes de magnitud por encima del
secreto más grande razonable y por debajo de lo que permitiría agotar la memoria."""

ACCESS_LOGGER: Final = "portero.access"


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return str(value.decode("latin-1"))
    return None


# --- Tamaño del cuerpo ---------------------------------------------------------------------------


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Rechaza con 413 ``payload-too-large`` todo cuerpo de más de ``max_bytes`` **antes** de que
    FastAPI lo deserialice (Cap. 6; OWASP API Security API4).

    1. Si ``Content-Length`` ya excede el límite, responde sin leer el cuerpo.
    2. Si no (o si viene por chunks, sin ``Content-Length``), lee el cuerpo contando bytes y
       corta en cuanto pasa del límite; nunca guarda más de ``max_bytes`` + un chunk.
    3. Si cabe, se lo entrega a la aplicación como un solo mensaje ``http.request``.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _header(scope, b"content-length")
        if declared is not None and declared.isdecimal() and int(declared) > self.max_bytes:
            await self._reject(scope, receive, send)
            return
        try:
            body = await self._read_body(receive)
        except _BodyTooLargeError:
            await self._reject(scope, receive, send)
            return
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # p. ej. ``http.disconnect``

        await self.app(scope, replay, send)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":  # el cliente se desconectó
                return b"".join(chunks)
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                raise _BodyTooLargeError
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        response = problem_response(Request(scope), 413, "payload-too-large")
        await response(scope, receive, send)


# --- Cabeceras de seguridad ----------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """Agrega ``SECURITY_HEADERS`` a toda respuesta (Cap. 6 §Cabeceras de seguridad; spec §7;
    OWASP ASVS V14.4.1 a V14.4.7):

    - ``Strict-Transport-Security: max-age=31536000``: el navegador solo usará HTTPS (V14.4.5).
    - ``X-Content-Type-Options: nosniff``: no reinterpreta un JSON como HTML o script (V14.4.4).
    - ``X-Frame-Options: DENY``: ninguna respuesta se muestra en un ``<iframe>`` (V14.4.7).
    - ``Cache-Control: no-store`` en **todas** las respuestas, no solo en ``/value``: así no hay
      que decidir cuáles contienen secretos (V8.2.1). Reemplaza cualquier otro valor.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._headers = [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in SECURITY_HEADERS.items()
        ]
        self._names = {name for name, _ in self._headers}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                kept = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() not in self._names
                ]
                message["headers"] = kept + self._headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


# --- Log de acceso estructurado ------------------------------------------------------------------


class _CurrentStderrHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """``StreamHandler`` que escribe en el ``sys.stderr`` vigente en cada registro, no en el que
    había al configurarlo (pytest y algunos servidores lo reemplazan)."""

    def emit(self, record: logging.LogRecord) -> None:
        # Asignación directa: ``setStream`` vaciaría antes el stream anterior, que puede estar
        # cerrado (p. ej., la captura de una prueba que ya terminó).
        self.stream = sys.stderr
        super().emit(record)


class _JsonFormatter(logging.Formatter):
    """Una línea JSON por registro (OWASP ASVS V7.1; H-70). La de ``portero.access`` ya viene
    armada por ``access_entry`` y sale tal cual; las demás llevan ``level``, ``logger``,
    ``message``, ``trace_id`` y ``path`` si se pasaron en ``extra``, y la traza en ``exc_info``
    (una sola línea: JSON escapa los saltos)."""

    def format(self, record: logging.LogRecord) -> str:
        if record.name == ACCESS_LOGGER:
            return record.getMessage()
        entry: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for campo in ("trace_id", "path"):
            if hasattr(record, campo):
                entry[campo] = getattr(record, campo)
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def _json_handler() -> logging.Handler:
    handler = _CurrentStderrHandler()
    handler.setFormatter(_JsonFormatter())
    return handler


def configure_logging(level: str) -> None:
    """Todo lo que el proceso escribe en stderr es JSON (OWASP ASVS V7.1; H-70). Idempotente.

    - ``portero``: nivel de ``PORTERO_LOG_LEVEL``; ``portero.access`` y ``portero.api`` lo
      heredan. Sigue propagando, por si el despliegue agrega sus propios manejadores.
    - ``uvicorn`` (arranque y la traza de un 500 que Starlette vuelve a lanzar): mismo formato,
      en lugar del texto plano de uvicorn. Su nivel sigue siendo el de ``--log-level``.
    - ``uvicorn.access``: apagado. Duplicaba cada petición en texto plano y con la query
      string; la registra ``AccessLogMiddleware``.

    Uvicorn configura sus loggers antes de llamar a ``create_app`` (``--factory``), así que lo
    de aquí prevalece."""
    portero = logging.getLogger("portero")
    portero.setLevel(level)
    if not any(isinstance(h, _CurrentStderrHandler) for h in portero.handlers):
        portero.addHandler(_json_handler())
    logging.getLogger("uvicorn").handlers = [_json_handler()]
    acceso_uvicorn = logging.getLogger("uvicorn.access")
    acceso_uvicorn.handlers = []
    acceso_uvicorn.propagate = False


def access_entry(scope: Scope, status_code: int, latency_ms: float) -> Mapping[str, Any]:
    """Campos del Cap. 6 §Logging estructurado: ``trace_id, actor_id, verb, path, status_code,
    latency_ms, user_agent``.

    Lo que **no** se registra (spec §7; RNF-006; OWASP ASVS V7.1.1): cuerpos, query string (va
    solo ``scope["path"]``), ni las cabeceras ``Authorization`` y ``Cookie``. ``actor_id`` lo
    fija la dependencia de autenticación tras validar el token; ``None`` si no hubo actor."""
    state = scope.get("state", {})
    actor_id = state.get("actor_id")
    return {
        "trace_id": state.get("trace_id"),
        "actor_id": None if actor_id is None else str(actor_id),
        "verb": scope.get("method"),
        "path": scope.get("path"),
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
        "user_agent": _header(scope, b"user-agent"),
    }


class AccessLogMiddleware:
    """Una línea JSON por petición en ``portero.access`` (Cap. 6 §Logging estructurado; OWASP
    ASVS V7.1). Si la aplicación lanza una excepción no controlada, se registra como 500 y la
    excepción sigue su curso hacia el manejador del 500."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._logger = logging.getLogger(ACCESS_LOGGER)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status_code = 500

        async def send_capturing_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_capturing_status)
        finally:
            latency_ms = (time.perf_counter() - start) * 1000
            entry = access_entry(scope, status_code, latency_ms)
            self._logger.info(json.dumps(entry, ensure_ascii=False))
