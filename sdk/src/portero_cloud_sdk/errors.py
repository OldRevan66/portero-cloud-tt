"""Jerarquía de excepciones del SDK (Cap. 6 §API pública del SDK, "Excepciones tipadas").

La aplicación consumidora puede capturar todas (``except PorteroError``) o solo una
(``except SecretNotFound``). ``RateLimited`` es una precisión al Cap. 6: la API responde 429 con
``Retry-After`` (spec Fase 5 §7) y la aplicación debe poder distinguirlo.

Los mensajes son fijos y en español. Nunca incluyen el token, el cuerpo de la respuesta ni el
valor de un secreto (OWASP ASVS V7.1.1 y V8.3): una excepción suele terminar en un log.
"""

from __future__ import annotations


class PorteroError(Exception):
    """Base de todas las excepciones del SDK.

    ``status_code`` es el código HTTP (``None`` si no hubo respuesta) y ``trace_id`` el
    ``X-Trace-Id`` de la respuesta, que el operador usa para buscar la petición en los logs del
    backend (spec Fase 5 §6). Ninguno de los dos es secreto.
    """

    def __init__(
        self, message: str, *, status_code: int | None = None, trace_id: str | None = None
    ) -> None:
        if status_code is not None:
            message = f"{message} (HTTP {status_code})"
        if trace_id is not None:
            message = f"{message} [trace_id={trace_id}]"
        super().__init__(message)
        self.status_code = status_code
        self.trace_id = trace_id


class AuthenticationError(PorteroError):
    """401: el token falta, expiró, está mal firmado o la Aplicación Cliente fue revocada."""


class PermissionDenied(PorteroError):
    """403: el token es válido, pero su alcance no cubre la operación (spec Fase 5 §4.1)."""


class SecretNotFound(PorteroError):
    """404, o un proyecto, ambiente o secreto que no aparece en lo que el token puede ver.

    "No existe" y "fuera del alcance del token" son indistinguibles a propósito (H-14)."""


class RateLimited(PorteroError):
    """429: se excedió el límite de tasa (spec Fase 5 §7). ``retry_after`` son los segundos
    que pide esperar el servidor, o ``None`` si no los indicó. El SDK no reintenta solo."""

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        status_code: int | None = None,
        trace_id: str | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, trace_id=trace_id)
        self.retry_after = retry_after


class NetworkError(PorteroError):
    """No hubo respuesta: conexión rechazada, DNS, TLS o tiempo de espera agotado."""


class ServerError(PorteroError):
    """5xx: error del backend. La aplicación decide si arranca sin el secreto (típicamente, no)."""
