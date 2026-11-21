"""Limitador de tasa del API REST Gateway: ventana deslizante en memoria del proceso (Cap. 6
§Rate limiting y controles transversales, tabla "Límites de tasa aplicados por el API Gateway";
spec Fase 5 §7; OWASP API Security Top 10 API4: Unrestricted Resource Consumption).

**Ventana deslizante con registro de marcas.** Por cada clave (IP o actor) se guardan las marcas
de tiempo de las peticiones aceptadas en los últimos ``WINDOW_SECONDS``. Una petición entra si
hay menos de ``limit`` marcas vigentes. A diferencia de una ventana fija (contador que se reinicia
cada minuto), no permite ráfagas de ``2 × limit`` en el cambio de minuto: en **cualquier**
intervalo de 60 s entran como mucho ``limit`` peticiones. Las peticiones rechazadas no dejan marca:
insistir mientras se está bloqueado no alarga el bloqueo.

Decisiones:

- Contadores en memoria del proceso, como dice el Cap. 6 para TT2. Con varias réplicas haría
  falta una caché compartida (p. ej. Redis), fuera del alcance del monolito.
- El reloj es inyectable (``time.monotonic`` por omisión: no salta con cambios de hora), para
  probar la ventana sin esperar.
- ``hit`` no tiene ``await``: en el ciclo de eventos de asyncio se ejecuta completo sin
  interrupciones, así que no necesita lock.
- Cuatro categorías con contadores **independientes**: agotar las operaciones generales no impide
  leer valores, y viceversa.
"""

import math
import re
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from portero.api.errors import ApiProblem

Clock = Callable[[], float]

WINDOW_SECONDS: Final = 60
"""Ancho de la ventana: los límites del Cap. 6 son "por minuto"."""

_SWEEP_EVERY: Final = 1_000
"""Cada cuántas peticiones se eliminan las claves sin marcas vigentes, para que la memoria no
crezca con cada IP o actor que pasó alguna vez (OWASP API4)."""


class Category(StrEnum):
    """Categorías de la tabla del Cap. 6."""

    AUTH = "auth"
    """``POST /auth/login`` y ``POST /auth/refresh``; clave = IP."""
    SECRET_VALUE = "secret_value"  # noqa: S105  # nombre de categoría, no una contraseña
    """``GET /secrets/{id}/value``; clave = actor."""
    GENERAL = "general"
    """Resto de endpoints autenticados; clave = actor."""
    HEALTH = "health"
    """``/health`` y ``/health/ready``; clave = IP."""


LIMITS: Mapping[Category, int] = MappingProxyType(
    {
        Category.AUTH: 10,
        Category.SECRET_VALUE: 60,
        Category.GENERAL: 100,
        Category.HEALTH: 600,
    }
)
"""Peticiones por minuto de cada categoría (Cap. 6, tabla de límites de tasa)."""

IP_CATEGORIES: Final = frozenset({Category.AUTH, Category.HEALTH})
"""Categorías cuya clave es la IP (``request.client.host``); las demás usan el actor."""


@dataclass(frozen=True)
class RateDecision:
    """Resultado de ``SlidingWindow.hit``. ``retry_after`` (segundos, ≥ 1) solo tiene sentido si
    ``allowed`` es falso; es el valor de la cabecera ``Retry-After`` (RFC 9110 §10.2.3)."""

    allowed: bool
    retry_after: int = 0


class SlidingWindow:
    """Ventana deslizante de ``limit`` peticiones en ``window_seconds`` por clave."""

    def __init__(
        self, limit: int, window_seconds: float = WINDOW_SECONDS, clock: Clock = time.monotonic
    ) -> None:
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._calls = 0

    def hit(self, key: str) -> RateDecision:
        """Intenta registrar una petición de ``key``.

        1. Descarta las marcas que ya salieron de la ventana (``ahora - marca ≥ ventana``).
        2. Si quedan menos de ``limit``, guarda la marca actual y permite.
        3. Si no, niega sin guardar nada. ``retry_after`` = segundos hasta que venza la marca
           más antigua, redondeado hacia arriba (nunca 0: el cliente volvería a chocar).
        """
        now = self._clock()
        self._maybe_sweep(now)
        marks = self._hits.setdefault(key, deque())
        while marks and now - marks[0] >= self._window:
            marks.popleft()
        if len(marks) < self._limit:
            marks.append(now)
            return RateDecision(allowed=True)
        wait = marks[0] + self._window - now
        return RateDecision(allowed=False, retry_after=max(1, math.ceil(wait)))

    def _maybe_sweep(self, now: float) -> None:
        self._calls += 1
        if self._calls % _SWEEP_EVERY:
            return
        expired = [k for k, m in self._hits.items() if not m or now - m[-1] >= self._window]
        for key in expired:
            del self._hits[key]


class RateLimiter:
    """Una ``SlidingWindow`` por categoría, con los límites de ``LIMITS``. Vive en
    ``app.state.rate_limiter`` (una por proceso).

    ``auth_limit`` sustituye solo el límite de la categoría AUTH (H-56): en el stack E2E todas las
    peticiones llegan desde la IP del gateway de Docker y el cupo de 10 por minuto se agotaría.
    Por omisión es el del Cap. 6; las demás categorías no son configurables."""

    def __init__(
        self, clock: Clock = time.monotonic, auth_limit: int = LIMITS[Category.AUTH]
    ) -> None:
        if auth_limit <= 0:
            raise ValueError("auth_limit debe ser positivo")
        limits = {**LIMITS, Category.AUTH: auth_limit}
        self._windows = {
            category: SlidingWindow(limit, WINDOW_SECONDS, clock)
            for category, limit in limits.items()
        }

    def enforce(self, category: Category, key: str) -> None:
        """Cuenta la petición; si excede el límite, 429 ``rate-limit-exceeded`` con
        ``Retry-After`` (Cap. 6; spec §6). El 429 no se registra en la bitácora (spec §5.2)."""
        decision = self._windows[category].hit(key)
        if not decision.allowed:
            raise ApiProblem(
                429,
                "rate-limit-exceeded",
                headers={"Retry-After": str(decision.retry_after)},
            )


_PREFIX = "/api/v1"
_AUTH_PATHS: Final = frozenset({f"{_PREFIX}/auth/login", f"{_PREFIX}/auth/refresh"})
_HEALTH_PATHS: Final = frozenset({f"{_PREFIX}/health", f"{_PREFIX}/health/ready"})
_SECRET_VALUE = re.compile(rf"^{_PREFIX}/secrets/[^/]+/value$")


def classify(method: str, path: str) -> Category:
    """Categoría de la petición según la tabla del Cap. 6. Lo que no es autenticación, salud ni
    lectura de valor es "operaciones generales"."""
    if method == "POST" and path in _AUTH_PATHS:
        return Category.AUTH
    if path in _HEALTH_PATHS:
        return Category.HEALTH
    if method == "GET" and _SECRET_VALUE.match(path):
        return Category.SECRET_VALUE
    return Category.GENERAL
