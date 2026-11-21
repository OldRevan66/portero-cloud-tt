"""Lógica compartida por ``PorteroClient`` y ``PorteroAsyncClient``, sin entrada/salida.

Cap. 6 §Modelos de uso síncrono y asíncrono: "una sola base de código compartida entre ambas
clases". Aquí está todo lo que no depende de cómo se envía la petición: validar el token y la
URL, armar cabeceras y rutas, traducir respuestas a excepciones, parsear con Pydantic y la memoria
de identificadores. Las clases solo envían peticiones y llaman a estas funciones, así que esta
lógica se escribe y se prueba una vez.

Dos reglas de seguridad atraviesan el módulo (OWASP ASVS V7.1.1 y V8.3):
- Las excepciones del SDK se lanzan **fuera** del bloque ``except`` que atrapó la original, para
  que ni ``__cause__`` ni ``__context__`` la conserven: la de httpx guarda el ``Request`` con la
  cabecera ``Authorization`` y el ``ValidationError`` de Pydantic guarda la entrada (que puede ser
  el valor de un secreto).
- Ningún mensaje lleva el token, el cuerpo de la respuesta ni el valor.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TypeVar
from uuid import UUID

import httpx
from pydantic import TypeAdapter, ValidationError

from portero_cloud_sdk.errors import (
    AuthenticationError,
    NetworkError,
    PermissionDenied,
    PorteroError,
    RateLimited,
    SecretNotFound,
    ServerError,
)
from portero_cloud_sdk.models import Secret

T = TypeVar("T")

API_PREFIX = "/api/v1"
DEFAULT_TIMEOUT = 10.0
"""Segundos; el del Listado del uso básico del Cap. 6."""

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

PROJECTS_PATH = "/projects"
HEALTH_PATH = "/health/ready"


# --- Construcción --------------------------------------------------------------------------------


def validate_token(token: str) -> str:
    """Rechaza un PAT vacío o con espacios en blanco (Cap. 6 §Manejo de credenciales).

    Un salto de línea en la cabecera ``Authorization`` sería inyección de cabeceras y un espacio
    delata un token mal copiado: se falla al construir (*fail fast*). El mensaje no repite el
    token."""
    if not isinstance(token, str) or not token or any(c.isspace() for c in token):
        raise ValueError("el token está vacío o contiene espacios en blanco")
    return token


def validate_timeout(timeout: float) -> float:
    """El tiempo de espera debe ser positivo: sin él, una red caída colgaría la aplicación."""
    if not timeout > 0:
        raise ValueError("timeout debe ser un número de segundos mayor que cero")
    return float(timeout)


def api_base_url(base_url: str, *, allow_insecure_http: bool) -> str:
    """URL base de la API a partir de la raíz del servidor (``https://host[:puerto]``).

    Hallazgo H-55: el PAT es un Bearer de larga vida (puede no tener ``exp``, H-09); por
    ``http`` a otro host viajaría en claro. Se exige ``https`` salvo en loopback (desarrollo
    local) o con ``allow_insecure_http=True``, una decisión explícita para una red interna con
    TLS terminado en el borde (OWASP ASVS V9.1.1).

    Hallazgo H-66: tampoco se aceptan credenciales (``usuario:clave@``), consulta ni fragmento.
    Las credenciales quedarían en el ``repr`` del cliente y de ahí en cualquier log (OWASP ASVS
    V7.1.1); la consulta y el fragmento romperían las rutas. El mensaje no repite la URL."""
    try:
        url = httpx.URL(base_url)
    except httpx.InvalidURL:
        raise ValueError("base_url no es una URL válida") from None
    if url.scheme not in ("http", "https") or not url.host:
        raise ValueError(
            "base_url debe ser una URL http(s) con host, p. ej. https://portero.example"
        )
    if url.userinfo or url.query or url.fragment or "?" in base_url or "#" in base_url:
        raise ValueError("base_url no debe llevar usuario, contraseña, consulta ni fragmento")
    if url.scheme == "http" and url.host not in _LOOPBACK_HOSTS and not allow_insecure_http:
        raise ValueError(
            "base_url debe usar https fuera de localhost: el token viajaría en claro "
            "(use allow_insecure_http=True solo en una red interna con TLS en el borde)"
        )
    return base_url.rstrip("/") + API_PREFIX


def default_headers(token: str, version: str) -> dict[str, str]:
    """Cabeceras de toda petición: el PAT como Bearer (RFC 6750) y el ``User-Agent`` del SDK."""
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": f"portero-cloud-sdk/{version}",
        "Accept": "application/json",
    }


# --- Rutas (spec Fase 5 §2) ----------------------------------------------------------------------


def environments_path(project_id: UUID) -> str:
    return f"/projects/{project_id}/environments"


def secrets_path(project_id: UUID, environment_id: UUID) -> str:
    return f"/projects/{project_id}/environments/{environment_id}/secrets"


def secret_path(secret_id: UUID) -> str:
    return f"/secrets/{secret_id}"


def secret_value_path(secret_id: UUID) -> str:
    return f"/secrets/{secret_id}/value"


# --- Respuestas → excepciones --------------------------------------------------------------------


def network_error(exc: httpx.TransportError) -> NetworkError:
    """``NetworkError`` con solo el tipo de la falla (``ConnectError``, ``ReadTimeout``…).

    El llamador la lanza fuera de su ``except`` (ver el docstring del módulo)."""
    return NetworkError(f"no se pudo comunicar con Portero Cloud ({type(exc).__name__})")


def _retry_after(response: httpx.Response) -> float | None:
    """Segundos de ``Retry-After`` (spec Fase 5 §7). La API solo envía enteros; una fecha HTTP
    u otro formato se ignora.

    Hallazgo H-67: ``str.isdigit()`` solo no basta, porque acepta "²" y luego ``float("²")``
    lanza ``ValueError``. Por eso se exigen dígitos ASCII."""
    value = response.headers.get("Retry-After", "").strip()
    return float(value) if value.isascii() and value.isdigit() else None


def raise_for_status(response: httpx.Response) -> None:
    """Traduce una respuesta que no es 2xx a la excepción tipada del Cap. 6.

    No lee el cuerpo (Problem Details): su ``detail`` es para humanos y no debe terminar en los
    logs de la aplicación consumidora."""
    status = response.status_code
    if 200 <= status < 300:
        return
    trace_id = response.headers.get("X-Trace-Id")
    if status == 401:
        raise AuthenticationError(
            "token inválido, expirado o revocado", status_code=status, trace_id=trace_id
        )
    if status == 403:
        raise PermissionDenied(
            "el token no tiene permiso para esta operación", status_code=status, trace_id=trace_id
        )
    if status == 404:
        raise SecretNotFound(
            "secreto no encontrado o fuera del alcance del token",
            status_code=status,
            trace_id=trace_id,
        )
    if status == 429:
        raise RateLimited(
            "demasiadas solicitudes a Portero Cloud",
            retry_after=_retry_after(response),
            status_code=status,
            trace_id=trace_id,
        )
    if status >= 500:
        raise ServerError(
            "error del servidor de Portero Cloud", status_code=status, trace_id=trace_id
        )
    raise PorteroError("Portero Cloud rechazó la solicitud", status_code=status, trace_id=trace_id)


# --- Parseo (Pydantic sobre dataclasses, Cap. 6 "serialización JSON automática") ---------------


@dataclass(frozen=True, slots=True)
class _Named:
    """Lo que la resolución necesita de un proyecto o un ambiente."""

    id: UUID
    name: str


@dataclass(frozen=True, slots=True)
class _SecretValue:
    """Cuerpo completo de ``GET /secrets/{id}/value`` (spec Fase 5 §2: ``{id, name, value,
    version}``); se valida entero para no aceptar una respuesta incoherente.
    ``repr=False``: el valor nunca sale en un repr."""

    id: UUID
    name: str
    value: str = field(repr=False)
    version: int


_NAMED_LIST = TypeAdapter(list[_Named])
_SECRET = TypeAdapter(Secret)
_SECRET_LIST = TypeAdapter(list[Secret])
_SECRET_VALUE = TypeAdapter(_SecretValue)


def _parse(adapter: TypeAdapter[T], response: httpx.Response) -> T:
    """Valida el JSON de ``response``. Los campos extra se ignoran (si la API agrega campos, el
    SDK no se rompe); un JSON inválido o un esquema distinto es ``PorteroError``."""
    try:
        return adapter.validate_json(response.content)
    except ValidationError:
        pass  # se lanza afuera: el ValidationError contiene la entrada
    raise PorteroError(
        "respuesta inesperada de Portero Cloud",
        status_code=response.status_code,
        trace_id=response.headers.get("X-Trace-Id"),
    )


def parse_named_list(response: httpx.Response) -> list[_Named]:
    return _parse(_NAMED_LIST, response)


def parse_secret(response: httpx.Response) -> Secret:
    return _parse(_SECRET, response)


def parse_secret_list(response: httpx.Response) -> tuple[Secret, ...]:
    secrets: list[Secret] = _parse(_SECRET_LIST, response)
    return tuple(secrets)


def parse_secret_value(response: httpx.Response) -> str:
    return _parse(_SECRET_VALUE, response).value


# --- Resolución por nombres (hallazgo H-54) -----------------------------------------------------


def not_found() -> SecretNotFound:
    """El nombre no aparece en lo que el token puede ver. Mismo mensaje que un 404 (H-14)."""
    return SecretNotFound("secreto no encontrado o fuera del alcance del token")


class IdCache:
    """Memoria de **identificadores** por nombre; nunca valores (Cap. 6 "Falla de manera
    segura": el SDK no cachea secretos).

    Tres niveles: proyecto → id, (proyecto, ambiente) → id, (ambiente, secreto) → id. Cada
    lista que llega de la API se guarda completa, así que pedir otro secreto del mismo ambiente
    no repite la resolución. Un id puede quedar obsoleto (secreto archivado y recreado con el
    mismo nombre); los clientes vacían la memoria ante un 404 de la API y resuelven una vez más.

    Con hilos, dos resoluciones simultáneas solo duplican peticiones: cada escritura de ``dict``
    es atómica en CPython y todas escriben los mismos ids."""

    def __init__(self) -> None:
        self._projects: dict[str, UUID] = {}
        self._environments: dict[tuple[UUID, str], UUID] = {}
        self._secrets: dict[tuple[UUID, str], UUID] = {}

    def is_empty(self) -> bool:
        return not (self._projects or self._environments or self._secrets)

    def clear(self) -> None:
        self._projects.clear()
        self._environments.clear()
        self._secrets.clear()

    def project(self, name: str) -> UUID | None:
        return self._projects.get(name)

    def store_projects(self, items: Iterable[_Named]) -> None:
        self._projects.update((item.name, item.id) for item in items)

    def environment(self, project_id: UUID, name: str) -> UUID | None:
        return self._environments.get((project_id, name))

    def store_environments(self, project_id: UUID, items: Iterable[_Named]) -> None:
        self._environments.update(((project_id, item.name), item.id) for item in items)

    def secret(self, environment_id: UUID, name: str) -> UUID | None:
        return self._secrets.get((environment_id, name))

    def store_secrets(self, environment_id: UUID, items: Iterable[Secret]) -> None:
        self._secrets.update(((environment_id, item.name), item.id) for item in items)


def is_stale_id_error(exc: SecretNotFound, cache_was_empty: bool) -> bool:
    """¿Vale la pena vaciar la memoria y resolver otra vez?

    Solo si la **API** respondió 404 (``status_code``) a una llamada que usó ids memorizados.
    Un nombre ausente de una lista recién pedida (``status_code is None``) no se reintenta."""
    return exc.status_code == 404 and not cache_was_empty
