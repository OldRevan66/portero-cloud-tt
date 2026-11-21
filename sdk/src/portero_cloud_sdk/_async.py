"""``PorteroAsyncClient``: cliente asíncrono del SDK (Cap. 6 §Modelos de uso síncrono y
asíncrono).

Capa delgada sobre ``httpx.AsyncClient`` con la misma firma que ``PorteroClient`` (los métodos
son corutinas). Repite, con ``await``, el mismo orden de pasos que la clase síncrona; todo lo
demás (validación, rutas, errores, parseo y memoria de ids) está en ``_core``. Solo lectura con
un PAT (privilegio mínimo; OWASP ASVS V2.10).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import TypeVar
from uuid import UUID

import httpx

from portero_cloud_sdk import _core
from portero_cloud_sdk._version import __version__
from portero_cloud_sdk.errors import NetworkError, SecretNotFound
from portero_cloud_sdk.models import Secret

T = TypeVar("T")


class PorteroAsyncClient:
    """Cliente asíncrono. Mismos parámetros y excepciones que ``PorteroClient``;
    ``async with PorteroAsyncClient(...) as client:`` cierra las conexiones al salir del
    *scope*, incluso ante excepciones (Cap. 6, Listado del uso asíncrono)."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = _core.DEFAULT_TIMEOUT,
        allow_insecure_http: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = _core.api_base_url(base_url, allow_insecure_http=allow_insecure_http)
        # El token solo vive en las cabeceras del cliente httpx, cuyo repr las oculta.
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers=_core.default_headers(_core.validate_token(token), __version__),
            timeout=_core.validate_timeout(timeout),
            transport=transport,
        )
        self._cache = _core.IdCache()

    def __repr__(self) -> str:
        return f"PorteroAsyncClient(base_url={self._base_url!r})"

    # --- Ciclo de vida ---------------------------------------------------------------------------

    async def close(self) -> None:
        """Libera el cliente HTTP subyacente. Llamarlo dos veces no tiene efecto."""
        await self._http.aclose()

    async def __aenter__(self) -> PorteroAsyncClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    # --- API pública (misma firma que PorteroClient) ---------------------------------------------

    async def get_secret_value(self, project: str, environment: str, name: str) -> str:
        """Valor en claro del secreto; se pide a la API en cada llamada (sin caché de valores).
        Ver ``PorteroClient.get_secret_value``."""

        async def read(secret_id: UUID) -> str:
            response = await self._get(_core.secret_value_path(secret_id))
            return _core.parse_secret_value(response)

        return await self._with_secret(project, environment, name, read)

    async def get_secret(self, project: str, environment: str, name: str) -> Secret:
        """Metadatos del secreto, sin el valor. Ver ``PorteroClient.get_secret``."""

        async def read(secret_id: UUID) -> Secret:
            return _core.parse_secret(await self._get(_core.secret_path(secret_id)))

        return await self._with_secret(project, environment, name, read)

    async def list_secrets(self, project: str, environment: str) -> tuple[Secret, ...]:
        """Metadatos de todos los secretos del ambiente. Ver ``PorteroClient.list_secrets``."""
        return await self._retrying_stale_ids(lambda: self._fetch_secrets(project, environment))

    async def health(self) -> bool:
        """``True`` si ``/health/ready`` responde 200, ``False`` con 503. Ver
        ``PorteroClient.health``."""
        response = await self._send(_core.HEALTH_PATH)
        if response.status_code == 503:
            return False
        _core.raise_for_status(response)
        return True

    async def validate(self) -> None:
        """*Fail fast* al arranque con ``GET /projects``. Ver ``PorteroClient.validate``."""
        await self._get(_core.PROJECTS_PATH)

    # --- Resolución por nombres (H-54) -----------------------------------------------------------

    async def _with_secret(
        self,
        project: str,
        environment: str,
        name: str,
        action: Callable[[UUID], Awaitable[T]],
    ) -> T:
        async def run() -> T:
            return await action(await self._resolve_secret(project, environment, name))

        return await self._retrying_stale_ids(run)

    async def _retrying_stale_ids(self, operation: Callable[[], Awaitable[T]]) -> T:
        """Si la API respondió 404 a un id memorizado, vacía la memoria y reintenta una vez."""
        cache_was_empty = self._cache.is_empty()
        try:
            return await operation()
        except SecretNotFound as exc:
            if not _core.is_stale_id_error(exc, cache_was_empty):
                raise
        self._cache.clear()
        return await operation()

    async def _resolve_secret(self, project: str, environment: str, name: str) -> UUID:
        project_id, environment_id = await self._resolve_environment(project, environment)
        secret_id = self._cache.secret(environment_id, name)
        if secret_id is None:
            await self._fetch_secrets(project, environment)
            secret_id = self._cache.secret(environment_id, name)
        if secret_id is None:
            raise _core.not_found()
        return secret_id

    async def _fetch_secrets(self, project: str, environment: str) -> tuple[Secret, ...]:
        """Pide la lista de secretos del ambiente y memoriza sus ids."""
        project_id, environment_id = await self._resolve_environment(project, environment)
        response = await self._get(_core.secrets_path(project_id, environment_id))
        secrets = _core.parse_secret_list(response)
        self._cache.store_secrets(environment_id, secrets)
        return secrets

    async def _resolve_environment(self, project: str, environment: str) -> tuple[UUID, UUID]:
        project_id = await self._resolve_project(project)
        environment_id = self._cache.environment(project_id, environment)
        if environment_id is None:
            response = await self._get(_core.environments_path(project_id))
            self._cache.store_environments(project_id, _core.parse_named_list(response))
            environment_id = self._cache.environment(project_id, environment)
        if environment_id is None:
            raise _core.not_found()
        return project_id, environment_id

    async def _resolve_project(self, project: str) -> UUID:
        project_id = self._cache.project(project)
        if project_id is None:
            response = await self._get(_core.PROJECTS_PATH)
            self._cache.store_projects(_core.parse_named_list(response))
            project_id = self._cache.project(project)
        if project_id is None:
            raise _core.not_found()
        return project_id

    # --- HTTP ------------------------------------------------------------------------------------

    async def _send(self, path: str) -> httpx.Response:
        """``GET`` relativo a ``/api/v1``; ``NetworkError`` sin encadenar la excepción de httpx."""
        error: NetworkError
        try:
            return await self._http.get(path)
        except httpx.TransportError as exc:
            error = _core.network_error(exc)
        raise error

    async def _get(self, path: str) -> httpx.Response:
        response = await self._send(path)
        _core.raise_for_status(response)
        return response
