"""``PorteroClient``: cliente síncrono del SDK (Cap. 6 §API pública del SDK).

Envía las peticiones con ``httpx.Client`` y delega todo lo demás en ``_core``. Solo lectura con
un PAT (Cap. 6 §Alcance, "Mínima superficie de API"): crear, rotar o borrar secretos no forma
parte del SDK, así que una Aplicación Cliente comprometida solo puede leer lo que su alcance
cubre (privilegio mínimo; OWASP ASVS V2.10, credenciales de servicio).
"""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import TypeVar
from uuid import UUID

import httpx

from portero_cloud_sdk import _core
from portero_cloud_sdk._version import __version__
from portero_cloud_sdk.errors import NetworkError, SecretNotFound
from portero_cloud_sdk.models import Secret

T = TypeVar("T")


class PorteroClient:
    """Cliente síncrono. Se construye una vez al arranque de la aplicación y se reutiliza
    (Cap. 6); ``with PorteroClient(...) as client:`` lo cierra al salir, incluso ante excepciones.

    ``base_url`` es la raíz del servidor (``https://portero.example``); el SDK agrega
    ``/api/v1``. ``token`` es el PAT de la Aplicación Cliente y solo llega por aquí: el SDK no lo
    lee de archivos ni de variables de entorno (Cap. 6 §Manejo de credenciales del cliente).
    ``transport`` permite inyectar un transporte de httpx (pruebas o proxies).

    Lanza ``ValueError`` si el token está vacío o tiene espacios, si ``base_url`` no es http(s)
    o si usa ``http`` fuera de loopback sin ``allow_insecure_http=True`` (H-55).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = _core.DEFAULT_TIMEOUT,
        allow_insecure_http: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = _core.api_base_url(base_url, allow_insecure_http=allow_insecure_http)
        # El token solo vive en las cabeceras del cliente httpx, cuyo repr las oculta.
        self._http = httpx.Client(
            base_url=self._base_url,
            headers=_core.default_headers(_core.validate_token(token), __version__),
            timeout=_core.validate_timeout(timeout),
            transport=transport,
        )
        self._cache = _core.IdCache()

    def __repr__(self) -> str:
        return f"PorteroClient(base_url={self._base_url!r})"

    # --- Ciclo de vida ---------------------------------------------------------------------------

    def close(self) -> None:
        """Libera el cliente HTTP subyacente. Llamarlo dos veces no tiene efecto."""
        self._http.close()

    def __enter__(self) -> PorteroClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # --- API pública (tabla "API pública de PorteroClient" del Cap. 6) --------------------------

    def get_secret_value(self, project: str, environment: str, name: str) -> str:
        """Valor en claro del secreto ``name`` del ``environment`` de ``project``.

        Se pide a la API en **cada** llamada (el valor no se cachea; Cap. 6 "Falla de manera
        segura"): una rotación se ve sin reiniciar. Lanza ``SecretNotFound`` si no existe o el
        alcance del token no lo cubre, ``PermissionDenied`` si la API responde 403."""
        return self._with_secret(
            project,
            environment,
            name,
            lambda sid: _core.parse_secret_value(self._get(_core.secret_value_path(sid))),
        )

    def get_secret(self, project: str, environment: str, name: str) -> Secret:
        """Metadatos del secreto, sin el valor. Se piden a ``GET /secrets/{id}`` en cada
        llamada, porque la versión cambia al rotar."""
        return self._with_secret(
            project,
            environment,
            name,
            lambda sid: _core.parse_secret(self._get(_core.secret_path(sid))),
        )

    def list_secrets(self, project: str, environment: str) -> tuple[Secret, ...]:
        """Metadatos de todos los secretos del ambiente. La API devuelve la lista completa, sin
        paginar (precisión al Cap. 6 en H-54)."""
        return self._retrying_stale_ids(lambda: self._fetch_secrets(project, environment))

    def health(self) -> bool:
        """``True`` si el backend está listo (``GET /health/ready`` 200), ``False`` si responde
        503 (BD caída o KEK sin cargar, H-06). Sin conexión → ``NetworkError``."""
        response = self._send(_core.HEALTH_PATH)
        if response.status_code == 503:
            return False
        _core.raise_for_status(response)
        return True

    def validate(self) -> None:
        """Verifica al arranque que el token es válido y el backend accesible (*fail fast*,
        Cap. 6 §Manejo de credenciales). Usa ``GET /projects``: ``/auth/me`` es solo para
        humanos y responde 403 a un PAT. Lanza la excepción tipada que corresponda."""
        self._get(_core.PROJECTS_PATH)

    # --- Resolución por nombres (H-54) -----------------------------------------------------------

    def _with_secret(
        self, project: str, environment: str, name: str, action: Callable[[UUID], T]
    ) -> T:
        def run() -> T:
            return action(self._resolve_secret(project, environment, name))

        return self._retrying_stale_ids(run)

    def _retrying_stale_ids(self, operation: Callable[[], T]) -> T:
        """Ejecuta ``operation``; si la API respondió 404 a un id memorizado, vacía la memoria y
        la ejecuta una sola vez más."""
        cache_was_empty = self._cache.is_empty()
        try:
            return operation()
        except SecretNotFound as exc:
            if not _core.is_stale_id_error(exc, cache_was_empty):
                raise
        self._cache.clear()
        return operation()

    def _resolve_secret(self, project: str, environment: str, name: str) -> UUID:
        project_id, environment_id = self._resolve_environment(project, environment)
        secret_id = self._cache.secret(environment_id, name)
        if secret_id is None:
            self._fetch_secrets(project, environment)
            secret_id = self._cache.secret(environment_id, name)
        if secret_id is None:
            raise _core.not_found()
        return secret_id

    def _fetch_secrets(self, project: str, environment: str) -> tuple[Secret, ...]:
        """Pide la lista de secretos del ambiente y memoriza sus ids."""
        project_id, environment_id = self._resolve_environment(project, environment)
        response = self._get(_core.secrets_path(project_id, environment_id))
        secrets = _core.parse_secret_list(response)
        self._cache.store_secrets(environment_id, secrets)
        return secrets

    def _resolve_environment(self, project: str, environment: str) -> tuple[UUID, UUID]:
        project_id = self._resolve_project(project)
        environment_id = self._cache.environment(project_id, environment)
        if environment_id is None:
            response = self._get(_core.environments_path(project_id))
            self._cache.store_environments(project_id, _core.parse_named_list(response))
            environment_id = self._cache.environment(project_id, environment)
        if environment_id is None:
            raise _core.not_found()
        return project_id, environment_id

    def _resolve_project(self, project: str) -> UUID:
        project_id = self._cache.project(project)
        if project_id is None:
            response = self._get(_core.PROJECTS_PATH)
            self._cache.store_projects(_core.parse_named_list(response))
            project_id = self._cache.project(project)
        if project_id is None:
            raise _core.not_found()
        return project_id

    # --- HTTP ------------------------------------------------------------------------------------

    def _send(self, path: str) -> httpx.Response:
        """``GET`` relativo a ``/api/v1``. Un fallo de transporte se convierte en
        ``NetworkError`` lanzado fuera del ``except`` (no encadena el ``Request`` de httpx)."""
        error: NetworkError
        try:
            return self._http.get(path)
        except httpx.TransportError as exc:
            error = _core.network_error(exc)
        raise error

    def _get(self, path: str) -> httpx.Response:
        response = self._send(path)
        _core.raise_for_status(response)
        return response
