"""Apoyo de las pruebas del SDK: constantes, servidor falso y utilidades.

Sin red ni BD: ``ServidorFalso`` es el manejador de un ``httpx.MockTransport`` e imita las
respuestas de la API REST (spec Fase 5 §2 para las formas, §6 para Problem Details y
``X-Trace-Id``, §7 para ``Retry-After``). Representa lo que ve una Aplicación Cliente con un PAT
de ``development`` del proyecto "Tienda en línea" (spec §3.7, H-23d): un solo proyecto visible y
un solo ambiente.

Los valores son marcadores obvios ("no-es-real"), nunca credenciales (RNF-006).
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID

import httpx

TOKEN = "pat-de-prueba-no-es-real-7f3a9c41"
VALOR = "demo-no-es-real-valor-del-secreto"
VALOR_NUEVO = "demo-no-es-real-valor-del-secreto-recreado"
DETALLE_DEL_SERVIDOR = "detalle-del-servidor-que-no-debe-propagarse"
TRACE_ID = "0f1e2d3c-4b5a-4968-8776-655443322110"

BASE_URL = "https://portero.example"
API = "/api/v1"

PROYECTO = "Tienda en línea"
AMBIENTE = "development"
NOMBRE = "DB_PASSWORD"

PID = UUID("6a1f4a2e-0c55-4c7e-9a43-1d2f3e4a5b60")
EID = UUID("7b2e5b3f-1d66-4d8f-8b54-2e3f4a5b6c71")
SID = UUID("8c3f6c40-2e77-4e90-9c65-3f4a5b6c7d82")
SID_NUEVO = "9d407d51-3f88-4fa1-8d76-4a5b6c7d8e93"
SID_OTRO = UUID("ae518e62-4099-40b2-9e87-5b6c7d8e9fa4")
USUARIO = UUID("bf629f73-51aa-41c3-8f98-6c7d8e9fa0b5")

CREATED_AT = "2026-10-01T10:00:00Z"

# crear_cliente(manejador=None, *, base_url=..., token=..., **kwargs) -> cliente
FabricaCliente = Callable[..., Any]


def problema(status: int, headers: dict[str, str] | None = None) -> httpx.Response:
    """Respuesta de error RFC 9457 como la del API REST Gateway (spec §6)."""
    cuerpo = {
        "type": f"https://portero-cloud.example/errors/{status}",
        "title": "Error",
        "status": status,
        "detail": DETALLE_DEL_SERVIDOR,
        "instance": "/api/v1/...",
        "trace_id": TRACE_ID,
    }
    cabeceras = {"X-Trace-Id": TRACE_ID, **(headers or {})}
    return httpx.Response(
        status,
        content=json.dumps(cuerpo).encode(),
        headers={"Content-Type": "application/problem+json", **cabeceras},
    )


def metadatos(secret_id: UUID | str, name: str, version: int = 3) -> dict[str, Any]:
    """Cuerpo de ``SecretOut`` (spec §2): metadatos, nunca el valor."""
    return {
        "id": str(secret_id),
        "name": name,
        "description": "Contraseña de la BD de demostración",
        "version": version,
        "project_id": str(PID),
        "environment_id": str(EID),
        "created_at": CREATED_AT,
        "created_by": str(USUARIO),
        "updated_at": CREATED_AT,
    }


class ServidorFalso:
    """Manejador para ``httpx.MockTransport`` que registra cada petición.

    - ``recrear_secreto()`` simula archivar ``DB_PASSWORD`` y crearlo de nuevo: cambia el id.
    - ``borrar_secreto()`` lo saca de la lista y su id responde 404.
    - ``respuesta_valor`` sustituye la respuesta de ``/value`` (respuestas mal formadas).
    """

    def __init__(self) -> None:
        self.peticiones: list[httpx.Request] = []
        self.secret_id: str | None = str(SID)
        self.valor = VALOR
        self.respuesta_valor: httpx.Response | None = None

    def recrear_secreto(self) -> None:
        self.secret_id = SID_NUEVO
        self.valor = VALOR_NUEVO

    def borrar_secreto(self) -> None:
        self.secret_id = None

    def contar(self, ruta: str) -> int:
        """Cuántas peticiones llegaron a ``/api/v1`` + ``ruta``."""
        return sum(1 for p in self.peticiones if p.url.path == API + ruta)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.peticiones.append(request)
        if request.method != "GET":
            return problema(405)
        ruta = request.url.path
        secretos = f"{API}/projects/{PID}/environments/{EID}/secrets"

        if ruta == f"{API}/projects":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": str(PID),
                        "name": PROYECTO,
                        "description": None,
                        "created_at": CREATED_AT,
                        "updated_at": CREATED_AT,
                    }
                ],
            )
        if ruta == f"{API}/projects/{PID}/environments":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": str(EID),
                        "project_id": str(PID),
                        "name": AMBIENTE,
                        "description": None,
                        "created_at": CREATED_AT,
                    }
                ],
            )
        if ruta == secretos:
            lista = [metadatos(SID_OTRO, "API_KEY", version=1)]
            if self.secret_id is not None:
                lista.insert(0, metadatos(self.secret_id, NOMBRE))
            return httpx.Response(200, json=lista)
        if self.secret_id is not None and ruta == f"{API}/secrets/{self.secret_id}":
            return httpx.Response(200, json=metadatos(self.secret_id, NOMBRE))
        if self.secret_id is not None and ruta == f"{API}/secrets/{self.secret_id}/value":
            if self.respuesta_valor is not None:
                return self.respuesta_valor
            return httpx.Response(
                200,
                json={"id": self.secret_id, "name": NOMBRE, "value": self.valor, "version": 3},
            )
        if ruta == f"{API}/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        return problema(404)


class TransporteConCierre(httpx.MockTransport):
    """``MockTransport`` que recuerda si el cliente lo cerró (``close`` o ``aclose``)."""

    cerrado = False

    def close(self) -> None:
        self.cerrado = True
        super().close()

    async def aclose(self) -> None:
        self.cerrado = True
        await super().aclose()


async def esperar(resultado: Any) -> Any:
    """Espera ``resultado`` si es una corutina (PorteroAsyncClient); si no, lo devuelve.

    Permite escribir una sola prueba de comportamiento para las dos clases."""
    if inspect.isawaitable(resultado):
        return await resultado
    return resultado
