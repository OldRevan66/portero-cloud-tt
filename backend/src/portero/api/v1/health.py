"""Verificación de salud del API REST Gateway (spec Fase 5 §3.8).

- ``GET /api/v1/health``: el proceso está vivo. No toca la BD; lo usa Docker Compose.
- ``GET /api/v1/health/ready``: la BD responde y la KEK quedó derivada y verificada en el
  arranque (H-06). 200 o 503.

Ningún cuerpo identifica al producto ni su versión: no le da pistas a un escaneo. Son respuestas
de estado para orquestadores, no errores de la API, así que no usan Problem Details.
"""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from portero.api.deps import SessionDep
from portero.db.session import ping

logger = logging.getLogger("portero.api")

router = APIRouter(tags=["salud"])


@router.get("/health", summary="Proceso en ejecución")
async def health() -> dict[str, str]:
    """Indica que el servicio está en ejecución."""
    return {"status": "ok"}


@router.get("/health/ready", summary="Listo para atender")
async def ready(request: Request, session: SessionDep) -> JSONResponse:
    """Listo para atender: BD accesible y KEK cargada (spec §3.8; H-06)."""
    kek_ready = getattr(request.app.state, "key_manager", None) is not None
    try:
        await ping(session)
        db_ready = True
    except (SQLAlchemyError, OSError):
        logger.warning("health/ready: la base de datos no responde", exc_info=True)
        db_ready = False
    if db_ready and kek_ready:
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "unavailable"}, status_code=503)
