"""Prueba del endpoint de salud del API REST Gateway."""

from httpx import ASGITransport, AsyncClient

from portero.config import Settings
from portero.main import create_app


async def test_health_responde_ok(settings: Settings) -> None:
    # Preparar
    app = create_app(settings)
    transport = ASGITransport(app=app)

    # Actuar
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    # Verificar
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# H-32 (hash señuelo al arrancar) se prueba ahora en tests/integration/test_arranque.py: el
# señuelo se prepara en el lifespan, que necesita la BD para derivar la KEK.
