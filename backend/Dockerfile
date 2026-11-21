# Imagen del backend de Portero Cloud. Multi-etapa: la etapa "builder" tiene uv y resuelve
# dependencias; la etapa final solo lleva Python, el entorno virtual y el código.
#
# H-64: las imágenes base van fijadas por digest (una etiqueta se puede mover, igual que las
# acciones de la CI van por SHA); la etiqueta queda como referencia. Dependabot las actualiza.

# ---------- Etapa 1: construcción ----------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

# uv fijado a la misma versión que se usa en desarrollo (reproducibilidad).
COPY --from=ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Primero solo las dependencias: esta capa se reutiliza mientras no cambie uv.lock.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Después el código del proyecto.
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---------- Etapa 2: ejecución ----------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

# Usuario sin privilegios (Cap. 6): UID fijo 10001, sin shell de inicio de sesión.
RUN groupadd --system --gid 10001 portero \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin portero

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv

USER 10001
EXPOSE 8000

# H-63 (CIS Docker 4.6): Docker sabe si la API responde, no solo si el proceso existe. La imagen
# slim no trae curl; se usa la stdlib de Python contra /api/v1/health (límite de 600/min por IP).
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --start-interval=2s --retries=3     CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2)"]

CMD ["uvicorn", "--factory", "portero.main:create_app", "--host", "0.0.0.0", "--port", "8000"]
