# portero-cloud-sdk

SDK Python de **Portero Cloud** para que una Aplicación Cliente lea sus secretos con su token
personal de acceso (PAT). Implementa el caso de uso CU-04 y el Cap. 6 §Diseño del SDK Python.

- **Solo lectura.** Crear, rotar o borrar secretos se hace en el Dashboard o por la API. Si el
  token de una aplicación se filtra, solo sirve para leer lo que cubre su alcance (privilegio
  mínimo).
- **Síncrono y asíncrono** con la misma firma: `PorteroClient` (`httpx.Client`) y
  `PorteroAsyncClient` (`httpx.AsyncClient`).
- **Sin caché de valores.** Cada `get_secret_value` pide el valor a la API, así que una rotación
  se ve sin reiniciar. El SDK solo memoriza los identificadores de proyectos, ambientes y
  secretos (hallazgo H-54).
- **Excepciones tipadas** y retornos inmutables (`Secret`, una *dataclass* congelada).

Requisitos: Python ≥ 3.10. Dependencias: `httpx` y `pydantic`.

## Instalación

Por ahora se instala desde la ruta del repositorio, no desde PyPI.

```bash
# con uv, en el proyecto de la aplicación
uv add ../portero-cloud/sdk

# con pip
pip install ./portero-cloud/sdk
```

## Uso síncrono

```python
import os
from portero_cloud_sdk import PorteroClient

client = PorteroClient(
    base_url=os.environ["PORTERO_BASE_URL"],  # raíz del servidor; el SDK agrega /api/v1
    token=os.environ["PORTERO_TOKEN"],
    timeout=10.0,  # segundos (valor por omisión)
)
client.validate()  # al arranque: falla rápido si el token o la URL están mal

db_password = client.get_secret_value("Tienda en línea", "development", "DB_PASSWORD")
secreto = client.get_secret("Tienda en línea", "development", "DB_PASSWORD")  # sin el valor
print(secreto.name, secreto.version)
client.close()
```

El cliente se crea **una sola vez** al arranque y se reutiliza. Con `with PorteroClient(...) as
client:` se cierra solo, incluso ante excepciones.

## Uso asíncrono

```python
from portero_cloud_sdk import PorteroAsyncClient


async def cargar_configuracion() -> str:
    async with PorteroAsyncClient(base_url=BASE_URL, token=TOKEN) as client:
        await client.validate()
        return await client.get_secret_value("Tienda en línea", "development", "DB_PASSWORD")
```

## Métodos

| Método | Devuelve | Notas |
|---|---|---|
| `get_secret_value(project, environment, name)` | `str` | El valor en claro. Se pide en cada llamada. |
| `get_secret(project, environment, name)` | `Secret` | `id`, `name`, `version`, `description`, `created_at`. Sin el valor. |
| `list_secrets(project, environment)` | `tuple[Secret, ...]` | Todos los secretos del ambiente. |
| `health()` | `bool` | `True` si el backend está listo y `False` si responde 503. Para el *health check* de la aplicación. |
| `validate()` | `None` | Comprueba el token y la conexión. Úsalo al arranque. |
| `close()` | `None` | Libera las conexiones. También funcionan `with` y `async with`. |

Los nombres se comparan exactos (distinguen mayúsculas). El SDK los resuelve con
`GET /projects` → `GET .../environments` → `GET .../secrets`, así que los nombres nunca viajan
en la URL.

## Manejo del token

El SDK recibe el token **solo** por el constructor. No lo busca en archivos, llaveros ni
servicios externos: si lo hiciera, el problema de guardar un secreto pasaría a la aplicación.

- **Variable de entorno inyectada por el orquestador.** El operador inyecta `PORTERO_TOKEN` con
  el mecanismo de *secrets* de la plataforma (Docker Secrets, Kubernetes Secrets, AWS Parameter
  Store…) y la aplicación lo lee con `os.environ`.
- **Nunca en el repositorio.** Ni en el código, ni en archivos de configuración versionados, ni
  en un `.env` que se suba a Git. `.gitignore` de referencia:
  ```gitignore
  .env
  .env.*
  !.env.example
  ```
- **Rotar el PAT = reiniciar la aplicación.** Se crea una Aplicación Cliente nueva en el
  Dashboard, se actualiza la variable en el orquestador, se reinicia la aplicación y se revoca la
  anterior. El SDK no recarga el token en caliente.
- **https obligatorio fuera de localhost** (hallazgo H-55). `http://` solo se acepta hacia
  `localhost`, `127.0.0.1` o `::1`. En una red interna con TLS terminado en el borde (p. ej.
  `http://backend:8000` dentro de Docker Compose), hay que pasar `allow_insecure_http=True` de
  forma explícita.
- El token no aparece en el `repr` del cliente, en los mensajes de las excepciones ni en los
  logs de httpx.

## Excepciones

Todas heredan de `PorteroError`: se puede capturar `except PorteroError` o solo una en
particular. Ninguna incluye el token ni el cuerpo de la respuesta. Tienen `status_code` (o
`None`) y `trace_id`, el `X-Trace-Id` con el que el operador encuentra la petición en los logs
del backend.

| Excepción | Cuándo | Qué hacer |
|---|---|---|
| `AuthenticationError` | 401: el token falta, expiró, es inválido o la aplicación fue revocada | Revisar `PORTERO_TOKEN`; no reintentar |
| `PermissionDenied` | 403: el token es válido pero su alcance no cubre la operación | Revisar el alcance de la Aplicación Cliente |
| `SecretNotFound` | 404, o el nombre no está entre lo que el token puede ver | Revisar los nombres; "no existe" y "fuera del alcance" se ven igual a propósito |
| `RateLimited` | 429: se excedió el límite de tasa | Esperar `retry_after` segundos; el SDK no reintenta solo |
| `NetworkError` | Sin respuesta: conexión rechazada, DNS, TLS o tiempo de espera | Típicamente, no arrancar |
| `ServerError` | 5xx del backend | Reportar el `trace_id` al operador |
| `PorteroError` | Otra respuesta 4xx o una respuesta mal formada | Reportar el `trace_id` |

Al construir el cliente se lanza `ValueError` si el token está vacío o tiene espacios, si
`timeout` no es positivo o si `base_url` no es una URL `https` válida (ver arriba).

## Ejemplo para la demo

`examples/leer_secreto.py` lee `PORTERO_BASE_URL` y `PORTERO_TOKEN` del entorno e imprime el
nombre, la versión y el valor **enmascarado**. `--mostrar` imprime el valor completo solo si es un
valor de demostración (`demo-no-es-real-...`).

```powershell
$env:PORTERO_BASE_URL = "http://localhost:8000"; $env:PORTERO_TOKEN = "<pega el token>"
uv run python examples/leer_secreto.py --proyecto "Tienda en línea" --ambiente development --nombre DB_PASSWORD
Remove-Item Env:PORTERO_TOKEN
```

Códigos de salida: 0 éxito, 2 configuración, 3 autenticación, 4 no encontrado o sin permiso,
5 límite de tasa, 6 red, 7 servidor, 1 otro error.

## Desarrollo

```bash
cd sdk && uv sync
uv run pytest -q                                   # sin red ni BD (httpx.MockTransport)
uv run pytest --cov=portero_cloud_sdk --cov-report=term-missing
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests                              # --strict
# contra el stack de desarrollo con el seed y un PAT de development:
$env:PORTERO_SDK_BASE_URL = "http://localhost:8000"; $env:PORTERO_SDK_TOKEN = "<PAT>"
uv run pytest -m vivo -v
```
