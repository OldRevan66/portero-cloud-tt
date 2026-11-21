# Portero Cloud

Sistema de gestión de secretos en la nube para equipos de desarrollo de PyMEs mexicanas.
Trabajo Terminal ESCOM-IPN 2026-B067 · Alumno: Arturo Monroy Mora · Directora: Dra. Nidia A. Cortez Duarte.

Backend en Python 3.12 + FastAPI + PostgreSQL 16; Dashboard Web en React 19 + TypeScript +
Mantine, servido por nginx. Los secretos se cifran con AES-256-GCM y
envoltura de llaves (DEK/KEK); el diseño está en los capítulos 5 y 6 del reporte técnico.

Versión **1.0.0**, la entregada para la evaluación del Trabajo Terminal. Licencia: [MIT](LICENSE).

| Documento | Para quién |
|---|---|
| [`docs/guia-instalacion.pdf`](docs/guia-instalacion.pdf) | Quien instala y opera el sistema: requisitos, `.env`, puesta en marcha, endurecimiento, respaldo, rotación de la KEK |
| [`docs/manual-usuario.pdf`](docs/manual-usuario.pdf) | Administrador, Líder Técnico y Desarrollador: uso del Dashboard Web y del SDK |

Este README resume los comandos para desarrolladores; la guía de instalación es la referencia
completa.

## Requisitos

| Herramienta | Versión | Instalación (PowerShell 7) |
|---|---|---|
| Windows 11 | — | sin WSL; Docker Desktop lo usa internamente |
| PowerShell | 7.x | `winget install --id Microsoft.PowerShell -e` |
| Git for Windows | reciente | `winget install --id Git.Git -e` |
| uv | ≥ 0.12 | `winget install --id astral-sh.uv -e` |
| Python | 3.12 | `uv python install 3.12` |
| Docker Desktop | reciente | `winget install --id Docker.DockerDesktop -e` |
| Node.js | 22 LTS | `winget install --id OpenJS.NodeJS.LTS -e` (solo para desarrollar el Dashboard) |

Configura Git para respetar los finales de línea LF del repositorio (`.gitattributes`):
`git config --global core.autocrlf false`.

## Instalación en Windows 11

Obtén el código copiando la carpeta del disco de entrega o clonando el repositorio público del
proyecto, y entra en ella:

```powershell
cd portero-cloud

# 1. Configuración local (el archivo .env NUNCA se sube a Git)
Copy-Item .env.example .env
notepad .env        # cambia todos los valores CAMBIAME

# 2. Dependencias del backend (crea backend\.venv con versiones exactas de uv.lock)
cd backend
uv sync
```

Variables de entorno (prefijo `PORTERO_`); si falta una obligatoria el backend no arranca:

| Variable | Obligatoria | Descripción |
|---|---|---|
| `PORTERO_DATABASE_URL` | sí | URL de PostgreSQL (`postgresql+asyncpg://...`) |
| `PORTERO_KEK_PASSPHRASE` | sí | passphrase de la que se deriva la KEK (Argon2id) |
| `PORTERO_JWT_PRIVATE_KEY` | sí | clave privada Ed25519 en PEM para firmar JWT |
| `PORTERO_ALLOWED_ORIGINS` | no (`[]`) | orígenes CORS, lista JSON |
| `PORTERO_DOCS_ENABLED` | no (`false`) | expone `/docs` (Swagger) |
| `POSTGRES_PASSWORD` | sí (Compose) | contraseña de la base de desarrollo |

## Bases de datos

```powershell
docker compose up -d db db-test   # db: desarrollo (5434, volumen) · db-test: pruebas (5433, en RAM)
docker compose ps                 # ambos deben aparecer "healthy"
docker compose down               # apagar (los datos de db se conservan)
docker compose down -v            # apagar y borrar el volumen (reinicio limpio)
```

## Ejecutar el backend en desarrollo

```powershell
cd backend
uv run uvicorn --factory portero.main:create_app --reload
# http://localhost:8000/api/v1/health  ->  {"status":"ok"}
# http://localhost:8000/docs           (si PORTERO_DOCS_ENABLED=true)
```

## Pruebas y calidad

```powershell
cd backend
uv run pytest                                   # todas las pruebas
uv run pytest tests/unit -q                     # solo unitarias (sin base de datos)
uv run pytest --cov=portero --cov-report=term-missing
uv run ruff check . ; uv run ruff format --check .
uv run mypy src/portero/crypto src/portero/rbac src/portero/db
```

Las pruebas de integración usan `db-test`, así que antes hay que
levantarla con `docker compose up -d db-test`.

## Todo el sistema con Docker

Desde cero (borra la base de desarrollo), con datos de demostración:

```powershell
docker compose down -v                    # reinicio limpio (borra el volumen de db)
docker compose up -d db                   # 1. solo la base de datos

cd backend
uv run alembic upgrade head               # 2. migraciones (usa PORTERO_DATABASE_URL de .env)
uv run python scripts/seed_demo.py --generar   # 3. seed: con la API detenida y la BD vacía
cd ..

docker compose up --build                 # 4. backend + Dashboard
```

El seed imprime **una sola vez** las contraseñas generadas de `admin@tienda.example`,
`lider@tienda.example` y `dev@tienda.example`, y el token de la Aplicación Cliente de demostración.
Sin `--generar` las pide con `getpass`. Los valores de los secretos de demostración empiezan con
`demo-no-es-real-`. El script se niega a correr si la base ya tiene usuarios o proyectos.

| Servicio | URL (solo en esta máquina) |
|---|---|
| Dashboard Web | http://localhost:8080 |
| API (Swagger con `PORTERO_DOCS_ENABLED=true`) | http://localhost:8000/docs |

```powershell
curl http://localhost:8080/api/v1/health   # la API a través del proxy de nginx
docker compose exec backend id             # uid=10001(portero): el proceso no corre como root
docker compose exec frontend id            # uid=101(nginx)
```

- La imagen del backend (`backend/Dockerfile`) es multi-etapa sobre `python:3.12-slim` y corre
  como el usuario sin privilegios `portero` (UID 10001). Compose además desactiva los volcados de
  memoria (`ulimits: core: 0`), impide la escalada de privilegios y retira las capacidades del
  kernel.
- La imagen del Dashboard (`frontend/Dockerfile`) compila la SPA con Node y la sirve con
  `nginx-unprivileged` (UID 101, puerto 8080, sistema de archivos de solo lectura). nginx hace
  de proxy de `/api` al backend: la SPA y la API comparten origen, así que la cookie del refresh
  (`HttpOnly`, `SameSite=Strict`) funciona sin CORS. Cabeceras en `frontend/security-headers.conf`:
  CSP, `X-Frame-Options: DENY`, `nosniff` y `Referrer-Policy: no-referrer`.
- Todos los puertos se publican solo en loopback (`127.0.0.1` y `[::1]`, H-33).
- El backend acepta `X-Forwarded-For` solo de la IP fija de nginx (`172.30.250.10`), que lo
  sobrescribe con la IP real del cliente (H-53). Si esa subred choca con tu red local, cambia
  `networks.default` y `FORWARDED_ALLOW_IPS` en `docker-compose.yml` a la vez.

## Dashboard Web en desarrollo

Con la base de datos y el backend corriendo en Windows (secciones anteriores):

```powershell
cd frontend
npm ci
npm run dev        # http://localhost:5173 (Vite manda /api a localhost:8000)
npm test           # Vitest
npm run lint ; npx tsc --noEmit ; npm run build
npx prettier --check .
```

`npm run lint` corre ESLint y además revisa los tipos de las pruebas E2E (`tsc -p e2e`).

## Pruebas E2E

Pruebas end-to-end del Dashboard con Playwright en Chromium (Cap. 6 §Pruebas end-to-end;
spec §8.6). Cubren siete flujos: (i) inicio y cierre de sesión, (ii) ciclo de vida de un secreto,
(iii) Aplicación Cliente, (iv) bitácora, (v) restricciones del Desarrollador, (vi) sesión tras
recargar y (vii) manejo del valor revelado. Cada corrida usa una instancia limpia (H-57).

**Requisitos:** Docker Desktop encendido, `uv` (genera las credenciales desechables con el
backend), Node 22 y `npm ci` en `frontend/`. Una vez por máquina hay que descargar el navegador:

```powershell
cd frontend
npx playwright install chromium
```

**Correrlas** (un solo comando; el stack de desarrollo puede seguir arriba):

```powershell
npm run e2e                          # todas
npm run e2e -- e2e/sesion.spec.ts    # un archivo
```

`npm run e2e` (`e2e/correr.mjs`):

1. Genera las credenciales en `frontend/e2e/.generado/`, ignorado por Git: contraseña de
   PostgreSQL, passphrase de la KEK, clave Ed25519 y contraseñas del seed.
2. Levanta el proyecto de Compose `portero-e2e` (`docker-compose.yml` + `docker-compose.e2e.yml`):
   BD en RAM sin puertos publicados, red `172.30.251.0/24` y Dashboard en
   `http://localhost:8180`.
3. Migra y siembra dentro de ese stack (servicio `preparar`). Nunca toca la BD de desarrollo
   ni lee `.env`.
4. Corre Playwright.
5. Siempre, aunque fallen las pruebas: `docker compose down -v` y borra las credenciales.
   Sale con el código de Playwright.

**Ver el reporte:**

```powershell
npx playwright show-report           # o: npm run e2e:reporte
npx playwright show-trace test-results\<prueba>\trace.zip
```

Si una prueba falla, Playwright guarda la captura y el *trace* (DOM, red y consola paso a paso)
en `test-results/`. El reporte HTML queda en `playwright-report/`, y ambos están ignorados por
Git. Esos archivos pueden contener credenciales del stack desechable, que dejan de servir al
bajarlo.

## Estructura

```
backend/
  src/portero/
    config.py  main.py
    api/          API REST Gateway
    auth/         Servicio de Autenticación
    rbac/         Módulo RBAC
    crypto/       Motor Criptográfico
    secrets_mgmt/ Servicio de Gestión de Secretos
    management/   Servicios de Gestión
    oplog/        Servicio de Registro de Operaciones
    db/           Capa de Persistencia (modelos, sesión, repositorios)
    cli.py        utilidades administrativas
  tests/  unit/  integration/  vectors/
frontend/
  src/            Dashboard Web (api/, auth/, projects/, secrets/, operations/, serviceAccounts/)
  Dockerfile  nginx.conf  security-headers.conf
sdk/              SDK Python (portero-cloud-sdk), con su propio README
docs/             guía de instalación y manual de usuario (PDF)
ejecutables/      imágenes Docker exportadas y paquete del SDK (ver abajo)
docker-compose.yml  docker-compose.e2e.yml
.github/workflows/ci.yml   integración continua (pruebas, calidad, auditoría de dependencias, E2E)
```

## Ejecutables

Portero Cloud es un servicio web: su forma ejecutable son las **imágenes de contenedor** del
backend y del Dashboard, que corren igual en cualquier equipo con Docker. Se construyen de forma
reproducible desde este código (`backend/Dockerfile` y `frontend/Dockerfile`, multi-etapa, con las
dependencias fijadas en `uv.lock` y `package-lock.json` y las imágenes base fijadas por digest).
Para no tener que compilarlas, la carpeta `ejecutables/` (en el disco de entrega y en los archivos
del Release v1.0.0) trae:

| Archivo | Contenido |
|---|---|
| `imagenes/portero-backend-1.0.0.tar` | API REST Gateway y servicios (`portero-cloud-backend:1.0.0`) |
| `imagenes/portero-frontend-1.0.0.tar` | Dashboard Web servido por nginx (`portero-cloud-frontend:1.0.0`) |
| `imagenes/postgres-16.tar` | PostgreSQL 16, la versión exacta que fija `docker-compose.yml` |
| `sdk/portero_cloud_sdk-1.0.0-py3-none-any.whl` | SDK Python instalable con `pip install` (y su `.tar.gz` de fuentes) |
| `SHA256SUMS.txt` | Huellas SHA-256 para comprobar que los archivos no cambiaron |

```powershell
cd ejecutables
Get-FileHash -Algorithm SHA256 imagenes\*.tar, sdk\*   # compara con SHA256SUMS.txt
docker load -i imagenes\postgres-16.tar
docker load -i imagenes\portero-backend-1.0.0.tar
docker load -i imagenes\portero-frontend-1.0.0.tar
cd ..
docker compose up -d     # usa las imágenes cargadas; --build las vuelve a compilar desde el código
```

Antes de `up` hacen falta el `.env`, las migraciones y el primer Administrador (o el seed de
demostración), como indica la guía de instalación. Esos pasos usan `uv` en la máquina anfitriona,
porque la imagen del backend solo contiene el código de la aplicación.

Los scripts administrativos están en `backend/scripts/` (generar llaves, datos de demostración,
prueba de carga) y en `portero.cli` (`create-admin`, `rotate-kek`, `sign-chain`); las migraciones,
en `backend/alembic/`.

## Trazabilidad

Los comentarios y las pruebas citan el diseño para poder seguir cada decisión:

- **Cap. 5 / Cap. 6**: capítulos de diseño del reporte técnico (arquitectura y diseño detallado).
- **CU-NN, RF-NNN, RNF-NNN**: casos de uso y requerimientos del reporte técnico.
- **H-NN**: hallazgos registrados durante la implementación (decisiones, correcciones y
  desviaciones del diseño), descritos en los capítulos 7 y 8 del reporte técnico.
- **spec §N**: especificación operativa derivada de los capítulos 5 y 6.
- **OWASP ASVS, NIST SP, RFC**: normas y estándares que sigue cada control.
