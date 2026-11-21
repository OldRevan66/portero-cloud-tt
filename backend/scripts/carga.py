"""Prueba de carga básica del API REST Gateway. **Solo para desarrollo**.

Mide latencia (p50/p95/p99 y máximo), throughput y errores de tres operaciones con ``C``
clientes concurrentes durante ``T`` segundos:

- ``GET /secrets/{id}/value`` con PAT (CU-03; la única respuesta con un valor en claro).
- ``POST /auth/login`` (CU-01; lenta a propósito: Argon2id).
- ``POST /secrets/{id}/rotate`` (CU-04; cifrado de una DEK nueva y registro en la cadena de hashes).

Además demuestra el 429 ``rate-limit-exceeded`` con ``Retry-After`` (spec Fase 5 §7).

Uso, desde ``backend/``, con el stack E2E levantado a mano (Cap. 8 del reporte técnico)::

    uv run python scripts/carga.py --entorno-e2e ../frontend/e2e/.generado/e2e.env \\
        --limite-login 600 --json carga.json

Sin ``--entorno-e2e`` toma ``SEED_PASSWORD_ADMIN`` y ``SEED_PASSWORD_LIDER`` del entorno o las pide
con ``getpass``. Los usuarios son los de ``seed_demo.py``.

**Se respetan los límites de tasa** (Cap. 6, tabla de límites; ``api/rate_limit.py``). Cada clave
del limitador (un PAT, un actor humano, la IP) tiene un ``Ritmo``: como mucho una petición cada
``60 / límite × 1.05`` segundos. Es un ritmo uniforme, no una ráfaga, así que en ninguna ventana de
60 s el servidor ve más de ``límite`` peticiones de esa clave y lo que se mide es su latencia, no
la de un 429. Para subir la carga se agregan claves (más Aplicaciones Cliente, que crea el
script), nunca se acelera una. Toda la carga sale de una sola IP: el límite de login es por IP y
el script lo respeta con ``--limite-login`` (10 por omisión, el del Cap. 6; el stack E2E lo sube a
600, H-56).

**Nunca imprime ni guarda** un token, una contraseña ni un cuerpo de respuesta: de cada petición
solo conserva el código HTTP y la latencia. Los valores de las rotaciones se generan con
``secrets`` y llevan el prefijo ``carga-no-es-real-``.
"""

import argparse
import asyncio
import getpass
import json
import os
import platform
import secrets
import statistics
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

ADMIN = "admin@tienda.example"
LIDER = "lider@tienda.example"
PROYECTO = "Tienda en línea"
AMBIENTE = "development"
SECRETO_LECTURA = "DB_PASSWORD"
SECRETO_ROTACION = "CARGA_ROTACION"
"""Nombres del seed (``scripts/seed_demo.py``) y del secreto que crea esta prueba."""

LIMITE_VALOR = 60
LIMITE_GENERAL = 100
LIMITE_LOGIN_CAP6 = 10
"""Peticiones por minuto de la tabla del Cap. 6 (``api/rate_limit.py``, ``LIMITS``)."""

MARGEN = 1.05
"""5 % de holgura sobre el intervalo mínimo: el reloj del cliente y el del servidor no coinciden
exactamente y la red puede juntar dos peticiones."""

Reloj = Callable[[], float]


# --- Ritmo por clave -----------------------------------------------------------------------------


class Ritmo:
    """Turnos de una clave del limitador: uno cada ``60 / limite_por_minuto × MARGEN`` s.

    ``reservar`` toma el siguiente turno y devuelve cuánto falta para él. No acumula turnos: una
    clave que estuvo quieta no gana una ráfaga después. No tiene ``await``, así que varias
    corrutinas pueden compartir un ``Ritmo`` (la IP del login) sin lock.
    """

    def __init__(self, limite_por_minuto: int, reloj: Reloj = time.monotonic) -> None:
        if limite_por_minuto <= 0:
            raise ValueError("el límite debe ser positivo")
        self.intervalo = 60 / limite_por_minuto * MARGEN
        self._reloj = reloj
        self._siguiente = float("-inf")

    @property
    def proximo(self) -> float:
        """Momento (en el reloj) del siguiente turno libre."""
        return self._siguiente

    def reservar(self) -> float:
        """Reserva el siguiente turno; devuelve los segundos de espera (0 si es ya)."""
        ahora = self._reloj()
        inicio = max(ahora, self._siguiente)
        self._siguiente = inicio + self.intervalo
        return inicio - ahora

    async def esperar(self) -> None:
        """Reserva un turno y duerme hasta él."""
        espera = self.reservar()
        if espera > 0:
            await asyncio.sleep(espera)


@dataclass
class Clave:
    """Una clave del limitador con su ``Ritmo`` y el dato que usa la petición (p. ej. el PAT)."""

    ritmo: Ritmo
    dato: Any = None


def claves_de(datos: Iterable[Any], limite: int) -> list[Clave]:
    """Una ``Clave`` con su propio ``Ritmo`` por dato (p. ej. una por PAT)."""
    return [Clave(Ritmo(limite), dato) for dato in datos]


# --- Medición y resumen --------------------------------------------------------------------------


@dataclass(frozen=True)
class Muestra:
    latencia_ms: float
    codigo: int
    """Código HTTP; 0 si la petición no obtuvo respuesta (error de red o tiempo agotado)."""


Peticion = Callable[[Any], Awaitable[int]]
"""Recibe el ``dato`` de la clave y devuelve el código HTTP. Nunca devuelve el cuerpo."""


async def _trabajador(
    claves: list[Clave], peticion: Peticion, fin: float, muestras: list[Muestra]
) -> None:
    """Bucle cerrado de un cliente: toma la clave con el turno más próximo, espera su turno,
    envía y mide. Termina cuando el siguiente turno cae después de ``fin``."""
    while True:
        clave = min(claves, key=lambda c: c.ritmo.proximo)
        espera = clave.ritmo.reservar()
        if time.monotonic() + espera >= fin:
            return
        if espera > 0:
            await asyncio.sleep(espera)
        inicio = time.perf_counter()
        try:
            codigo = await peticion(clave.dato)
        except httpx.HTTPError:
            codigo = 0
        muestras.append(Muestra((time.perf_counter() - inicio) * 1000, codigo))


async def correr(
    nombre: str, asignacion: list[list[Clave]], peticion: Peticion, duracion_s: float
) -> dict[str, Any]:
    """Corre un trabajador por lista de ``asignacion`` durante ``duracion_s`` y resume."""
    muestras: list[Muestra] = []
    inicio = time.monotonic()
    fin = inicio + duracion_s
    await asyncio.gather(
        *(_trabajador(claves, peticion, fin, muestras) for claves in asignacion if claves)
    )
    return resumir(nombre, muestras, max(duracion_s, time.monotonic() - inicio))


def _percentiles(latencias: list[float]) -> dict[str, float | None]:
    if not latencias:
        return {"p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None}
    if len(latencias) == 1:
        cortes = latencias * 99
    else:
        cortes = statistics.quantiles(latencias, n=100, method="inclusive")
    return {
        "p50_ms": cortes[49],
        "p95_ms": cortes[94],
        "p99_ms": cortes[98],
        "max_ms": max(latencias),
    }


def resumir(nombre: str, muestras: list[Muestra], duracion_s: float) -> dict[str, Any]:
    """n, respuestas 2xx, errores por código, throughput (2xx por segundo) y percentiles de
    latencia de las 2xx. Percentiles ``inclusive`` (interpolación lineal, como el R-7)."""
    correctas = [m.latencia_ms for m in muestras if 200 <= m.codigo < 300]
    errores = Counter("red" if m.codigo == 0 else str(m.codigo) for m in muestras)
    for codigo in [c for c in errores if c.startswith("2")]:
        del errores[codigo]
    return {
        "escenario": nombre,
        "duracion_s": round(duracion_s, 2),
        "n": len(muestras),
        "ok": len(correctas),
        "errores": dict(sorted(errores.items())),
        "throughput": len(correctas) / duracion_s if duracion_s > 0 else 0.0,
        **_percentiles(correctas),
    }


def formatear(resumen: dict[str, Any]) -> str:
    """Una línea legible por escenario."""
    cabeza = (
        f"{resumen['escenario']}: n={resumen['n']} ok={resumen['ok']} "
        f"errores={resumen['errores'] or 'ninguno'} "
        f"throughput={resumen['throughput']:.2f}/s en {resumen['duracion_s']} s"
    )
    if resumen["p50_ms"] is None:
        return f"{cabeza} (sin respuestas 2xx)"
    return (
        f"{cabeza} | p50={resumen['p50_ms']:.1f} ms p95={resumen['p95_ms']:.1f} ms "
        f"p99={resumen['p99_ms']:.1f} ms max={resumen['max_ms']:.1f} ms"
    )


# --- Escenarios ----------------------------------------------------------------------------------


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def escenario_valor(
    cliente: httpx.AsyncClient,
    claves: list[Clave],
    secret_id: str,
    *,
    clientes: int,
    duracion_s: float,
) -> dict[str, Any]:
    """``GET /secrets/{id}/value`` con un PAT por clave; el cliente ``k`` usa las claves
    ``k, k + C, …``. El cuerpo (con el valor) se descarta sin leerlo más allá de httpx."""

    async def pedir(pat: str) -> int:
        respuesta = await cliente.get(f"/secrets/{secret_id}/value", headers=_bearer(pat))
        return respuesta.status_code

    asignacion = [claves[k::clientes] for k in range(clientes)]
    nombre = f"value C={clientes} A={len(claves)}"
    return await correr(nombre, asignacion, pedir, duracion_s)


async def escenario_login(
    cliente: httpx.AsyncClient,
    ip: Ritmo,
    email: str,
    password: str,
    *,
    clientes: int,
    duracion_s: float,
) -> dict[str, Any]:
    """``POST /auth/login`` con ``clientes`` concurrentes que comparten el ``Ritmo`` de la IP.
    El access token y la cookie de refresh de cada respuesta se descartan."""

    async def pedir(_: None) -> int:
        respuesta = await cliente.post("/auth/login", json={"email": email, "password": password})
        cliente.cookies.clear()
        return respuesta.status_code

    clave = Clave(ip)
    return await correr(f"login C={clientes}", [[clave]] * clientes, pedir, duracion_s)


async def escenario_rotar(
    cliente: httpx.AsyncClient, claves: list[Clave], secret_id: str, *, duracion_s: float
) -> dict[str, Any]:
    """``POST /secrets/{id}/rotate`` con un actor humano por clave (un PAT no puede rotar: solo
    tiene ``secrets:read``). Cada valor nuevo sale de ``secrets`` y nunca se imprime."""

    async def pedir(token: str) -> int:
        cuerpo = {"new_value": f"carga-no-es-real-{secrets.token_hex(16)}"}
        respuesta = await cliente.post(
            f"/secrets/{secret_id}/rotate", json=cuerpo, headers=_bearer(token)
        )
        return respuesta.status_code

    nombre = f"rotate C={len(claves)}"
    return await correr(nombre, [[c] for c in claves], pedir, duracion_s)


async def demostrar_429(
    cliente: httpx.AsyncClient, pat: str, secret_id: str, *, peticiones: int = 65
) -> dict[str, Any]:
    """Sin ``Ritmo``: ``peticiones`` lecturas concurrentes con un mismo PAT. Con el límite de
    60/min se esperan 60 respuestas 200 y el resto 429 con ``Retry-After`` (spec §7)."""

    async def pedir() -> httpx.Response:
        return await cliente.get(f"/secrets/{secret_id}/value", headers=_bearer(pat))

    respuestas = await asyncio.gather(*(pedir() for _ in range(peticiones)))
    codigos = Counter(str(r.status_code) for r in respuestas)
    retry_after = sorted(
        {int(r.headers["Retry-After"]) for r in respuestas if r.status_code == 429}
    )
    return {
        "escenario": "límite /value sin ritmo",
        "peticiones": peticiones,
        "codigos": dict(sorted(codigos.items())),
        "retry_after": retry_after,
    }


def formatear_429(resultado: dict[str, Any]) -> str:
    return (
        f"{resultado['escenario']}: {resultado['peticiones']} peticiones -> "
        f"códigos {resultado['codigos']}, Retry-After {resultado['retry_after']} s"
    )


# --- Preparación ---------------------------------------------------------------------------------


def leer_entorno_e2e(ruta: Path) -> dict[str, str]:
    """Solo ``SEED_PASSWORD_ADMIN`` y ``SEED_PASSWORD_LIDER`` del ``e2e.env`` generado por
    ``generate_e2e_env.py``; el resto del archivo (KEK, clave JWT) ni se guarda."""
    buscadas = {"SEED_PASSWORD_ADMIN", "SEED_PASSWORD_LIDER"}
    encontradas = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        nombre, _, valor = linea.partition("=")
        if nombre.strip() in buscadas:
            encontradas[nombre.strip()] = valor.strip()
    return encontradas


def _contrasena(variables: dict[str, str], nombre: str, email: str) -> str:
    return variables.get(nombre) or os.environ.get(nombre) or getpass.getpass(f"{email}: ")


def _exigir(respuesta: httpx.Response, esperado: int, que: str) -> httpx.Response:
    """Aborta con el código HTTP si la preparación falla; nunca muestra el cuerpo."""
    if respuesta.status_code != esperado:
        raise SystemExit(f"error: {que} respondió {respuesta.status_code}")
    return respuesta


async def _login(cliente: httpx.AsyncClient, ip: Ritmo, email: str, password: str) -> str:
    await ip.esperar()
    respuesta = await cliente.post("/auth/login", json={"email": email, "password": password})
    cliente.cookies.clear()
    return str(_exigir(respuesta, 200, f"login de {email}").json()["access_token"])


@dataclass
class Preparado:
    secreto_lectura: str
    secreto_rotacion: str
    pats: list[str]
    pat_limite: str


async def preparar(cliente: httpx.AsyncClient, admin: Clave, apps: int) -> Preparado:
    """Con el token del Administrador (``admin.dato``) y su ``Ritmo`` de 100/min: localiza el
    proyecto y el ambiente del seed, crea ``CARGA_ROTACION`` y ``apps + 1`` Aplicaciones
    Cliente de ``development`` (la última solo para la demostración del 429)."""

    async def pedir(metodo: str, ruta: str, esperado: int, cuerpo: Any = None) -> Any:
        await admin.ritmo.esperar()
        respuesta = await cliente.request(metodo, ruta, json=cuerpo, headers=_bearer(admin.dato))
        return _exigir(respuesta, esperado, f"{metodo} {ruta}").json()

    proyecto = next(p for p in await pedir("GET", "/projects", 200) if p["name"] == PROYECTO)
    pid = proyecto["id"]
    ambientes = await pedir("GET", f"/projects/{pid}/environments", 200)
    eid = next(a["id"] for a in ambientes if a["name"] == AMBIENTE)
    coleccion = f"/projects/{pid}/environments/{eid}/secrets"
    existentes = {s["name"]: s["id"] for s in await pedir("GET", coleccion, 200)}
    lectura = existentes[SECRETO_LECTURA]
    rotacion = existentes.get(SECRETO_ROTACION)  # se reutiliza si una corrida previa lo creó
    if rotacion is None:
        valor = f"carga-no-es-real-{secrets.token_hex(16)}"
        cuerpo = {"name": SECRETO_ROTACION, "value": valor}
        rotacion = (await pedir("POST", coleccion, 201, cuerpo))["id"]

    vence = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    corrida = secrets.token_hex(3)  # nombres distintos en cada corrida
    pats = []
    for i in range(apps + 1):
        nombre = f"carga-{corrida}-{i:03d}"
        cuerpo = {"name": nombre, "environment_id": eid, "expires_at": vence}
        creada = await pedir("POST", f"/projects/{pid}/service-accounts", 201, cuerpo)
        pats.append(str(creada["token"]))
        print(f"\r  Aplicaciones Cliente creadas: {i + 1}/{apps + 1}", end="", flush=True)
    print()
    return Preparado(lectura, rotacion, pats[:apps], pats[apps])


# --- Programa ------------------------------------------------------------------------------------


ESCENARIOS = ("valor", "login", "rotar", "mixto", "limite")


async def _principal(args: argparse.Namespace) -> list[dict[str, Any]]:
    variables = leer_entorno_e2e(args.entorno_e2e) if args.entorno_e2e else {}
    pass_admin = _contrasena(variables, "SEED_PASSWORD_ADMIN", ADMIN)
    pass_lider = _contrasena(variables, "SEED_PASSWORD_LIDER", LIDER)
    resultados: list[dict[str, Any]] = []

    def anotar(resultado: dict[str, Any], texto: str) -> None:
        resultados.append(resultado)
        print(f"  {texto}", flush=True)

    limites = httpx.Limits(max_connections=100, max_keepalive_connections=100)
    async with httpx.AsyncClient(base_url=args.base, timeout=30, limits=limites) as cliente:
        ip = Ritmo(args.limite_login)  # una sola IP para todos los logins
        print("Preparación (login, secreto de rotación y Aplicaciones Cliente)...")
        admin = Clave(Ritmo(LIMITE_GENERAL), await _login(cliente, ip, ADMIN, pass_admin))
        lider = Clave(Ritmo(LIMITE_GENERAL), await _login(cliente, ip, LIDER, pass_lider))
        listo = await preparar(cliente, admin, args.apps)
        pats = claves_de(listo.pats, LIMITE_VALOR)  # el Ritmo de cada PAT dura toda la corrida

        if "valor" in args.escenarios:
            print("GET /secrets/{id}/value (PAT)...")
            for c in sorted({max(1, args.apps // 5), max(1, args.apps // 2)}):
                r = await escenario_valor(
                    cliente,
                    pats[: 2 * c],
                    listo.secreto_lectura,
                    clientes=c,
                    duracion_s=args.duracion,
                )
                anotar(r, formatear(r))
        if "login" in args.escenarios:
            print("POST /auth/login...")
            for c in (1, 4):
                r = await escenario_login(
                    cliente, ip, LIDER, pass_lider, clientes=c, duracion_s=args.duracion_login
                )
                anotar(r, formatear(r))
        if "rotar" in args.escenarios:
            print("POST /secrets/{id}/rotate...")
            r = await escenario_rotar(
                cliente, [admin, lider], listo.secreto_rotacion, duracion_s=args.duracion
            )
            anotar(r, formatear(r))
        if "mixto" in args.escenarios:
            print("Mixto: value con logins concurrentes...")
            c = max(1, args.apps // 5)
            solo, con_login = await asyncio.gather(
                escenario_valor(
                    cliente,
                    pats[: 2 * c],
                    listo.secreto_lectura,
                    clientes=c,
                    duracion_s=args.duracion_login,
                ),
                escenario_login(
                    cliente, ip, LIDER, pass_lider, clientes=4, duracion_s=args.duracion_login
                ),
            )
            solo["escenario"] += " (con logins)"
            con_login["escenario"] += " (con value)"
            anotar(solo, formatear(solo))
            anotar(con_login, formatear(con_login))
        if "limite" in args.escenarios:
            print("Límite de tasa sin ritmo...")
            r = await demostrar_429(cliente, listo.pat_limite, listo.secreto_lectura)
            anotar(r, formatear_429(r))
    return resultados


def main() -> None:
    parser = argparse.ArgumentParser(description="Prueba de carga básica (solo desarrollo).")
    parser.add_argument("--base", default="http://localhost:8180/api/v1", help="URL de /api/v1")
    parser.add_argument("--entorno-e2e", type=Path, help="e2e.env generado (contraseñas del seed)")
    parser.add_argument("--apps", type=int, default=50, help="Aplicaciones Cliente (PAT) a crear")
    parser.add_argument("--duracion", type=float, default=60, help="T de value y rotate (s)")
    parser.add_argument("--duracion-login", type=float, default=30, help="T de login (s)")
    parser.add_argument(
        "--limite-login",
        type=int,
        default=LIMITE_LOGIN_CAP6,
        help="límite de login por IP del servidor (600 en el stack E2E, H-56)",
    )
    parser.add_argument(
        "--escenarios",
        default=",".join(ESCENARIOS),
        help=f"subconjunto de {','.join(ESCENARIOS)} (recorte 3: valor)",
    )
    parser.add_argument("--json", type=Path, help="guarda los resúmenes (sin tokens ni valores)")
    args = parser.parse_args()
    args.escenarios = {e.strip() for e in args.escenarios.split(",")}
    if desconocidos := args.escenarios - set(ESCENARIOS):
        parser.error(f"escenarios desconocidos: {sorted(desconocidos)}")

    print("carga: solo para desarrollo; crea Aplicaciones Cliente y rotaciones en la BD destino.")
    inicio = datetime.now(UTC)
    resultados = asyncio.run(_principal(args))
    if args.json:
        informe = {
            "inicio": inicio.isoformat(timespec="seconds"),
            "cliente": {"plataforma": platform.platform(), "cpus_logicas": os.cpu_count()},
            "parametros": {
                "base": args.base,
                "apps": args.apps,
                "duracion_s": args.duracion,
                "duracion_login_s": args.duracion_login,
                "limite_login": args.limite_login,
            },
            "resultados": resultados,
        }
        texto = json.dumps(informe, ensure_ascii=False, indent=2) + "\n"
        args.json.write_text(texto, encoding="utf-8", newline="\n")  # LF también en Windows
        print(f"Resúmenes en {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
