"""Ejemplo para la demo: una Aplicación Cliente lee un secreto con su PAT (CU-04).

Uso (desde ``sdk/``)::

    $env:PORTERO_BASE_URL = "http://localhost:8000"; $env:PORTERO_TOKEN = "<PAT>"
    uv run python examples/leer_secreto.py --proyecto "Tienda en línea" \\
        --ambiente development --nombre DB_PASSWORD

El token llega por una variable de entorno, como recomienda el Cap. 6 §Manejo de credenciales del
cliente; nunca por argumento (quedaría en el historial de la terminal y en la lista de procesos).
El valor se imprime **enmascarado**; ``--mostrar`` lo imprime completo solo si es un valor de
demostración (prefijo ``demo-no-es-real-``), para no exhibir un secreto real en pantalla.
Ante cualquier error imprime un mensaje en español y sale con un código distinto de cero.
"""

from __future__ import annotations

import argparse
import os
import sys

from portero_cloud_sdk import (
    AuthenticationError,
    NetworkError,
    PermissionDenied,
    PorteroClient,
    PorteroError,
    RateLimited,
    SecretNotFound,
    ServerError,
)

PREFIJO_DEMO = "demo-no-es-real-"
MASCARA = "********"


def _argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lee un secreto de Portero Cloud con un PAT.")
    parser.add_argument("--proyecto", required=True, help="nombre del proyecto")
    parser.add_argument("--ambiente", required=True, help="nombre del ambiente, p. ej. development")
    parser.add_argument("--nombre", required=True, help="nombre del secreto, p. ej. DB_PASSWORD")
    parser.add_argument(
        "--mostrar",
        action="store_true",
        help=f"imprime el valor completo (solo valores que empiezan con {PREFIJO_DEMO})",
    )
    return parser.parse_args()


def _error(mensaje: str, codigo: int) -> int:
    print(f"Error: {mensaje}", file=sys.stderr)
    return codigo


def main() -> int:
    args = _argumentos()
    base_url = os.environ.get("PORTERO_BASE_URL")
    token = os.environ.get("PORTERO_TOKEN")
    if not base_url or not token:
        return _error("defina PORTERO_BASE_URL y PORTERO_TOKEN en el entorno.", 2)

    try:
        with PorteroClient(base_url=base_url, token=token) as client:
            client.validate()
            secreto = client.get_secret(args.proyecto, args.ambiente, args.nombre)
            valor = client.get_secret_value(args.proyecto, args.ambiente, args.nombre)
    except ValueError as exc:  # token o URL mal configurados; el mensaje no incluye el token
        return _error(f"configuración inválida: {exc}.", 2)
    except AuthenticationError:
        return _error("el token es inválido, expiró o la Aplicación Cliente fue revocada.", 3)
    except SecretNotFound:
        return _error("el secreto no existe o está fuera del alcance de este token.", 4)
    except PermissionDenied:
        return _error("el token no tiene permiso para leer este secreto.", 4)
    except RateLimited as exc:
        espera = f" Reintente en {exc.retry_after:.0f} s." if exc.retry_after else ""
        return _error(f"demasiadas solicitudes.{espera}", 5)
    except NetworkError:
        return _error(f"no se pudo conectar con Portero Cloud en {base_url}.", 6)
    except ServerError as exc:
        return _error(f"error del servidor (trace_id={exc.trace_id}).", 7)
    except PorteroError as exc:
        return _error(f"respuesta inesperada de Portero Cloud: {exc}", 1)

    print(f"Secreto: {secreto.name}")
    print(f"Versión: {secreto.version}")
    if not args.mostrar:
        print(f"Valor:   {MASCARA}  (use --mostrar con valores de demostración)")
    elif valor.startswith(PREFIJO_DEMO):
        print(f"Valor:   {valor}")
    else:
        print(f"Valor:   {MASCARA}  (--mostrar solo imprime valores {PREFIJO_DEMO}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
