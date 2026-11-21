"""Genera el archivo de entorno del stack E2E (H-57; Cap. 6 §Pruebas end-to-end del Dashboard).

Uso (desde ``backend/``; lo llama ``npm run e2e``, no hace falta correrlo a mano)::

    uv run python scripts/generate_e2e_env.py ../frontend/e2e/.generado/e2e.env

Escribe, con valores nuevos en cada corrida, la contraseña de PostgreSQL, la passphrase de la KEK,
la clave privada Ed25519 de los JWT y las contraseñas de los tres usuarios del seed. Así el
repositorio no guarda ningún secreto del stack E2E y dos corridas nunca comparten credenciales.

- Valores aleatorios con ``secrets`` (CSPRNG del sistema operativo) y la clave con
  ``generate_private_key_pem`` del Motor Criptográfico, la misma de ``generate_jwt_key.py``.
- El archivo se crea con permisos 0600 y nunca sobrescribe uno existente (``O_EXCL``): si quedó
  uno de una corrida interrumpida, el orquestador lo borra antes.
- No imprime ningún valor. El archivo vive en una ruta ignorada por Git y el orquestador lo borra
  al bajar el stack.
"""

import argparse
import importlib.util
import os
import secrets
import sys
from pathlib import Path
from types import ModuleType

from portero.crypto.signing import generate_private_key_pem

RANDOM_VARIABLES = (
    "POSTGRES_PASSWORD",
    "PORTERO_KEK_PASSPHRASE",
    "SEED_PASSWORD_ADMIN",
    "SEED_PASSWORD_LIDER",
    "SEED_PASSWORD_DEV",
)
"""Variables con un valor aleatorio de 24 caracteres URL-safe (18 bytes; cumple la política de
contraseñas del Cap. 6, de 12 a 128 caracteres, y no necesita comillas en el archivo)."""


def _jwt_key_script() -> ModuleType:
    """``generate_jwt_key.py`` (hermano de este archivo), para reutilizar ``env_line``."""
    path = Path(__file__).resolve().with_name("generate_jwt_key.py")
    spec = importlib.util.spec_from_file_location("generate_jwt_key", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"no se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render() -> str:
    """Contenido del archivo: ``NOMBRE=valor`` por línea y la clave PEM con ``\\n`` escapados."""
    lines = ["# Generado por scripts/generate_e2e_env.py para el stack E2E. Desechable."]
    lines += [f"{name}={secrets.token_urlsafe(18)}" for name in RANDOM_VARIABLES]
    lines.append(_jwt_key_script().env_line(generate_private_key_pem()))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Escribe el archivo en la ruta recibida. Devuelve el código de salida."""
    parser = argparse.ArgumentParser(description="Entorno desechable del stack E2E.")
    parser.add_argument("ruta", type=Path, help="archivo a crear (ruta ignorada por Git)")
    args = parser.parse_args(argv)
    try:
        fd = os.open(args.ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"error: {args.ruta} ya existe; bórralo antes", file=sys.stderr)
        return 1
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as archivo:
        archivo.write(render())
    print(f"Entorno E2E escrito en {args.ruta}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
