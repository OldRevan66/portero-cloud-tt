"""Genera el par de llaves Ed25519 de la firma diaria del cierre de la bitácora (H-81).

Uso (desde ``backend/``)::

    uv run python scripts/generate_oplog_key.py

Imprime dos líneas listas para pegar, con los saltos de línea del PEM escapados como ``\\n``:

- ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY``: va en el ``.env`` de la API, que verifica las firmas.
- ``PORTERO_OPLOG_SIGNING_PRIVATE_KEY``: solo para la tarea programada que ejecuta
  ``python -m portero.cli sign-chain``. **No** va en el ``.env``: ``docker-compose.yml`` lo carga
  completo en el contenedor de la API.

Es una llave distinta de la del JWT (NIST SP 800-57 Pt. 1 §5.2, un propósito por llave). No
escribe ningún archivo.
"""

import sys

from portero.crypto.signing import (
    generate_private_key_pem,
    load_ed25519_private_key_pem,
    public_key_pem,
)

PRIVATE_VARIABLE = "PORTERO_OPLOG_SIGNING_PRIVATE_KEY"
PUBLIC_VARIABLE = "PORTERO_OPLOG_SIGNING_PUBLIC_KEY"


def env_line(variable: str, pem: bytes) -> str:
    """``VARIABLE="..."`` en una línea, con ``\\n`` escapados."""
    return f'{variable}="' + pem.decode("ascii").replace("\n", "\\n") + '"'


def main() -> None:
    privada = generate_private_key_pem()
    publica = public_key_pem(load_ed25519_private_key_pem(privada, PRIVATE_VARIABLE).public_key())
    print(env_line(PRIVATE_VARIABLE, privada))
    print(env_line(PUBLIC_VARIABLE, publica))
    print(
        f"# {PUBLIC_VARIABLE} va en el .env de la API. {PRIVATE_VARIABLE} es la llave privada:\n"
        "# no la pongas en el .env ni la subas a Git; dásela solo a la tarea de sign-chain.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
