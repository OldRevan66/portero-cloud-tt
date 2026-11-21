"""Genera una clave privada Ed25519 para firmar JWT (spec §3.2; Cap. 6 §Estructura del JWT).

Uso (desde ``backend/``)::

    uv run python scripts/generate_jwt_key.py

Imprime en la salida estándar una sola línea lista para pegar en el ``.env``, con los saltos de
línea del PEM escapados como ``\\n`` (python-dotenv los expande dentro de comillas dobles). No
escribe ningún archivo: la clave solo existe en la terminal hasta que la pegas.

Cambiar la clave invalida todos los tokens emitidos con la anterior (Cap. 6 §Revocación,
"operación de emergencia").
"""

import sys

from portero.crypto.signing import generate_private_key_pem


def env_line(pem: bytes) -> str:
    """``PORTERO_JWT_PRIVATE_KEY="..."`` en una línea, con ``\\n`` escapados."""
    return 'PORTERO_JWT_PRIVATE_KEY="' + pem.decode("ascii").replace("\n", "\\n") + '"'


def main() -> None:
    print(env_line(generate_private_key_pem()))
    print(
        "# Pega la línea anterior en tu .env. Es la clave privada: no la subas a Git.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
