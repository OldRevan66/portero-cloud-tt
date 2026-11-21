"""Prueba de ``scripts/generate_oplog_key.py`` (H-81): imprime la llave privada y la pública de la
firma del cierre en dos líneas para ``.env``; las dos llegan a ``Settings`` y forman un par."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from portero.config import Settings
from portero.crypto.signing import (
    load_ed25519_private_key_pem,
    load_ed25519_public_key_pem,
    public_key_thumbprint,
)

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_oplog_key.py"


def _cargar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_oplog_key", SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_las_dos_lineas_forman_un_par_valido(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for nombre in ("PORTERO_OPLOG_SIGNING_PRIVATE_KEY", "PORTERO_OPLOG_SIGNING_PUBLIC_KEY"):
        monkeypatch.delenv(nombre, raising=False)
    _cargar_script().main()
    privada, publica = capsys.readouterr().out.strip().splitlines()

    assert privada.startswith('PORTERO_OPLOG_SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n')
    assert publica.startswith('PORTERO_OPLOG_SIGNING_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\\n')

    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "PORTERO_DATABASE_URL=postgresql+asyncpg://x@localhost/x",
                "PORTERO_KEK_PASSPHRASE=marcador-de-prueba",
                "PORTERO_JWT_PRIVATE_KEY=marcador-de-prueba",
                "PORTERO_JWT_ISSUER=https://portero.example.test",
                privada,
                publica,
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.oplog_signing_private_key is not None
    assert settings.oplog_signing_public_key is not None

    llave = load_ed25519_private_key_pem(
        settings.oplog_signing_private_key.get_secret_value().encode(), "privada"
    )
    verificadora = load_ed25519_public_key_pem(
        settings.oplog_signing_public_key.encode(), "publica"
    )
    assert public_key_thumbprint(llave.public_key()) == public_key_thumbprint(verificadora)


def test_el_aviso_dice_que_la_privada_no_va_en_el_env_de_la_api(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``docker-compose.yml`` carga todo el ``.env`` en el contenedor de la API: si la llave
    privada estuviera ahí, quien comprometa la API podría volver a firmar (H-81)."""
    _cargar_script().main()
    aviso = capsys.readouterr().err

    assert "PORTERO_OPLOG_SIGNING_PRIVATE_KEY" in aviso
    assert "no la pongas en el .env" in aviso
