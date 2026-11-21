"""Prueba de ``scripts/generate_jwt_key.py``: la línea que imprime, pegada en un ``.env``, llega
a ``Settings`` como un PEM que el Motor Criptográfico acepta (spec §3.2)."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from portero.config import Settings
from portero.crypto.signing import JwtSigner

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_jwt_key.py"


def _cargar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_jwt_key", SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_la_linea_impresa_funciona_en_un_env(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for nombre in ("PORTERO_JWT_PRIVATE_KEY", "PORTERO_JWT_ISSUER"):
        monkeypatch.delenv(nombre, raising=False)
    _cargar_script().main()
    salida = capsys.readouterr()
    linea = salida.out.strip()

    assert linea.startswith('PORTERO_JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n')
    assert "\n" not in linea  # una sola línea, con \n escapados

    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "PORTERO_DATABASE_URL=postgresql+asyncpg://x@localhost/x",
                "PORTERO_KEK_PASSPHRASE=marcador-de-prueba",
                "PORTERO_JWT_ISSUER=https://portero.example.test",
                linea,
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]

    pem = settings.jwt_private_key.get_secret_value().encode()
    assert JwtSigner.from_pem(pem).kid


def test_cada_ejecucion_genera_una_clave_distinta(capsys: pytest.CaptureFixture[str]) -> None:
    modulo = _cargar_script()
    modulo.main()
    modulo.main()
    a, b = capsys.readouterr().out.strip().splitlines()

    assert a != b
