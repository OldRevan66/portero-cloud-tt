"""Prueba de ``scripts/generate_e2e_env.py``: el archivo de entorno del stack E2E (H-57) se genera
al vuelo, con valores aleatorios que nunca se imprimen ni se versionan."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from dotenv import dotenv_values

from portero.crypto.signing import JwtSigner

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_e2e_env.py"
CLAVES = {
    "POSTGRES_PASSWORD",
    "PORTERO_KEK_PASSPHRASE",
    "PORTERO_JWT_PRIVATE_KEY",
    "SEED_PASSWORD_ADMIN",
    "SEED_PASSWORD_LIDER",
    "SEED_PASSWORD_DEV",
}


def _cargar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_e2e_env", SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_genera_todas_las_variables_sin_imprimirlas(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ruta = tmp_path / "e2e.env"

    assert _cargar_script().main([str(ruta)]) == 0

    valores = dotenv_values(ruta)
    assert set(valores) == CLAVES
    salida = capsys.readouterr()
    for clave, valor in valores.items():
        assert valor, clave
        assert valor not in salida.out + salida.err
    pem = valores["PORTERO_JWT_PRIVATE_KEY"]
    assert pem is not None
    JwtSigner.from_pem(pem.encode())  # PEM Ed25519 que el Motor Criptográfico acepta
    for clave in CLAVES - {"PORTERO_JWT_PRIVATE_KEY"}:
        assert len(valores[clave] or "") >= 24  # 18 bytes del CSPRNG; política de 12 a 128


def test_cada_corrida_genera_valores_distintos(tmp_path: Path) -> None:
    script = _cargar_script()
    script.main([str(tmp_path / "a.env")])
    script.main([str(tmp_path / "b.env")])

    a, b = dotenv_values(tmp_path / "a.env"), dotenv_values(tmp_path / "b.env")
    for clave in CLAVES:
        assert a[clave] != b[clave], clave


def test_no_sobrescribe_un_archivo_existente(tmp_path: Path) -> None:
    ruta = tmp_path / "e2e.env"
    ruta.write_text("NO_TOCAR=1\n", encoding="utf-8")

    assert _cargar_script().main([str(ruta)]) != 0
    assert ruta.read_text(encoding="utf-8") == "NO_TOCAR=1\n"
