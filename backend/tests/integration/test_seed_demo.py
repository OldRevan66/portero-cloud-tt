"""``scripts/seed_demo.py`` contra db-test (dentro de la transacción que se revierte).

Fija que los datos se crean por los servicios (con su bitácora íntegra), que el PAT y las
contraseñas generadas se imprimen una sola vez, que ningún valor de secreto sale por la terminal
y que el script se niega a correr sobre una BD con datos.
"""

import importlib.util
import secrets
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.passwords import verify_password
from portero.config import Settings
from portero.db.models import AuditLog, Project, Secret, SecretVersion, ServiceAccount, User
from portero.oplog.service import OperationLogService

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"


def _cargar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("seed_demo", SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


async def _contar(session: AsyncSession, modelo: type) -> int:
    return await session.scalar(select(func.count()).select_from(modelo)) or 0


async def test_siembra_la_demo_y_no_repite(
    db_session: AsyncSession, settings_app: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_demo = _cargar_script()
    if await _contar(db_session, User) or await _contar(db_session, Project):
        pytest.skip("db-test tiene datos confirmados; el script exige una BD vacía")

    assert await seed_demo.seed(db_session, settings_app, seed_demo._generate) == 0

    salida = capsys.readouterr().out
    assert await _contar(db_session, User) == 3
    assert await _contar(db_session, Project) == 1
    assert await _contar(db_session, Secret) == 5
    assert await _contar(db_session, SecretVersion) == 6  # cinco versiones 1 y una rotación
    cuenta = await db_session.scalar(select(ServiceAccount))
    assert cuenta is not None
    assert salida.count(cuenta.token_prefix) == 1  # el PAT completo, una sola vez (H-42)
    for _, _, valor in seed_demo.SECRETS + [seed_demo.ROTATION]:
        assert valor not in salida
    verbos = set((await db_session.scalars(select(AuditLog.verb))).all())
    assert {"create_user", "assign_role", "create_project", "create_secret"} <= verbos
    assert {"rotate_secret", "create_service_account"} <= verbos
    assert (await OperationLogService().verify_chain(db_session)).ok

    assert await seed_demo.seed(db_session, settings_app, seed_demo._generate) == 1
    assert "ya tiene usuarios o proyectos" in capsys.readouterr().out
    assert await _contar(db_session, User) == 3


# --- Modo no interactivo para el stack E2E (H-57) ------------------------------------------------

VARIABLES = ("SEED_PASSWORD_ADMIN", "SEED_PASSWORD_LIDER", "SEED_PASSWORD_DEV")


async def test_contrasenas_del_entorno_sin_imprimir_contrasenas_ni_pat(
    db_session: AsyncSession,
    settings_app: Settings,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El orquestador de E2E genera las contraseñas y las pasa por el entorno; el seed no las
    imprime, ni tampoco el PAT: la salida del contenedor queda en los logs de CI."""
    seed_demo = _cargar_script()
    if await _contar(db_session, User) or await _contar(db_session, Project):
        pytest.skip("db-test tiene datos confirmados; el script exige una BD vacía")
    contrasenas = {variable: secrets.token_urlsafe(18) for variable in VARIABLES}
    for variable, valor in contrasenas.items():
        monkeypatch.setenv(variable, valor)

    assert await seed_demo.seed(db_session, settings_app, seed_demo._from_env) == 0

    salida = capsys.readouterr()
    texto = salida.out + salida.err
    cuenta = await db_session.scalar(select(ServiceAccount))
    assert cuenta is not None
    assert cuenta.token_prefix not in texto
    for valor in contrasenas.values():
        assert valor not in texto
    usuarios = {u.email: u for u in (await db_session.scalars(select(User))).all()}
    for (email, _), variable in zip(
        (seed_demo.ADMIN, seed_demo.LIDER, seed_demo.DEV), VARIABLES, strict=True
    ):
        assert verify_password(usuarios[email].password_hash, contrasenas[variable])


async def test_si_falta_una_contrasena_del_entorno_no_crea_nada(
    db_session: AsyncSession,
    settings_app: Settings,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_demo = _cargar_script()
    if await _contar(db_session, User) or await _contar(db_session, Project):
        pytest.skip("db-test tiene datos confirmados; el script exige una BD vacía")
    monkeypatch.setenv("SEED_PASSWORD_ADMIN", secrets.token_urlsafe(18))
    monkeypatch.setenv("SEED_PASSWORD_LIDER", secrets.token_urlsafe(18))
    monkeypatch.delenv("SEED_PASSWORD_DEV", raising=False)

    assert await seed_demo.seed(db_session, settings_app, seed_demo._from_env) == 2

    assert "SEED_PASSWORD_DEV" in capsys.readouterr().out
    assert await _contar(db_session, User) == 0
    assert await _contar(db_session, Project) == 0
