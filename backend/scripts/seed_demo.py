"""Datos de demostración para el Dashboard y la presentación. **Solo para desarrollo.**

Uso (desde ``backend/``, con la API detenida y la BD de desarrollo vacía)::

    uv run python scripts/seed_demo.py            # pide las contraseñas con getpass
    uv run python scripts/seed_demo.py --generar  # las genera con ``secrets`` y las imprime
    python scripts/seed_demo.py --contrasenas-del-entorno   # stack E2E (H-57), sin imprimir

Crea, siempre a través de los servicios (así cada paso queda en la bitácora con su cadena de
hashes, igual que si se hiciera por la API):

- Administrador ``admin@tienda.example`` (con ``cli.create_admin``, H-38), Líder Técnico
  ``lider@tienda.example`` (todo el proyecto) y Desarrollador ``dev@tienda.example`` (solo
  ``development``).
- El proyecto "Tienda en línea" con sus ambientes ``development``, ``staging`` y
  ``production`` (RF-031).
- Cinco secretos con valores **obviamente falsos** (prefijo ``demo-no-es-real-``) y una rotación.
- Una Aplicación Cliente de ``development`` cuyo PAT se imprime **una sola vez** (H-21).

Se niega a correr si la BD ya tiene usuarios o proyectos: nunca mezcla datos de demo con datos
reales. Las contraseñas tecleadas no se imprimen; las generadas (``--generar``) sí, una sola vez,
porque de otro modo nadie podría entrar. Con ``--contrasenas-del-entorno`` (stack E2E, H-57) las
contraseñas llegan en ``SEED_PASSWORD_ADMIN``, ``SEED_PASSWORD_LIDER`` y ``SEED_PASSWORD_DEV``
(las genera el orquestador de Playwright, que ya las conoce) y no se imprime ni una contraseña ni
el PAT: la salida del contenedor termina en los logs de CI. Las operaciones las registra como
``cli:seed-demo`` con el id del Administrador (es quien queda como ``created_by``).

Si falla a la mitad, borra la BD de desarrollo (``docker compose down -v``), aplica la migración
y vuelve a correrlo: cada servicio confirma su propia transacción.
"""

import argparse
import asyncio
import getpass
import os
import secrets
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.service import AuthService
from portero.cli import create_admin
from portero.config import Settings
from portero.crypto.engine import CryptoEngine
from portero.crypto.signing import JwtSigner
from portero.db.session import create_engine, create_sessionmaker
from portero.management.environments import EnvironmentService
from portero.management.projects import ProjectService
from portero.management.service_accounts import ServiceAccountService
from portero.management.users import UserService
from portero.oplog.service import OperationActor
from portero.rbac.permissions import Role
from portero.secrets_mgmt.kek_store import load_key_manager
from portero.secrets_mgmt.service import SecretService

ACTOR_REF = "cli:seed-demo"
PROJECT_NAME = "Tienda en línea"
ADMIN = ("admin@tienda.example", "Administración Demo")
LIDER = ("lider@tienda.example", "Líder Demo")
DEV = ("dev@tienda.example", "Desarrollo Demo")

SECRETS = [
    ("development", "DB_PASSWORD", "demo-no-es-real-db-password-dev"),
    ("development", "PAYMENTS_API_KEY", "demo-no-es-real-sk_test_000000000000"),
    ("development", "JWT_SIGNING_SECRET", "demo-no-es-real-jwt-signing-secret"),
    ("staging", "DB_PASSWORD", "demo-no-es-real-db-password-staging"),
    ("production", "SMTP_PASSWORD", "demo-no-es-real-smtp-password"),
]
"""(ambiente, nombre, valor). Valores de ejemplo, no secretos: el prefijo lo deja claro."""

ROTATION = ("development", "DB_PASSWORD", "demo-no-es-real-db-password-dev-v2")

PasswordSource = Callable[[str], str]

ENV_PASSWORDS = {
    ADMIN[0]: "SEED_PASSWORD_ADMIN",
    LIDER[0]: "SEED_PASSWORD_LIDER",
    DEV[0]: "SEED_PASSWORD_DEV",
}
"""Variable de entorno de cada usuario en ``--contrasenas-del-entorno``. Sin prefijo
``PORTERO_``: no son configuración del sistema y ``Settings`` nunca las ve."""


def _ask(email: str) -> str:
    """Contraseña tecleada dos veces con ``getpass`` (nunca como argumento: quedaría en el
    historial del shell)."""
    password = getpass.getpass(f"Contraseña para {email}: ")
    if getpass.getpass("Confírmala: ") != password:
        raise SystemExit("error: las contraseñas no coinciden")
    return password


def _generate(email: str) -> str:
    """Contraseña aleatoria de 24 caracteres URL-safe (``secrets``, CSPRNG; cumple la política
    del Cap. 6: 12 a 128 caracteres)."""
    return secrets.token_urlsafe(18)


def _from_env(email: str) -> str:
    """Contraseña tomada del entorno (stack E2E, H-57). ``KeyError`` con el nombre de la
    variable si falta; ``seed`` lo convierte en el código de salida 2 antes de crear nada."""
    return os.environ[ENV_PASSWORDS[email]]


async def _is_empty(session: AsyncSession) -> bool:
    users = await UserService().list_users(session)
    projects = await ProjectService().list_projects(session, None)
    return not users and not projects


async def _user_id_by_email(session: AsyncSession, email: str) -> UUID:
    return next(u.id for u in await UserService().list_users(session) if u.email == email)


async def seed(session: AsyncSession, settings: Settings, password_for: PasswordSource) -> int:
    """Crea los datos de demo. Devuelve el código de salida."""
    if not await _is_empty(session):
        print("error: la BD ya tiene usuarios o proyectos; seed_demo solo corre en una BD vacía")
        return 1
    generated = password_for is _generate
    from_env = password_for is _from_env
    try:
        passwords = {email: password_for(email) for email, _ in (ADMIN, LIDER, DEV)}
    except KeyError as missing:
        print(f"error: falta la variable de entorno {missing.args[0]}")
        return 2

    # 1. Administrador (H-38): el mismo camino que ``portero.cli create-admin``.
    if await create_admin(session, ADMIN[0], read_password=lambda _: passwords[ADMIN[0]]) != 0:
        return 1
    actor = OperationActor("human", ACTOR_REF, await _user_id_by_email(session, ADMIN[0]))

    # 2. Proyecto con sus tres ambientes (RF-031).
    projects = ProjectService()
    project_id = (
        await projects.create_project(
            session, actor, name=PROJECT_NAME, description="Proyecto de demostración"
        )
    ).id
    environments = {
        e.name: e.id for e in await EnvironmentService().list_environments(session, project_id)
    }

    # 3. Líder del proyecto y Desarrollador de development.
    users = UserService()
    for (email, name), role, scope_environment in (
        (LIDER, Role.LIDER_TECNICO, None),
        (DEV, Role.DESARROLLADOR, environments["development"]),
    ):
        user = await users.create_user(
            session, actor, email=email, name=name, password=passwords[email]
        )
        await users.assign_role(
            session,
            actor,
            user,
            role_id=role,
            project_id=project_id,
            environment_id=scope_environment,
        )

    # 4. Secretos y una rotación (Servicio de Gestión de Secretos con la KEK de la instancia).
    signer = JwtSigner.from_pem(settings.jwt_private_key.get_secret_value().encode())
    key_manager = await load_key_manager(
        session, settings.kek_passphrase.get_secret_value().encode()
    )
    try:
        service = SecretService(CryptoEngine(key_manager))
        created = {}
        for environment, name, value in SECRETS:
            plaintext = bytearray(value, "utf-8")
            try:
                ref = await service.create_secret(
                    session,
                    actor=actor,
                    project_id=project_id,
                    environment_id=environments[environment],
                    name=name,
                    value=plaintext,
                    description="Valor de demostración",
                )
            finally:
                SecretService.wipe(plaintext)
            created[(environment, name)] = ref.secret_id
        environment, name, value = ROTATION
        plaintext = bytearray(value, "utf-8")
        try:
            await service.rotate_secret(
                session, created[(environment, name)], plaintext, actor=actor
            )
        finally:
            SecretService.wipe(plaintext)
    finally:
        key_manager.close()

    # 5. Aplicación Cliente de development; el PAT solo existe en esta salida (H-21).
    accounts = ServiceAccountService(
        AuthService(signer, settings.jwt_issuer).issue_personal_access_token
    )
    account = await accounts.create_service_account(
        session,
        actor,
        project_id,
        name="ci-tienda-dev",
        environment_id=environments["development"],
        expires_at=datetime.now(UTC) + timedelta(days=90),
    )

    print(f"\nProyecto '{PROJECT_NAME}' con {len(SECRETS)} secretos y una rotación.")
    for email, _ in (ADMIN, LIDER, DEV):
        if generated:
            shown = passwords[email]
        else:
            shown = "(del entorno)" if from_env else "(la que tecleaste)"
        print(f"  {email:24} {shown}")
    if from_env:
        print(f"\nPAT de '{account.account.name}' omitido en modo no interactivo.")
        return 0
    print(f"\nPAT de la Aplicación Cliente '{account.account.name}' (se muestra UNA vez):")
    print(account.token)
    if generated:
        print("\nGuarda las contraseñas y el PAT ahora: no se vuelven a mostrar.", file=sys.stderr)
    return 0


async def _run(password_for: PasswordSource) -> int:
    settings = Settings()  # lee PORTERO_* del entorno
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as session:
            return await seed(session, settings, password_for)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Datos de demo (solo desarrollo).")
    parser.add_argument(
        "--generar",
        action="store_true",
        help="genera las contraseñas con secrets y las imprime una vez, en lugar de pedirlas",
    )
    parser.add_argument(
        "--contrasenas-del-entorno",
        action="store_true",
        help="toma las contraseñas de SEED_PASSWORD_ADMIN/LIDER/DEV y no imprime nada sensible",
    )
    args = parser.parse_args()
    if args.generar and args.contrasenas_del_entorno:
        parser.error("--generar y --contrasenas-del-entorno son excluyentes")
    print("seed_demo: solo para desarrollo; crea datos de ejemplo en la BD configurada.")
    if args.contrasenas_del_entorno:
        source: PasswordSource = _from_env
    else:
        source = _generate if args.generar else _ask
    sys.exit(asyncio.run(_run(source)))


if __name__ == "__main__":
    main()
