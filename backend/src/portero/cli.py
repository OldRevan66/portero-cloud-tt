"""Utilidades administrativas por línea de comandos: ``python -m portero.cli <subcomando>``.

No se exponen en la API: humano en el bucle (NIST SP 800-57).

- ``create-admin <correo>``: crea el primer Administrador de instancia (H-38).
- ``rotate-kek``: rotación de la KEK con re-envoltura de todas las DEKs (H-07, H-40).
- ``sign-chain``: firma diaria del cierre de la cadena de la bitácora (H-81).
"""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Callable, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from portero.auth.emails import normalize_email
from portero.auth.passwords import PasswordPolicyError, check_password_policy, hash_password
from portero.config import Settings
from portero.crypto.errors import KekPassphraseError, SigningKeyError
from portero.crypto.kek import PARAMETROS_KEK_PRODUCCION, KdfParams
from portero.crypto.signing import (
    load_ed25519_private_key_pem,
    load_ed25519_public_key_pem,
    public_key_thumbprint,
)
from portero.db.models import User, UserRoleAssignment
from portero.db.repositories.user import UserRepository
from portero.db.session import create_engine, create_sessionmaker
from portero.oplog.service import (
    ChainNotIntactError,
    EmptyChainError,
    OperationEvent,
    OperationLogService,
)
from portero.rbac.permissions import Role
from portero.secrets_mgmt import kek_rotation
from portero.secrets_mgmt.errors import KekRotationError

PasswordReader = Callable[[str], str]

CREATE_ADMIN_ACTOR_REF = "cli:create-admin"
"""``actor_ref`` del CLI (spec Fase 5 §5.3): ``actor_type=human`` y ``actor_user_id`` NULL."""


def _error(mensaje: str) -> int:
    print(f"error: {mensaje}", file=sys.stderr)
    return 1


async def create_admin(
    session: AsyncSession, email: str, *, read_password: PasswordReader = getpass.getpass
) -> int:
    """Crea el primer Administrador de instancia (H-38). Devuelve el código de salida.

    En una instalación nueva nadie tiene ``users:manage``, así que no hay forma de crear usuarios
    por la API. Este comando cubre ese hueco con un humano en el bucle:

    - se niega si ya existe un Administrador activo: no es una puerta trasera para crear más;
    - la contraseña se lee con ``getpass`` dos veces (nunca como argumento, que quedaría en el
      historial del shell) y pasa por la política del Cap. 6 §Política de contraseñas (NIST SP
      800-63B §5.1.1);
    - el usuario y su asignación global de Administrador se crean en una sola transacción, junto
      con sus registros ``create_user`` y ``assign_role`` en el Servicio de Registro de
      Operaciones (spec Fase 5 §5.4; H-11): si el registro falla, no se crea nada.

    El correo se normaliza igual que en la API (H-45). La contraseña nunca se imprime.
    """
    email = normalize_email(email)
    users = UserRepository(session)
    try:
        if await users.active_user_with_role_exists(Role.ADMINISTRADOR):
            return _error(
                "ya existe un Administrador activo; los demás usuarios se crean desde la API"
            )
        if await users.email_exists(email):
            return _error(f"ya existe un usuario con el correo {email}")

        password = read_password("Contraseña: ")
        if read_password("Confirma la contraseña: ") != password:
            return _error("las contraseñas no coinciden")
        try:
            check_password_policy(password)
        except PasswordPolicyError as exc:  # el mensaje nunca incluye la contraseña
            return _error(str(exc))

        user = User(email=email, password_hash=hash_password(password))
        await users.add(user)
        user_id = user.id  # se lee antes del rollback de abajo, que expira el objeto
        await users.add_assignment(UserRoleAssignment(user_id=user_id, role_id=Role.ADMINISTRADOR))
        oplog = OperationLogService()
        for verb, details in (
            ("create_user", None),
            (
                "assign_role",
                {
                    "target_user_id": str(user_id),
                    "role_id": int(Role.ADMINISTRADOR),
                    "project_id": None,
                    "environment_id": None,
                },
            ),
        ):
            await oplog.record(
                session,
                OperationEvent(
                    actor_type="human",
                    actor_ref=CREATE_ADMIN_ACTOR_REF,
                    verb=verb,
                    result="success",
                    resource_type="user",
                    resource_id=user_id,
                    details=details,
                ),
            )
        await session.commit()
    finally:
        # Sin efecto tras el commit; en cualquier salida temprana descarta la transacción.
        await session.rollback()

    print(f"Administrador creado: {email} (id {user_id})")
    return 0


async def _run_create_admin(email: str) -> int:
    engine = create_engine(Settings())  # lee PORTERO_* del entorno
    try:
        async with create_sessionmaker(engine)() as session:
            return await create_admin(session, email)
    finally:
        await engine.dispose()


_AVISO_ROTACION = (
    "Rotación de la KEK (H-07). Antes de continuar, detén la API: un proceso en marcha conserva\n"
    "la KEK vieja en memoria y cifraría secretos nuevos con ella (H-40)."
)


async def rotate_kek(
    session: AsyncSession,
    *,
    read_password: PasswordReader = getpass.getpass,
    new_params: KdfParams = PARAMETROS_KEK_PRODUCCION,
) -> int:
    """Rota la KEK: versión N+1 y re-envoltura de todas las DEKs (spec §1.6; H-07, H-40).

    Solo orquesta; la rotación la hace ``portero.secrets_mgmt.kek_rotation.rotate_kek`` en una
    sola transacción. Humano en el bucle (NIST SP 800-57): no se expone en la API.

    - Advierte que la API debe estar detenida (H-40).
    - Pide con ``getpass`` la passphrase actual, la nueva y su confirmación. Nunca como
      argumento (quedaría en el historial del shell) y nunca las imprime.
    - Se lee la passphrase actual en lugar de ``PORTERO_KEK_PASSPHRASE``: quien rota debe
      conocerla, y el ``.env`` puede no estar disponible en la terminal del operador.

    Devuelve el código de salida.
    """
    print(_AVISO_ROTACION)
    actual = read_password("Passphrase actual de la KEK: ")
    nueva = read_password("Passphrase nueva de la KEK: ")
    if read_password("Confirma la passphrase nueva: ") != nueva:
        return _error("las passphrases nuevas no coinciden")
    try:
        resultado = await kek_rotation.rotate_kek(
            session,
            current_passphrase=actual.encode(),
            new_passphrase=nueva.encode(),
            oplog=OperationLogService(),
            new_params=new_params,
        )
    except (KekRotationError, KekPassphraseError) as exc:  # mensajes fijos, sin passphrases
        return _error(str(exc))

    print(
        f"KEK rotada: versión {resultado.from_version} → {resultado.to_version}; "
        f"{resultado.rewrapped_deks} DEKs re-envueltas.\n"
        "Actualiza PORTERO_KEK_PASSPHRASE con la passphrase nueva y vuelve a arrancar la API."
    )
    return 0


async def _run_rotate_kek() -> int:
    engine = create_engine(Settings())  # lee PORTERO_* del entorno
    try:
        async with create_sessionmaker(engine)() as session:
            return await rotate_kek(session)
    finally:
        await engine.dispose()


SIGNING_PRIVATE_VARIABLE = "PORTERO_OPLOG_SIGNING_PRIVATE_KEY"
SIGNING_PUBLIC_VARIABLE = "PORTERO_OPLOG_SIGNING_PUBLIC_KEY"


async def sign_chain(
    session: AsyncSession, *, private_key_pem: str | None, public_key_pem: str | None
) -> int:
    """Firma el cierre de la cadena de la bitácora (H-81). Devuelve el código de salida.

    El operador lo programa una vez al día (cron o Programador de tareas con
    ``docker compose exec``). La llave privada llega solo en esa invocación, por
    ``PORTERO_OPLOG_SIGNING_PRIVATE_KEY``; nunca como argumento (quedaría en el historial del
    shell y en la lista de procesos) ni en el ``.env`` de la API.

    - Si también está ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY`` (la que usa la API para verificar),
      debe ser el par de la privada: si no, el Dashboard reportaría las firmas como inválidas.
    - Si la cadena o una firma anterior no pasa la verificación, no firma (ver
      ``OperationLogService.sign_chain``).
    - Imprime el ancla (registro, ``last_hash`` y fecha). La salida de la tarea queda en el
      host, fuera de la BD: sirve para detectar que alguien borró las firmas recientes junto
      con el final de la cadena. Nunca imprime la llave.
    """
    if private_key_pem is None:
        return _error(
            f"falta {SIGNING_PRIVATE_VARIABLE}; genérala con scripts/generate_oplog_key.py"
        )
    try:
        private_key = load_ed25519_private_key_pem(
            private_key_pem.encode(), SIGNING_PRIVATE_VARIABLE
        )
        if public_key_pem is not None:
            configured = load_ed25519_public_key_pem(
                public_key_pem.encode(), SIGNING_PUBLIC_VARIABLE
            )
            if public_key_thumbprint(configured) != public_key_thumbprint(private_key.public_key()):
                return _error(
                    f"{SIGNING_PUBLIC_VARIABLE} no es el par de {SIGNING_PRIVATE_VARIABLE}"
                )
    except SigningKeyError as exc:  # mensaje fijo, sin el PEM
        return _error(str(exc))

    try:
        firma = await OperationLogService().sign_chain(session, private_key)
    except ChainNotIntactError as exc:
        report = exc.report
        return _error(
            "la bitácora no está íntegra; no se firmó el cierre. "
            f"Filas rotas: {report.broken or 'ninguna'}; "
            f"firmas inválidas: {report.invalid_signatures or 'ninguna'}; "
            f"firmas faltantes: {report.missing_signatures or 'ninguna'}"
        )
    except EmptyChainError as exc:
        return _error(str(exc))

    print(
        f"Cierre firmado: registro #{firma.last_audit_id}, "
        f"hash {firma.last_hash}, {firma.created_at.isoformat()}"
    )
    return 0


async def _run_sign_chain() -> int:
    settings = Settings()  # lee PORTERO_* del entorno
    private_key = settings.oplog_signing_private_key
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as session:
            return await sign_chain(
                session,
                private_key_pem=private_key.get_secret_value() if private_key else None,
                public_key_pem=settings.oplog_signing_public_key,
            )
    finally:
        await engine.dispose()


def build_parser() -> argparse.ArgumentParser:
    """Parser con un subcomando por utilidad administrativa."""
    parser = argparse.ArgumentParser(
        prog="python -m portero.cli", description="Utilidades administrativas de Portero Cloud."
    )
    subcomandos = parser.add_subparsers(dest="command", required=True)
    crear = subcomandos.add_parser(
        "create-admin", help="crea el primer Administrador de instancia (H-38)"
    )
    crear.add_argument("email", help="correo del Administrador")
    subcomandos.add_parser(
        "rotate-kek",
        help="rota la KEK y re-envuelve todas las DEKs (H-07); detén la API antes",
    )
    subcomandos.add_parser(
        "sign-chain",
        help=(
            "firma el cierre de la cadena de la bitácora (H-81); la llave privada llega por "
            f"{SIGNING_PRIVATE_VARIABLE}"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada de ``python -m portero.cli``."""
    args = build_parser().parse_args(argv)
    if args.command == "create-admin":
        return asyncio.run(_run_create_admin(args.email))
    if args.command == "rotate-kek":
        return asyncio.run(_run_rotate_kek())
    if args.command == "sign-chain":
        return asyncio.run(_run_sign_chain())
    return 2  # pragma: no cover  # argparse ya rechaza subcomandos desconocidos


if __name__ == "__main__":
    sys.exit(main())
