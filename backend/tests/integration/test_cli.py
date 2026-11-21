"""Pruebas de ``python -m portero.cli create-admin`` (H-38), ``rotate-kek`` (H-07) y
``sign-chain`` (H-81) contra db-test.

En una instalación nueva nadie tiene ``users:manage``, así que el primer Administrador se crea por
línea de comandos: humano en el bucle, contraseña leída con ``getpass`` (dos veces) y la misma
política de ``auth/passwords.py`` (NIST SP 800-63B §5.1.1). La contraseña nunca se imprime.

``getpass`` se simula inyectando ``read_password``. Con ``capsys`` se revisa toda la salida.
"""

from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import PASSPHRASE_PRUEBA

from portero.auth.passwords import hash_password, verify_password
from portero.cli import build_parser, create_admin, rotate_kek, sign_chain
from portero.crypto.kek import KdfParams, KeyManager
from portero.crypto.signing import (
    generate_private_key_pem,
    load_ed25519_private_key_pem,
    public_key_pem,
)
from portero.db.models import AuditLog, ChainSignature, KekVersion, User, UserRoleAssignment
from portero.oplog.service import OperationEvent, OperationLogService

CORREO = "admin@example.com"
CONTRASENA = "marcador-prueba-clave-larga"  # noqa: S105  # marcador de prueba, no un secreto
ADMINISTRADOR = 1


def _entradas(*respuestas: str) -> Callable[[str], str]:
    """Doble de ``getpass.getpass``: devuelve las respuestas en orden y falla si se piden más."""
    pendientes: Iterator[str] = iter(respuestas)

    def _leer(_prompt: str = "") -> str:
        return next(pendientes)

    return _leer


async def _usuario(session: AsyncSession, email: str) -> User | None:
    return (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()


def _salida_sin_contrasena(capsys: pytest.CaptureFixture[str], *contrasenas: str) -> str:
    salida = capsys.readouterr()
    for pwd in contrasenas:
        assert pwd not in salida.out
        assert pwd not in salida.err
    return salida.out + salida.err


async def test_crea_administrador_con_hash_argon2id_y_asignacion_global(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, CONTRASENA))

    assert codigo == 0
    _salida_sin_contrasena(capsys, CONTRASENA)
    user = await _usuario(db_session, CORREO)
    assert user is not None
    assert user.is_active
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password(user.password_hash, CONTRASENA)
    asignaciones = (
        (
            await db_session.execute(
                select(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id)
            )
        )
        .scalars()
        .all()
    )
    assert [(a.role_id, a.project_id, a.environment_id) for a in asignaciones] == [
        (ADMINISTRADOR, None, None)
    ]


@pytest.mark.parametrize(
    ("contrasena", "motivo"),
    [
        ("corta", "al menos 12"),
        ("password1234", "comunes"),
    ],
)
async def test_contrasena_que_viola_la_politica_no_crea_nada(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str], contrasena: str, motivo: str
) -> None:
    codigo = await create_admin(db_session, CORREO, read_password=_entradas(contrasena, contrasena))

    assert codigo != 0
    assert motivo in _salida_sin_contrasena(capsys, contrasena)
    assert await _usuario(db_session, CORREO) is None


async def test_confirmacion_distinta_no_crea_nada(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    otra = "marcador-prueba-otra-clave"
    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, otra))

    assert codigo != 0
    assert "no coinciden" in _salida_sin_contrasena(capsys, CONTRASENA, otra)
    assert await _usuario(db_session, CORREO) is None


async def test_correo_duplicado_da_error_claro(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    # Ya existe un usuario (no Administrador) con ese correo.
    previo = User(email=CORREO, password_hash=hash_password(CONTRASENA), name="Previo")
    db_session.add(previo)
    await db_session.commit()

    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, CONTRASENA))

    assert codigo != 0
    salida = _salida_sin_contrasena(capsys, CONTRASENA)
    assert "ya existe" in salida
    assert CORREO in salida
    usuarios = (await db_session.execute(select(User).where(User.email == CORREO))).scalars().all()
    assert [u.id for u in usuarios] == [previo.id]
    assert (
        await db_session.execute(
            select(UserRoleAssignment).where(UserRoleAssignment.user_id == previo.id)
        )
    ).first() is None


async def test_create_admin_guarda_el_correo_en_minusculas(db_session: AsyncSession) -> None:
    """H-45: el CLI normaliza el correo igual que la API (sin espacios y en minúsculas)."""
    codigo = await create_admin(
        db_session, f"  {CORREO.upper()} ", read_password=_entradas(CONTRASENA, CONTRASENA)
    )

    assert codigo == 0
    correos = (await db_session.execute(select(User.email))).scalars().all()
    assert correos == [CORREO]


async def test_se_niega_si_ya_hay_un_administrador_activo(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    # H-38: no es una puerta trasera para crear Administradores adicionales.
    actual = User(email="actual@example.com", password_hash=hash_password(CONTRASENA))
    db_session.add(actual)
    await db_session.flush()
    db_session.add(UserRoleAssignment(user_id=actual.id, role_id=ADMINISTRADOR))
    await db_session.commit()

    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, CONTRASENA))

    assert codigo != 0
    assert "Administrador" in _salida_sin_contrasena(capsys, CONTRASENA)
    assert await _usuario(db_session, CORREO) is None


async def test_un_administrador_inactivo_no_impide_crear_otro(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    # H-38 habla de un Administrador *activo*: si el único está desactivado, se puede crear otro.
    inactivo = User(
        email="inactivo@example.com", password_hash=hash_password(CONTRASENA), is_active=False
    )
    db_session.add(inactivo)
    await db_session.flush()
    db_session.add(UserRoleAssignment(user_id=inactivo.id, role_id=ADMINISTRADOR))
    await db_session.commit()

    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, CONTRASENA))

    assert codigo == 0
    _salida_sin_contrasena(capsys, CONTRASENA)
    assert await _usuario(db_session, CORREO) is not None


def test_parser_del_subcomando_create_admin() -> None:
    args = build_parser().parse_args(["create-admin", CORREO])

    assert args.command == "create-admin"
    assert args.email == CORREO


def test_parser_no_acepta_la_contrasena_como_argumento() -> None:
    # La contraseña solo entra por getpass: en la línea de comandos quedaría en el historial del
    # shell y en la lista de procesos.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["create-admin", CORREO, "--password", CONTRASENA])


# --- rotate-kek (spec §1.6, H-07, H-40) -------------------------------------------------------
#
# La CLI solo orquesta: pide las passphrases con getpass, valida la confirmación y delega en
# ``portero.secrets_mgmt.kek_rotation.rotate_kek``. La rotación en sí (re-envoltura, una sola
# transacción, bitácora) se prueba en ``test_rotacion_kek.py``.

PASSPHRASE_ACTUAL = PASSPHRASE_PRUEBA.decode()
PASSPHRASE_NUEVA = "marcador-de-prueba-passphrase-kek-nueva"  # noqa: S105  # marcador de prueba


class _EntradasConPrompts:
    """Doble de ``getpass.getpass`` que además recuerda qué preguntó."""

    def __init__(self, *respuestas: str) -> None:
        self._pendientes: Iterator[str] = iter(respuestas)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return next(self._pendientes)


async def _kek_activa(session: AsyncSession) -> list[tuple[int, bool]]:
    stmt = (
        select(KekVersion)
        .order_by(KekVersion.version_number)
        .execution_options(populate_existing=True)
    )
    return [
        (v.version_number, v.deactivated_at is None)
        for v in (await session.execute(stmt)).scalars()
    ]


async def test_rotate_kek_pide_actual_nueva_y_confirmacion_sin_imprimirlas(
    db_session: AsyncSession,
    key_manager: KeyManager,
    parametros_argon2_solo_pruebas: KdfParams,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entradas = _EntradasConPrompts(PASSPHRASE_ACTUAL, PASSPHRASE_NUEVA, PASSPHRASE_NUEVA)

    codigo = await rotate_kek(
        db_session, read_password=entradas, new_params=parametros_argon2_solo_pruebas
    )

    assert codigo == 0
    assert len(entradas.prompts) == 3
    assert "actual" in entradas.prompts[0].lower()
    assert "nueva" in entradas.prompts[1].lower()
    assert "confirma" in entradas.prompts[2].lower()
    salida = _salida_sin_contrasena(capsys, PASSPHRASE_ACTUAL, PASSPHRASE_NUEVA)
    assert "API" in salida  # H-40: advierte que la API debe estar detenida
    assert "PORTERO_KEK_PASSPHRASE" in salida  # y qué hacer después
    assert await _kek_activa(db_session) == [(1, False), (2, True)]


@pytest.mark.parametrize(
    ("respuestas", "motivo"),
    [
        pytest.param(
            (PASSPHRASE_ACTUAL, PASSPHRASE_NUEVA, "marcador-de-prueba-otra"),
            "no coinciden",
            id="confirmacion-distinta",
        ),
        pytest.param(
            ("marcador-de-prueba-equivocada", PASSPHRASE_NUEVA, PASSPHRASE_NUEVA),
            "passphrase de KEK incorrecta",
            id="actual-incorrecta",
        ),
        pytest.param(
            (PASSPHRASE_ACTUAL, PASSPHRASE_ACTUAL, PASSPHRASE_ACTUAL),
            "distinta",
            id="nueva-igual-a-la-actual",
        ),
        pytest.param((PASSPHRASE_ACTUAL, "", ""), "vacía", id="nueva-vacia"),
    ],
)
async def test_rotate_kek_con_entradas_invalidas_no_cambia_nada(
    db_session: AsyncSession,
    key_manager: KeyManager,
    parametros_argon2_solo_pruebas: KdfParams,
    capsys: pytest.CaptureFixture[str],
    respuestas: tuple[str, str, str],
    motivo: str,
) -> None:
    codigo = await rotate_kek(
        db_session,
        read_password=_EntradasConPrompts(*respuestas),
        new_params=parametros_argon2_solo_pruebas,
    )

    assert codigo != 0
    assert motivo in _salida_sin_contrasena(capsys, *(r for r in respuestas if r))
    assert await _kek_activa(db_session) == [(1, True)]


def test_parser_del_subcomando_rotate_kek() -> None:
    assert build_parser().parse_args(["rotate-kek"]).command == "rotate-kek"


def test_parser_no_acepta_passphrases_como_argumento() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["rotate-kek", "--passphrase", PASSPHRASE_NUEVA])


# --- create-admin en el Servicio de Registro de Operaciones (spec Fase 5 §5.2–5.4; H-11) -------


async def _registros_cli(session: AsyncSession, actor_ref: str) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.actor_ref == actor_ref).order_by(AuditLog.id)
    return list((await session.execute(stmt)).scalars())


async def test_create_admin_registra_create_user_y_assign_role(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    codigo = await create_admin(db_session, CORREO, read_password=_entradas(CONTRASENA, CONTRASENA))

    assert codigo == 0
    _salida_sin_contrasena(capsys, CONTRASENA)
    user = await _usuario(db_session, CORREO)
    assert user is not None
    creado, asignado = await _registros_cli(db_session, "cli:create-admin")
    for registro in (creado, asignado):
        assert registro.actor_type == "human"
        assert registro.actor_user_id is None
        assert registro.result == "success"
        assert registro.resource_type == "user"
        assert registro.resource_id == user.id
        assert registro.project_id is None
        assert registro.environment_id is None
        assert CONTRASENA not in str(registro.details)
    assert creado.verb == "create_user"
    assert asignado.verb == "assign_role"
    assert asignado.details == {
        "target_user_id": str(user.id),
        "role_id": ADMINISTRADOR,
        "project_id": None,
        "environment_id": None,
    }
    assert (await OperationLogService().verify_chain(db_session)).ok


async def test_create_admin_fallido_no_registra_nada(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    codigo = await create_admin(db_session, CORREO, read_password=_entradas("corta", "corta"))

    assert codigo != 0
    assert await _registros_cli(db_session, "cli:create-admin") == []


# --- sign-chain (H-81) ---------------------------------------------------------------------------


async def _sembrar_bitacora(session: AsyncSession) -> AuditLog:
    """Un registro cualquiera para que haya algo que firmar; devuelve el último."""
    registro = await OperationLogService().record(
        session,
        OperationEvent(
            actor_type="service", actor_ref="sa:cli", verb="create_project", result="success"
        ),
    )
    await session.commit()
    return registro


def _par_pem() -> tuple[str, str]:
    privada = generate_private_key_pem()
    publica = public_key_pem(load_ed25519_private_key_pem(privada, "prueba").public_key())
    return privada.decode(), publica.decode()


async def test_sign_chain_firma_e_imprime_el_ancla_sin_la_llave(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    """La salida de la tarea programada queda en el host, fuera de la BD: es un ancla más."""
    cierre = await _sembrar_bitacora(db_session)
    privada, publica = _par_pem()

    codigo = await sign_chain(db_session, private_key_pem=privada, public_key_pem=publica)

    assert codigo == 0
    salida = capsys.readouterr()
    assert f"#{cierre.id}" in salida.out
    assert cierre.current_hash in salida.out
    assert "PRIVATE KEY" not in salida.out + salida.err
    firma = await db_session.scalar(
        select(ChainSignature).where(ChainSignature.last_audit_id == cierre.id)
    )
    assert firma is not None


async def test_sign_chain_sin_la_publica_configurada_tambien_firma(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    """H-86: ``PORTERO_OPLOG_SIGNING_PUBLIC_KEY`` es opcional al firmar (solo se compara si
    viene); la firma se verifica con la pública derivada de la privada."""
    cierre = await _sembrar_bitacora(db_session)
    privada, _ = _par_pem()

    codigo = await sign_chain(db_session, private_key_pem=privada, public_key_pem=None)

    assert codigo == 0
    assert f"#{cierre.id}" in capsys.readouterr().out
    firma = await db_session.scalar(
        select(ChainSignature).where(ChainSignature.last_audit_id == cierre.id)
    )
    assert firma is not None


async def test_sign_chain_sin_llave_explica_la_variable(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    codigo = await sign_chain(db_session, private_key_pem=None, public_key_pem=None)

    assert codigo == 1
    assert "PORTERO_OPLOG_SIGNING_PRIVATE_KEY" in capsys.readouterr().err


async def test_sign_chain_con_pem_invalido_no_lo_imprime(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    pem = "marcador-de-prueba-pem-invalido"

    codigo = await sign_chain(db_session, private_key_pem=pem, public_key_pem=None)

    assert codigo == 1
    salida = capsys.readouterr()
    assert pem not in salida.out + salida.err


async def test_sign_chain_se_niega_si_la_publica_configurada_no_es_su_par(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    """Firmar con una llave que la API no reconoce dejaría firmas "inválidas" en el Dashboard."""
    await _sembrar_bitacora(db_session)
    privada, _ = _par_pem()
    _, otra_publica = _par_pem()
    antes = await db_session.scalar(select(func.count()).select_from(ChainSignature))

    codigo = await sign_chain(db_session, private_key_pem=privada, public_key_pem=otra_publica)

    assert codigo == 1
    assert "PORTERO_OPLOG_SIGNING_PUBLIC_KEY" in capsys.readouterr().err
    assert await db_session.scalar(select(func.count()).select_from(ChainSignature)) == antes


async def test_sign_chain_con_la_cadena_alterada_sale_con_error(
    db_session: AsyncSession, capsys: pytest.CaptureFixture[str]
) -> None:
    cierre = await _sembrar_bitacora(db_session)
    await db_session.execute(
        text("UPDATE audit_logs SET actor_ref = 'sa:alterado' WHERE id = :id"), {"id": cierre.id}
    )
    await db_session.commit()
    db_session.expunge_all()
    privada, publica = _par_pem()

    codigo = await sign_chain(db_session, private_key_pem=privada, public_key_pem=publica)

    assert codigo == 1
    assert "no está íntegra" in capsys.readouterr().err


def test_parser_del_subcomando_sign_chain() -> None:
    assert build_parser().parse_args(["sign-chain"]).command == "sign-chain"


def test_parser_no_acepta_la_llave_como_argumento() -> None:
    """La llave quedaría en el historial del shell y en la lista de procesos."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["sign-chain", "--key", "marcador"])
