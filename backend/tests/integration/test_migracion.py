"""La migración inicial está aplicada y el esquema hace cumplir sus restricciones (spec §2)."""

import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.conftest import Alcance

from portero.oplog.service import OperationEvent, OperationLogService

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"

TABLAS_CAP5 = {
    "users",
    "roles",
    "user_role_assignments",
    "projects",
    "environments",
    "secrets",
    "secret_versions",
    "kek_versions",
    "audit_logs",
    "revoked_tokens",
    "service_accounts",
}


async def test_la_base_esta_en_la_revision_head(db_session: AsyncSession) -> None:
    head = ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_current_head()
    actual = await db_session.scalar(text("SELECT version_num FROM alembic_version"))
    assert actual == head


async def test_existen_las_11_tablas_del_cap5(db_session: AsyncSession) -> None:
    filas = await db_session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    assert TABLAS_CAP5 <= {f[0] for f in filas}


async def test_roles_sembrados(db_session: AsyncSession) -> None:
    filas = (await db_session.execute(text("SELECT id, name FROM roles ORDER BY id"))).all()
    assert [tuple(f) for f in filas] == [
        (1, "Administrador"),
        (2, "Líder Técnico"),
        (3, "Desarrollador"),
    ]


@pytest.mark.parametrize(
    ("indice", "condicion"),
    [
        ("uq_secrets_nombre_activo", "WHERE (archived_at IS NULL)"),
        ("uq_kek_versions_una_activa", "WHERE (deactivated_at IS NULL)"),
        ("ix_service_accounts_project_id_vigentes", "WHERE (revoked_at IS NULL)"),
    ],
)
async def test_indices_parciales(db_session: AsyncSession, indice: str, condicion: str) -> None:
    definicion = await db_session.scalar(
        text("SELECT indexdef FROM pg_indexes WHERE indexname = :n"), {"n": indice}
    )
    assert definicion is not None
    assert condicion in definicion


async def test_fk_circular_de_version_actual_existe(db_session: AsyncSession) -> None:
    definicion = await db_session.scalar(
        text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'fk_secrets_current_version_id_secret_versions'"
        )
    )
    assert definicion == "FOREIGN KEY (current_version_id) REFERENCES secret_versions(id)"


async def test_trigger_actualiza_updated_at(db_session: AsyncSession, alcance: Alcance) -> None:
    # Aunque el UPDATE intente fijar una fecha vieja, el trigger la reemplaza por now().
    await db_session.execute(
        text("UPDATE users SET name = 'otro', updated_at = '2000-01-01T00:00:00Z' WHERE id = :id"),
        {"id": alcance.user_id},
    )
    anio = await db_session.scalar(
        text("SELECT extract(year FROM updated_at) FROM users WHERE id = :id"),
        {"id": alcance.user_id},
    )
    assert anio is not None and int(anio) > 2000


async def _debe_violar(session: AsyncSession, sql: str, params: dict[str, object]) -> None:
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await session.execute(text(sql), params)


async def test_ambiente_sin_proyecto_viola_check(
    db_session: AsyncSession, alcance: Alcance
) -> None:
    await _debe_violar(
        db_session,
        "INSERT INTO user_role_assignments (id, user_id, role_id, environment_id) "
        "VALUES (:id, :u, 3, :e)",
        {"id": uuid.uuid4(), "u": alcance.user_id, "e": alcance.environment_id},
    )


async def test_asignacion_global_duplicada_viola_unique(
    db_session: AsyncSession, alcance: Alcance
) -> None:
    # H-19: con NULLS NOT DISTINCT dos asignaciones globales iguales chocan.
    sql = "INSERT INTO user_role_assignments (id, user_id, role_id) VALUES (:id, :u, 1)"
    await db_session.execute(text(sql), {"id": uuid.uuid4(), "u": alcance.user_id})
    await _debe_violar(db_session, sql, {"id": uuid.uuid4(), "u": alcance.user_id})


async def test_solo_una_kek_activa(db_session: AsyncSession) -> None:
    sql = "INSERT INTO kek_versions (id, version_number, source) VALUES (:id, :n, 'external_kms')"
    await db_session.execute(text(sql), {"id": uuid.uuid4(), "n": 9001})
    await _debe_violar(db_session, sql, {"id": uuid.uuid4(), "n": 9002})


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        (
            "INSERT INTO kek_versions (id, version_number, source, deactivated_at) "
            "VALUES (:id, 9100, 'otro', now())",
            {},
        ),
        (
            "INSERT INTO revoked_tokens (token_jti, token_type, expires_at) "
            "VALUES (:id, 'session', now())",
            {},
        ),
        (
            "INSERT INTO audit_logs (event_timestamp, actor_type, actor_ref, verb, result, "
            "current_hash) VALUES (now(), 'user', 'x', 'login', 'success', repeat('0', 64))",
            {},
        ),
        (
            "INSERT INTO audit_logs (event_timestamp, actor_type, actor_ref, verb, result, "
            "current_hash) VALUES (now(), 'human', 'x', 'login', 'ok', repeat('1', 64))",
            {},
        ),
    ],
    ids=["kek-source", "token-type-session-H03", "actor-type-user-H04", "result"],
)
async def test_check_de_valores_enumerados(
    db_session: AsyncSession, sql: str, params: dict[str, object]
) -> None:
    await _debe_violar(db_session, sql, {"id": uuid.uuid4(), **params})


async def test_revoked_tokens_admite_token_sin_usuario(db_session: AsyncSession) -> None:
    # H-03: tokens de servicio sin usuario y revocaciones automáticas sin actor.
    await db_session.execute(
        text(
            "INSERT INTO revoked_tokens (token_jti, token_type, expires_at) "
            "VALUES (:id, 'service', now())"
        ),
        {"id": uuid.uuid4()},
    )


async def test_columna_tokens_invalid_before(db_session: AsyncSession) -> None:
    # H-37: TIMESTAMPTZ NULL; NULL = nunca se han revocado en bloque los tokens del usuario.
    fila = (
        await db_session.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'users' AND column_name = 'tokens_invalid_before'"
            )
        )
    ).one()
    assert tuple(fila) == ("timestamp with time zone", "YES")


async def test_tabla_chain_signatures_h81(db_session: AsyncSession) -> None:
    """H-81: firma del cierre de la cadena; la tabla 12, fuera del Cap. 5."""
    filas = await db_session.execute(
        text(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'chain_signatures' ORDER BY column_name"
        )
    )
    assert [tuple(f) for f in filas] == [
        ("created_at", "timestamp with time zone", "NO"),
        ("id", "uuid", "NO"),
        ("last_audit_id", "bigint", "NO"),
        ("last_hash", "character", "NO"),
        ("public_key_thumbprint", "character", "NO"),
        ("signature", "bytea", "NO"),
    ]


async def test_firma_de_largo_distinto_a_64_viola_check(db_session: AsyncSession) -> None:
    registro = await OperationLogService().record(
        db_session,
        OperationEvent(
            actor_type="service", actor_ref="sa:migracion", verb="create_project", result="success"
        ),
    )
    id_registro = registro.id
    await _debe_violar(
        db_session,
        "INSERT INTO chain_signatures "
        "(id, created_at, last_audit_id, last_hash, signature, public_key_thumbprint) "
        "VALUES (:id, now(), :audit, :hash, :firma, :huella)",
        {
            "id": uuid.uuid4(),
            "audit": id_registro,
            "hash": "0" * 64,
            "firma": b"\x00" * 63,
            "huella": "x" * 43,
        },
    )


async def test_fk_de_chain_signatures_es_restrict(db_session: AsyncSession) -> None:
    regla = await db_session.scalar(
        text(
            "SELECT confdeltype::text FROM pg_constraint "
            "WHERE conname = 'fk_chain_signatures_last_audit_id_audit_logs'"
        )
    )
    assert regla == "r"  # RESTRICT
