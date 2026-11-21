"""Entorno de Alembic para Portero Cloud (plantilla asíncrona, asyncpg; Cap. 6 §Stack backend).

La URL de la base se toma de ``PORTERO_DATABASE_URL`` (entorno o ``.env``), no de
``alembic.ini``. Solo se exige esa variable: migrar no necesita la passphrase de la KEK ni la
clave de firma de JWT.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from portero.db.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


class _MigrationSettings(BaseSettings):
    """Subconjunto de ``portero.config.Settings`` que necesita Alembic."""

    model_config = SettingsConfigDict(
        env_prefix="PORTERO_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: SecretStr  # incluye la contraseña de la base (H-28)


def _database_url() -> str:
    return _MigrationSettings().database_url.get_secret_value()  # type: ignore[call-arg]


def run_migrations_offline() -> None:
    """Genera el SQL sin conectarse (``alembic upgrade head --sql``), útil para revisarlo."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = create_async_engine(
        _database_url(), poolclass=pool.NullPool, hide_parameters=True
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
