"""Dependencia Bearer con PAT de Aplicaciones Cliente (spec Fase 5 §3.7; H-21, H-25).

La fuente de verdad de la revocación de un PAT es ``service_accounts.revoked_at``, no
``revoked_tokens``. Se observa con ``GET /auth/me``: un PAT vigente **pasa** la autenticación y
recibe 403 (un service account no tiene "yo" humano, spec §3.4); uno revocado o de una service
account inexistente se queda en 401.
"""

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.integration.api.conftest import assert_problema, bearer
from tests.integration.conftest import Alcance, crear_alcance

from portero.auth.tokens import IssuedToken, issue_service_token
from portero.crypto.signing import JwtSigner
from portero.db.models import ServiceAccount

ISSUER = "https://portero.example.test"


async def _crear_pat(
    session: AsyncSession, signer: JwtSigner, alcance: Alcance
) -> tuple[ServiceAccount, IssuedToken]:
    """Service account con su PAT; solo se guarda SHA-256(token) en hex (spec núcleo §3.3)."""
    cuenta = ServiceAccount(
        id=uuid4(),
        name="ci-prueba",
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        token_hash="0" * 64,
        token_prefix="marcador",  # noqa: S106  # se reemplaza abajo por el prefijo real
        created_by=alcance.user_id,
    )
    pat = issue_service_token(
        signer,
        service_account_id=cuenta.id,
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        expires_at=None,
        issuer=ISSUER,
    )
    cuenta.token_hash = hashlib.sha256(pat.token.encode()).hexdigest()
    cuenta.token_prefix = pat.token[-8:]  # H-42
    session.add(cuenta)
    await session.commit()
    return cuenta, pat


async def test_pat_vigente_pasa_la_dependencia(
    cliente: AsyncClient, db_session: AsyncSession, signer_app: JwtSigner
) -> None:
    _, pat = await _crear_pat(db_session, signer_app, await crear_alcance(db_session))

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(pat.token))

    # 403 y no 401: el token se aceptó, pero /auth/me es solo para humanos.
    assert_problema(respuesta, 403, "permission-denied")


async def test_pat_revocado_da_401(
    cliente: AsyncClient, db_session: AsyncSession, signer_app: JwtSigner
) -> None:
    cuenta, pat = await _crear_pat(db_session, signer_app, await crear_alcance(db_session))
    cuenta.revoked_at = datetime.now(UTC)
    await db_session.commit()

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(pat.token))

    assert_problema(respuesta, 401, "authentication-failed")
    assert respuesta.headers["www-authenticate"].startswith("Bearer")


async def test_pat_de_service_account_inexistente_da_401(
    cliente: AsyncClient, db_session: AsyncSession, signer_app: JwtSigner
) -> None:
    alcance = await crear_alcance(db_session)
    pat = issue_service_token(
        signer_app,
        service_account_id=uuid4(),
        project_id=alcance.project_id,
        environment_id=alcance.environment_id,
        expires_at=None,
        issuer=ISSUER,
    )

    respuesta = await cliente.get("/api/v1/auth/me", headers=bearer(pat.token))

    assert_problema(respuesta, 401, "authentication-failed")
