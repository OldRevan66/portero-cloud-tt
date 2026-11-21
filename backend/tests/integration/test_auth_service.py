"""Pruebas del Servicio de Autenticación (CU-01) contra db-test: login con bloqueo y tiempo
uniforme, refresh con rotación y logout (Cap. 6 §Autenticación de actores humanos, §Revocación y
renovación; spec núcleo §3.1–3.2; spec Fase 5 §3.1–3.5; H-08, H-24, H-25, H-37).

Las contraseñas usan los parámetros Argon2id de producción (≈50 ms por verificación): aquí se
prueba el flujo real. Las pruebas de H-08 y H-24 son de **flujo** (qué ``verify`` se ejecuta y
contra qué hash), no de tiempo: medir tiempos en CI daría resultados intermitentes.
"""

import asyncio
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import portero.auth.service as servicio_mod
from portero.auth.passwords import hash_password, needs_rehash, verify_password
from portero.auth.service import AuthService, InvalidCredentialsError, TokenPair
from portero.auth.tokens import (
    API_TOKEN_TYPES,
    REFRESH_TOKEN_TYPES,
    TokenRejectedError,
    TokenScope,
    TokenType,
    VerifiedToken,
    issue_refresh_token,
    validate_token,
)
from portero.crypto.signing import JwtSigner
from portero.db.models import RevokedToken, User, UserRoleAssignment
from portero.db.repositories.user import RevokedTokenRepository

ISSUER = "https://portero.example.test"
CONTRASENA = "marcador-prueba-clave-larga"  # noqa: S105  # marcador de prueba, no un secreto
OTRA_CONTRASENA = "marcador-prueba-clave-equivocada"  # noqa: S105
MENSAJE = "credenciales inválidas"
ADMINISTRADOR = 1


@dataclass
class Reloj:
    """Reloj controlable que se inyecta en ``AuthService``. Arranca en la hora real porque PyJWT
    valida ``iat`` y ``exp`` contra el reloj del sistema."""

    ahora: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __call__(self) -> datetime:
        return self.ahora

    def avanzar(self, delta: timedelta) -> None:
        self.ahora += delta


@dataclass
class Espia:
    """Envuelve una función real y registra sus argumentos posicionales."""

    real: Callable[..., bool]
    llamadas: list[tuple[object, ...]] = field(default_factory=list)

    def __call__(self, *args: object) -> bool:
        self.llamadas.append(args)
        return self.real(*args)


@pytest.fixture
def signer() -> JwtSigner:
    return JwtSigner(Ed25519PrivateKey.generate())


@pytest.fixture
def reloj() -> Reloj:
    return Reloj()


@pytest.fixture
def servicio(signer: JwtSigner, reloj: Reloj) -> AuthService:
    return AuthService(signer, ISSUER, clock=reloj)


@pytest.fixture
async def usuario(db_session: AsyncSession) -> User:
    """Usuario activo con contraseña real y asignación global de Administrador."""
    user = User(email="ana@example.com", password_hash=hash_password(CONTRASENA), name="Ana")
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRoleAssignment(user_id=user.id, role_id=ADMINISTRADOR))
    await db_session.commit()
    return user


async def _validar(
    session: AsyncSession, signer: JwtSigner, token: str, tipos: frozenset[TokenType]
) -> VerifiedToken:
    return await validate_token(
        token,
        signer=signer,
        issuer=ISSUER,
        accepted_types=tipos,
        is_revoked=RevokedTokenRepository(session).is_revoked,
    )


async def _revocado(session: AsyncSession, jti: UUID) -> RevokedToken | None:
    return (
        await session.execute(select(RevokedToken).where(RevokedToken.token_jti == jti))
    ).scalar_one_or_none()


async def _rechazo_login(servicio: AuthService, session: AsyncSession, email: str, pwd: str) -> str:
    with pytest.raises(InvalidCredentialsError) as exc:
        await servicio.login(session, email, pwd)
    assert pwd not in str(exc.value)
    return str(exc.value)


async def _rechazo_refresh(servicio: AuthService, session: AsyncSession, token: str) -> str:
    with pytest.raises(TokenRejectedError) as exc:
        await servicio.refresh(session, token)
    assert token not in str(exc.value)
    return exc.value.reason


# --- login: éxito ---------------------------------------------------------------------------------


async def test_login_correcto_emite_par_valido(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User, reloj: Reloj
) -> None:
    usuario.failed_login_attempts = 3
    await db_session.commit()

    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    assert isinstance(par, TokenPair)
    access = await _validar(db_session, signer, par.access.token, API_TOKEN_TYPES)
    refresh = await _validar(db_session, signer, par.refresh.token, REFRESH_TOKEN_TYPES)
    assert access.sub == refresh.sub == usuario.id
    assert (access.token_type, refresh.token_type) == ("access", "refresh")
    assert access.roles == ("Administrador",)
    await db_session.refresh(usuario)
    assert usuario.failed_login_attempts == 0
    assert usuario.locked_until is None
    assert usuario.last_login_at == reloj.ahora


async def test_login_rehashea_si_los_parametros_cambiaron(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    # Hash con parámetros más débiles que los del Cap. 6 (como uno heredado de otra versión).
    viejo = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(CONTRASENA)
    usuario.password_hash = viejo
    await db_session.commit()
    assert needs_rehash(viejo)

    await servicio.login(db_session, "ana@example.com", CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.password_hash != viejo
    assert not needs_rehash(usuario.password_hash)
    assert verify_password(usuario.password_hash, CONTRASENA)


async def test_login_sin_rehash_conserva_el_hash(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    original = usuario.password_hash

    await servicio.login(db_session, "ana@example.com", CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.password_hash == original


# --- login: fallos y bloqueo (NIST SP 800-63B §5.2.2) ---------------------------------------------


async def test_contrasena_incorrecta_rechaza_e_incrementa(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    assert await _rechazo_login(servicio, db_session, "ana@example.com", OTRA_CONTRASENA) == MENSAJE

    # El incremento queda confirmado aunque el servicio haya lanzado la excepción.
    await db_session.rollback()
    await db_session.refresh(usuario)
    assert usuario.failed_login_attempts == 1
    assert usuario.locked_until is None


async def test_cinco_fallos_bloquean_quince_minutos(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    for _ in range(5):
        await _rechazo_login(servicio, db_session, "ana@example.com", OTRA_CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.locked_until == reloj.ahora + timedelta(minutes=15)
    # El contador se conserva: solo un login exitoso lo reinicia (spec núcleo §3.1).
    assert usuario.failed_login_attempts == 5


async def test_cuatro_fallos_no_bloquean(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    for _ in range(4):
        await _rechazo_login(servicio, db_session, "ana@example.com", OTRA_CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.locked_until is None
    assert usuario.failed_login_attempts == 4


async def test_bloqueo_vencido_y_otro_fallo_vuelve_a_bloquear(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    usuario.failed_login_attempts = 5
    usuario.locked_until = reloj.ahora - timedelta(minutes=1)
    await db_session.commit()

    await _rechazo_login(servicio, db_session, "ana@example.com", OTRA_CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.locked_until == reloj.ahora + timedelta(minutes=15)


async def test_bloqueo_vencido_con_contrasena_correcta_entra(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    usuario.failed_login_attempts = 5
    usuario.locked_until = reloj.ahora - timedelta(seconds=1)
    await db_session.commit()

    await servicio.login(db_session, "ana@example.com", CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.failed_login_attempts == 0
    assert usuario.locked_until is None


async def test_cuenta_bloqueada_con_contrasena_correcta_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    usuario.locked_until = reloj.ahora + timedelta(minutes=10)
    await db_session.commit()

    assert await _rechazo_login(servicio, db_session, "ana@example.com", CONTRASENA) == MENSAJE

    await db_session.refresh(usuario)
    assert usuario.last_login_at is None


async def test_cuenta_inactiva_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    usuario.is_active = False
    await db_session.commit()

    assert await _rechazo_login(servicio, db_session, "ana@example.com", CONTRASENA) == MENSAJE

    await db_session.refresh(usuario)
    assert usuario.last_login_at is None


async def test_correo_inexistente_rechaza_y_verifica_contra_senuelo(
    servicio: AuthService, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # H-08: sin cuenta, igual se ejecuta un verify real contra el hash señuelo.
    espia = Espia(servicio_mod.verify_against_decoy)
    monkeypatch.setattr(servicio_mod, "verify_against_decoy", espia)

    assert await _rechazo_login(servicio, db_session, "nadie@example.com", CONTRASENA) == MENSAJE

    assert espia.llamadas == [(CONTRASENA,)]


# --- login: H-24, siempre un verify contra el hash real antes de rechazar -------------------------


@pytest.mark.parametrize("estado", ["bloqueada", "inactiva"])
async def test_cuenta_bloqueada_o_inactiva_verifica_contra_el_hash_real(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    reloj: Reloj,
    monkeypatch: pytest.MonkeyPatch,
    estado: str,
) -> None:
    if estado == "bloqueada":
        usuario.locked_until = reloj.ahora + timedelta(minutes=10)
    else:
        usuario.is_active = False
    await db_session.commit()
    hash_real = usuario.password_hash  # se lee antes: el rollback del servicio expira el objeto
    espia_real = Espia(servicio_mod.verify_password)
    espia_senuelo = Espia(servicio_mod.verify_against_decoy)
    monkeypatch.setattr(servicio_mod, "verify_password", espia_real)
    monkeypatch.setattr(servicio_mod, "verify_against_decoy", espia_senuelo)

    await _rechazo_login(servicio, db_session, "ana@example.com", CONTRASENA)

    assert espia_real.llamadas == [(hash_real, CONTRASENA)]
    assert espia_senuelo.llamadas == []


async def test_los_cuatro_rechazos_son_indistinguibles(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    errores: list[InvalidCredentialsError] = []

    async def _capturar(email: str, pwd: str) -> None:
        with pytest.raises(InvalidCredentialsError) as exc:
            await servicio.login(db_session, email, pwd)
        errores.append(exc.value)

    await _capturar("ana@example.com", OTRA_CONTRASENA)  # contraseña incorrecta
    await _capturar("nadie@example.com", CONTRASENA)  # correo inexistente
    usuario.locked_until = reloj.ahora + timedelta(minutes=10)
    await db_session.commit()
    await _capturar("ana@example.com", CONTRASENA)  # bloqueada
    usuario.locked_until = None
    usuario.is_active = False
    await db_session.commit()
    await _capturar("ana@example.com", CONTRASENA)  # inactiva

    assert {type(e) for e in errores} == {InvalidCredentialsError}
    assert {str(e) for e in errores} == {MENSAJE}
    assert {e.args for e in errores} == {(MENSAJE,)}


# --- refresh: rotación (Cap. 6 §Renovación con refresh token; OWASP JWT Cheat Sheet) --------------


async def test_refresh_valido_rota_el_par(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    nuevo = await servicio.refresh(db_session, viejo.refresh.token)

    assert nuevo.refresh.jti != viejo.refresh.jti
    assert nuevo.access.jti != viejo.access.jti
    await _validar(db_session, signer, nuevo.access.token, API_TOKEN_TYPES)
    await _validar(db_session, signer, nuevo.refresh.token, REFRESH_TOKEN_TYPES)
    fila = await _revocado(db_session, viejo.refresh.jti)
    assert fila is not None
    assert fila.token_type == "refresh"  # noqa: S105  # tipo de token, no una contraseña
    assert fila.user_id == usuario.id
    assert fila.revoked_by is None  # rotación automática, sin actor (H-03)
    assert fila.expires_at == viejo.refresh.expires_at


async def test_refresh_da_otros_30_minutos_sin_mover_el_inicio_de_la_sesion(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    """H-61 (OWASP ASVS V3.3.2): el login da 30 min de inactividad; cada renovación da otros 30
    y conserva ``auth_time``, del que sale el tope de 12 h."""
    login = reloj.ahora.replace(microsecond=0)
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    assert viejo.refresh.expires_at == login + timedelta(minutes=30)
    reloj.avanzar(timedelta(minutes=20))

    nuevo = await servicio.refresh(db_session, viejo.refresh.token)

    assert nuevo.refresh.expires_at == login + timedelta(minutes=50)
    # Sin verificar: su iat está 20 min adelante del reloj real y PyJWT lo rechazaría.
    claims = jwt.decode(nuevo.refresh.token, options={"verify_signature": False})
    assert claims["auth_time"] == int(login.timestamp())


async def test_tras_30_minutos_sin_renovar_la_sesion_vence(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    """Un login de hace 31 min que nunca se renovó: el refresh ya no sirve (inactividad)."""
    reloj.avanzar(-timedelta(minutes=31))
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    with pytest.raises(TokenRejectedError) as exc:
        await servicio.refresh(db_session, viejo.refresh.token)

    assert exc.value.reason == "expirado"


async def test_cerca_del_fin_de_la_sesion_el_access_vence_con_ella(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    """A 5 min del tope de 12 h, el refresh y el access vencen con la sesión, no 30 y 15 min
    después."""
    fin_de_sesion = reloj.ahora.replace(microsecond=0) + timedelta(hours=12)
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    reloj.avanzar(timedelta(hours=11, minutes=55))

    nuevo = await servicio.refresh(db_session, viejo.refresh.token)

    assert nuevo.refresh.expires_at == fin_de_sesion
    assert nuevo.access.expires_at == fin_de_sesion


async def test_una_sesion_renovada_vence_a_las_12_horas_del_login(
    servicio: AuthService,
    db_session: AsyncSession,
    signer: JwtSigner,
    usuario: User,
    reloj: Reloj,
) -> None:
    """Una sesión iniciada hace casi 12 h y renovada sin pausas: en cuanto se cumplen las 12 h,
    el refresh renovado ya no sirve, aunque no haya pasado media hora de inactividad.

    PyJWT revisa ``exp`` con el reloj real, no con ``Reloj``, y un login de hace 12 h ya habría
    vencido por inactividad. Por eso el refresh de partida se firma con la clave del servicio y
    un ``auth_time`` de hace 12 h menos 2 s (como si se hubiera renovado sin pausas), y la prueba
    espera en tiempo real a que pase el tope."""
    inicio = reloj.ahora - timedelta(hours=12) + timedelta(seconds=2)
    activo = issue_refresh_token(
        signer, user_id=usuario.id, issuer=ISSUER, now=reloj.ahora, auth_time=inicio
    )
    renovado = await servicio.refresh(db_session, activo.token)
    assert renovado.refresh.expires_at is not None
    restante = (renovado.refresh.expires_at - datetime.now(UTC)).total_seconds()
    assert restante < 5  # si la renovación alargara la sesión, falla aquí y no espera horas
    await asyncio.sleep(max(restante, 0) + 0.2)

    with pytest.raises(TokenRejectedError) as exc:
        await servicio.refresh(db_session, renovado.refresh.token)

    assert exc.value.reason == "expirado"


async def test_refresh_revoca_y_emite_en_la_misma_transaccion(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Si la emisión del par nuevo falla, la revocación del refresh viejo se deshace: el usuario
    # no se queda sin tokens.
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    def _falla(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("falla simulada al emitir")

    with monkeypatch.context() as m:
        m.setattr(servicio_mod, "issue_access_token", _falla)
        with pytest.raises(RuntimeError, match="falla simulada"):
            await servicio.refresh(db_session, viejo.refresh.token)

    assert await _revocado(db_session, viejo.refresh.jti) is None
    await servicio.refresh(db_session, viejo.refresh.token)  # sigue siendo canjeable


async def test_reusar_refresh_viejo_se_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    viejo = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    await servicio.refresh(db_session, viejo.refresh.token)

    assert await _rechazo_refresh(servicio, db_session, viejo.refresh.token) == "refresh_reused"


async def test_reuso_de_refresh_invalida_la_cadena_del_atacante(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    # H-43 (Cap. 6 §Renovación: "forzar reautenticación completa"; RFC 9700 §4.14.2): el
    # atacante canjea primero el refresh robado (R1 → R2); cuando el dueño presenta R1, el reúso
    # debe dejar sin servicio a R2 y al access emitido con él, no solo rechazar a R1.
    robado = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    del_atacante = await servicio.refresh(db_session, robado.refresh.token)

    assert await _rechazo_refresh(servicio, db_session, robado.refresh.token) == "refresh_reused"

    assert (
        await _rechazo_refresh(servicio, db_session, del_atacante.refresh.token)
        == "tokens_invalidados"
    )
    with pytest.raises(TokenRejectedError) as rechazo:
        await servicio.authenticate(db_session, del_atacante.access.token)
    assert rechazo.value.reason == "tokens_invalidados"


async def test_access_token_no_sirve_para_refresh(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    # H-25: /auth/refresh solo acepta token_type=refresh.
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    assert await _rechazo_refresh(servicio, db_session, par.access.token) == "tipo"
    assert await _revocado(db_session, par.access.jti) is None


async def test_refresh_de_otra_clave_se_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    ajeno = AuthService(JwtSigner(Ed25519PrivateKey.generate()), ISSUER, clock=reloj)
    par = await ajeno.login(db_session, "ana@example.com", CONTRASENA)

    assert await _rechazo_refresh(servicio, db_session, par.refresh.token) == "cabecera"


async def test_refresh_de_usuario_desactivado_se_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    usuario.is_active = False
    await db_session.commit()

    assert await _rechazo_refresh(servicio, db_session, par.refresh.token) == "usuario_inactivo"
    assert await _revocado(db_session, par.refresh.jti) is None


async def test_refresh_emitido_antes_de_tokens_invalid_before_se_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    # H-37: T = floor(evento) + 1 s; el refresh se emitió en el mismo segundo del evento.
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    usuario.tokens_invalid_before = reloj.ahora.replace(microsecond=0) + timedelta(seconds=1)
    await db_session.commit()

    assert await _rechazo_refresh(servicio, db_session, par.refresh.token) == "tokens_invalidados"


async def test_refresh_emitido_despues_de_tokens_invalid_before_es_valido(
    servicio: AuthService, db_session: AsyncSession, usuario: User, reloj: Reloj
) -> None:
    usuario.tokens_invalid_before = reloj.ahora.replace(microsecond=0) - timedelta(seconds=10)
    await db_session.commit()
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)

    await servicio.refresh(db_session, par.refresh.token)


# --- logout (Cap. 6 §Casos que disparan revocación) -----------------------------------------------


async def test_logout_revoca_access_y_refresh(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    access = await _validar(db_session, signer, par.access.token, API_TOKEN_TYPES)

    await servicio.logout(db_session, access, par.refresh.token)

    fila_access = await _revocado(db_session, par.access.jti)
    fila_refresh = await _revocado(db_session, par.refresh.jti)
    assert fila_access is not None
    assert fila_refresh is not None
    assert (fila_access.token_type, fila_access.user_id) == ("access", usuario.id)
    assert (fila_refresh.token_type, fila_refresh.user_id) == ("refresh", usuario.id)
    assert await _rechazo_refresh(servicio, db_session, par.refresh.token) == "refresh_reused"


async def test_repetir_logout_no_falla(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    access = await _validar(db_session, signer, par.access.token, API_TOKEN_TYPES)

    await servicio.logout(db_session, access, par.refresh.token)
    await servicio.logout(db_session, access, par.refresh.token)

    assert await _revocado(db_session, par.access.jti) is not None


async def test_logout_sin_refresh_revoca_solo_el_access(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    access = await _validar(db_session, signer, par.access.token, API_TOKEN_TYPES)

    await servicio.logout(db_session, access, None)

    assert await _revocado(db_session, par.access.jti) is not None
    assert await _revocado(db_session, par.refresh.jti) is None


async def test_logout_ignora_un_refresh_invalido(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    access = await _validar(db_session, signer, par.access.token, API_TOKEN_TYPES)

    await servicio.logout(db_session, access, "esto-no-es-un-jwt")

    assert await _revocado(db_session, par.access.jti) is not None


async def test_logout_no_revoca_el_refresh_de_otro_usuario(
    servicio: AuthService, db_session: AsyncSession, signer: JwtSigner, usuario: User
) -> None:
    # Spec Fase 5 §3.3: solo se revoca el refresh si es "del mismo usuario".
    otro = User(email="beto@example.com", password_hash=hash_password(CONTRASENA), name="Beto")
    db_session.add(otro)
    await db_session.commit()
    par_ana = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    par_beto = await servicio.login(db_session, "beto@example.com", CONTRASENA)
    access_ana = await _validar(db_session, signer, par_ana.access.token, API_TOKEN_TYPES)

    await servicio.logout(db_session, access_ana, par_beto.refresh.token)

    assert await _revocado(db_session, par_ana.access.jti) is not None
    assert await _revocado(db_session, par_beto.refresh.jti) is None


async def test_logout_con_un_pat_se_rechaza(
    servicio: AuthService, db_session: AsyncSession, usuario: User
) -> None:
    # H-21: la revocación de un PAT es service_accounts.revoked_at, no revoked_tokens; además un
    # PAT sin exp no cabe en revoked_tokens.expires_at (NOT NULL). Logout es solo para humanos.
    pat = VerifiedToken(
        sub=uuid4(),
        jti=uuid4(),
        actor_type="service",
        token_type="service",  # noqa: S106  # tipo de token, no una contraseña
        roles=(),
        scope=TokenScope(project_id=uuid4(), environment_id=None),
        expires_at=None,
        issued_at=datetime.now(UTC).replace(microsecond=0),
    )

    with pytest.raises(TokenRejectedError) as exc:
        await servicio.logout(db_session, pat, None)

    assert exc.value.reason == "tipo"
    assert await _revocado(db_session, pat.jti) is None


async def test_canje_simultaneo_del_mismo_refresh_solo_gana_uno(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Dos peticiones validan el mismo refresh antes de que alguna lo revoque: ambas ven
    # is_revoked=False. Se simula dejando que la consulta mienta; el INSERT ... ON CONFLICT de la
    # segunda no inserta nada y el servicio lo trata como reuso.
    par = await servicio.login(db_session, "ana@example.com", CONTRASENA)
    await servicio.refresh(db_session, par.refresh.token)  # la primera petición gana

    async def _nunca_revocado(_self: RevokedTokenRepository, _jti: UUID) -> bool:
        return False

    monkeypatch.setattr(RevokedTokenRepository, "is_revoked", _nunca_revocado)

    assert await _rechazo_refresh(servicio, db_session, par.refresh.token) == "refresh_reused"


async def test_login_que_falla_al_emitir_no_deja_cambios(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usuario.failed_login_attempts = 3
    await db_session.commit()

    def _falla(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("falla simulada al emitir")

    monkeypatch.setattr(servicio_mod, "issue_access_token", _falla)
    with pytest.raises(RuntimeError, match="falla simulada"):
        await servicio.login(db_session, "ana@example.com", CONTRASENA)

    await db_session.refresh(usuario)
    assert usuario.failed_login_attempts == 3
    assert usuario.last_login_at is None


# --- H-72: Argon2id fuera del hilo del ciclo de eventos (OWASP API4) ------------------------------


@dataclass
class EspiaDeHilo:
    """Envuelve una función real y anota si cada llamada corrió en el hilo principal, que es el
    del ciclo de eventos en estas pruebas."""

    real: Callable[..., object]
    en_hilo_principal: list[bool] = field(default_factory=list)

    def __call__(self, *args: object) -> object:
        self.en_hilo_principal.append(threading.current_thread() is threading.main_thread())
        return self.real(*args)


def _espiar_hilos(monkeypatch: pytest.MonkeyPatch) -> dict[str, EspiaDeHilo]:
    espias = {
        nombre: EspiaDeHilo(getattr(servicio_mod, nombre))
        for nombre in ("verify_password", "verify_against_decoy", "hash_password")
    }
    for nombre, espia in espias.items():
        monkeypatch.setattr(servicio_mod, nombre, espia)
    # Guarda: si el ciclo de eventos no corriera en el hilo principal, estas pruebas no probarían
    # nada.
    assert threading.current_thread() is threading.main_thread()
    return espias


async def test_login_verifica_la_contrasena_fuera_del_ciclo_de_eventos(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-72: mientras Argon2id calcula (~17 ms), el ciclo de eventos sigue atendiendo."""
    espias = _espiar_hilos(monkeypatch)

    await servicio.login(db_session, "ana@example.com", CONTRASENA)

    assert espias["verify_password"].en_hilo_principal == [False]


async def test_login_con_correo_inexistente_verifica_el_senuelo_fuera_del_ciclo(
    servicio: AuthService, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H-72 sobre H-08: el señuelo también cuesta un Argon2id y no debe detener el ciclo."""
    espias = _espiar_hilos(monkeypatch)

    await _rechazo_login(servicio, db_session, "nadie@example.com", CONTRASENA)

    assert espias["verify_against_decoy"].en_hilo_principal == [False]


async def test_login_de_cuenta_bloqueada_verifica_fuera_del_ciclo(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    reloj: Reloj,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-72 sobre H-24: el verify contra el hash real de una cuenta bloqueada tampoco."""
    usuario.locked_until = reloj.ahora + timedelta(minutes=10)
    await db_session.commit()
    espias = _espiar_hilos(monkeypatch)

    await _rechazo_login(servicio, db_session, "ana@example.com", CONTRASENA)

    assert espias["verify_password"].en_hilo_principal == [False]


async def test_rehash_del_login_ocurre_fuera_del_ciclo(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usuario.password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        CONTRASENA
    )
    await db_session.commit()
    espias = _espiar_hilos(monkeypatch)

    await servicio.login(db_session, "ana@example.com", CONTRASENA)

    assert espias["verify_password"].en_hilo_principal == [False]
    assert espias["hash_password"].en_hilo_principal == [False]


async def test_cambio_de_contrasena_verifica_y_hashea_fuera_del_ciclo(
    servicio: AuthService,
    db_session: AsyncSession,
    usuario: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    espias = _espiar_hilos(monkeypatch)

    await servicio.change_password(db_session, usuario.id, CONTRASENA, OTRA_CONTRASENA)

    assert espias["verify_password"].en_hilo_principal == [False]
    assert espias["hash_password"].en_hilo_principal == [False]
    await db_session.refresh(usuario)
    assert verify_password(usuario.password_hash, OTRA_CONTRASENA)
