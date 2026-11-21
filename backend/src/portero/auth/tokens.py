"""Construcción y validación de claims JWT (access, refresh, service; RFC 7519). La firma y la
verificación criptográfica se delegan en ``portero.crypto.signing`` (spec §3.2, H-09, H-25).

Claims según la tabla "Estructura del payload del JWT" del Cap. 6: ``iss``, ``sub``, ``aud``,
``iat``, ``exp``, ``jti``, ``actor_type``, ``token_type``, ``roles`` (solo humanos) y ``scope``
(solo Aplicaciones Cliente).

Este módulo no consulta la base de datos: la emisión devuelve ``jti`` y ``expires_at`` para que
el Servicio de Autenticación los registre, y la revocación se consulta con una función inyectada.
"""

import hashlib
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from portero.crypto.errors import TokenVerificationError
from portero.crypto.signing import JwtSigner

TokenType = Literal["access", "refresh", "service"]
ActorType = Literal["human", "service"]

AUDIENCE = "portero-cloud"
ACCESS_TTL = timedelta(minutes=15)
"""Vida del access token (Cap. 6 §Emisión del par de tokens; OWASP JWT Cheat Sheet)."""

SESSION_TTL = timedelta(hours=12)
IDLE_TTL = timedelta(minutes=30)
"""Límites de la sesión de un humano (H-61; OWASP ASVS 4.0.3 V3.3.2, L2: reautenticar tras 12
horas de uso o 30 minutos de inactividad). Sustituyen los 7 días del Cap. 6, que se contaban de
nuevo en cada renovación.

- ``SESSION_TTL``, absoluto: se cuenta desde el login (claim ``auth_time``, que cada rotación
  hereda) y renovar no lo mueve.
- ``IDLE_TTL``, por inactividad: cada refresh vence 30 min después de emitirse, así que quien
  sigue usando el Dashboard renueva antes y quien lo deja pierde la sesión.

Un refresh vence en ``min(iat + IDLE_TTL, auth_time + SESSION_TTL)``."""

API_TOKEN_TYPES: frozenset[TokenType] = frozenset({"access", "service"})
"""Tipos que autentican peticiones a la API. El refresh token queda fuera (H-25)."""

REFRESH_TOKEN_TYPES: frozenset[TokenType] = frozenset({"refresh"})
"""Único tipo que acepta ``POST /api/v1/auth/refresh`` (Cap. 6 §Renovación)."""

_ACTOR_OF_TYPE: Mapping[str, ActorType] = {
    "access": "human",
    "refresh": "human",
    "service": "service",
}
"""Coherencia ``token_type`` → ``actor_type`` (H-25)."""

_REQUIRED_CLAIMS = ("iss", "sub", "aud", "iat", "jti", "actor_type", "token_type")
"""``exp`` no está aquí: es obligatorio salvo en ``token_type=service`` (H-09) y se revisa
después, cuando ya se conoce el tipo. Lo mismo ``auth_time``, obligatorio solo en el refresh
(H-61)."""

RevocationCheck = Callable[[UUID], Awaitable[bool]]
"""Consulta inyectada: ``True`` si el ``jti`` está en ``revoked_tokens``."""


class TokenRejectedError(Exception):
    """El token no es válido. ``reason`` es una etiqueta estable para el Servicio de Registro de
    Operaciones; al cliente se le responde siempre un 401 genérico. El mensaje no incluye el
    token.

    ``subject`` es el ``sub`` del token, y solo se llena cuando la firma ya se verificó (motivo
    ``revocado``): así ``refresh_reused`` queda registrado con el dueño del token sin confiar en
    un token falsificado (spec Fase 5 §3.2 y §5.3).
    """

    def __init__(self, reason: str, *, subject: UUID | None = None) -> None:
        super().__init__(f"token rechazado: {reason}")
        self.reason = reason
        self.subject = subject


@dataclass(frozen=True)
class IssuedToken:
    """Token recién emitido. ``jti`` y ``expires_at`` son lo que se guarda en
    ``revoked_tokens`` si después se revoca (``expires_at`` es ``None`` en un PAT sin
    vencimiento)."""

    token: str
    jti: UUID
    expires_at: datetime | None


@dataclass(frozen=True)
class TokenScope:
    """Claim ``scope`` de un PAT: proyecto y, opcionalmente, ambiente."""

    project_id: UUID
    environment_id: UUID | None


@dataclass(frozen=True)
class VerifiedToken:
    """Claims de un token que pasó todas las verificaciones. ``roles`` es informativo: el
    Módulo RBAC autoriza con las asignaciones vigentes en la BD, no con este claim."""

    sub: UUID
    jti: UUID
    actor_type: ActorType
    token_type: TokenType
    roles: tuple[str, ...]
    scope: TokenScope | None
    expires_at: datetime | None
    issued_at: datetime
    """Claim ``iat``; se compara con ``users.tokens_invalid_before`` (H-37)."""
    auth_time: datetime | None = None
    """Claim ``auth_time`` (OpenID Connect Core §2): el login que abrió la sesión. Solo en el
    refresh, de donde sale el tope de 12 h (H-61)."""


# --- Emisión ------------------------------------------------------------------------------------


def _check_aware(valor: datetime) -> datetime:
    if valor.tzinfo is None:
        raise ValueError("las fechas de los tokens deben tener zona horaria")
    return valor


def _sign(
    signer: JwtSigner,
    *,
    sub: UUID,
    actor_type: ActorType,
    kind: TokenType,
    issuer: str,
    now: datetime | None,
    expires_at: datetime | None,
    extra: Mapping[str, Any],
) -> IssuedToken:
    emitido = _check_aware(now) if now is not None else datetime.now(UTC)
    jti = uuid.uuid4()  # uuid4 usa os.urandom (CSPRNG del sistema operativo)
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": str(sub),
        "aud": AUDIENCE,
        "iat": int(emitido.timestamp()),
        "jti": str(jti),
        "actor_type": actor_type,
        "token_type": kind,
        **extra,
    }
    vence: datetime | None = None
    if expires_at is not None:
        claims["exp"] = int(_check_aware(expires_at).timestamp())
        # Se reporta el vencimiento que dice el token (segundos enteros), no el de entrada.
        vence = datetime.fromtimestamp(claims["exp"], UTC)
    return IssuedToken(token=signer.sign_token(claims), jti=jti, expires_at=vence)


def issue_access_token(
    signer: JwtSigner,
    *,
    user_id: UUID,
    roles: Sequence[str],
    issuer: str,
    now: datetime | None = None,
    not_after: datetime | None = None,
) -> IssuedToken:
    """Access token de un humano, vigente 15 minutos (Cap. 6 §Emisión del par de tokens).

    ``not_after`` es el fin de la sesión (H-61): si llega antes, el token vence con ella.
    """
    emitido = _check_aware(now) if now is not None else datetime.now(UTC)
    vence = emitido + ACCESS_TTL
    if not_after is not None:
        vence = min(vence, _check_aware(not_after))
    return _sign(
        signer,
        sub=user_id,
        actor_type="human",
        kind="access",
        issuer=issuer,
        now=emitido,
        expires_at=vence,
        extra={"roles": list(roles)},
    )


def issue_refresh_token(
    signer: JwtSigner,
    *,
    user_id: UUID,
    issuer: str,
    now: datetime | None = None,
    auth_time: datetime | None = None,
) -> IssuedToken:
    """Refresh token de un humano. No lleva ``roles``: solo sirve para canjearse por un par nuevo
    (Cap. 6 §Renovación con refresh token).

    ``auth_time`` es el login que abrió la sesión: ``None`` en el login (vale ``now``); en la
    rotación, el del refresh canjeado. Vence en ``min(now + IDLE_TTL, auth_time + SESSION_TTL)``
    (H-61; OWASP ASVS V3.3.2).
    """
    emitido = _check_aware(now) if now is not None else datetime.now(UTC)
    inicio = _check_aware(auth_time) if auth_time is not None else emitido
    return _sign(
        signer,
        sub=user_id,
        actor_type="human",
        kind="refresh",
        issuer=issuer,
        now=emitido,
        expires_at=min(emitido + IDLE_TTL, inicio + SESSION_TTL),
        extra={"auth_time": int(inicio.timestamp())},
    )


def issue_service_token(
    signer: JwtSigner,
    *,
    service_account_id: UUID,
    project_id: UUID,
    environment_id: UUID | None,
    expires_at: datetime | None,
    issuer: str,
    now: datetime | None = None,
) -> IssuedToken:
    """PAT firmado de una Aplicación Cliente (A-04; Cap. 6 §Generación del token).

    ``sub`` es ``service_accounts.id``; ``scope`` copia su proyecto y ambiente. Sin
    ``expires_at`` el claim ``exp`` se **omite** (H-09): un ``"exp": null`` lo rechazaría PyJWT.
    """
    return _sign(
        signer,
        sub=service_account_id,
        actor_type="service",
        kind="service",
        issuer=issuer,
        now=now,
        expires_at=expires_at,
        extra={
            "scope": {
                "project_id": str(project_id),
                "environment_id": str(environment_id) if environment_id is not None else None,
            }
        },
    )


PAT_PREFIX_LENGTH = 8
"""Caracteres del PAT que se guardan en ``token_prefix`` (spec núcleo §3.3; H-42)."""


@dataclass(frozen=True)
class IssuedPersonalAccessToken:
    """PAT recién emitido con lo único que se persiste de él (spec núcleo §3.3; H-21).

    ``token`` se entrega **una sola vez** al operador y no se guarda. ``token_hash`` va a
    ``service_accounts.token_hash`` y ``token_prefix`` a ``service_accounts.token_prefix``.
    """

    token: str
    token_hash: str
    token_prefix: str
    expires_at: datetime | None


def personal_access_token_hash(token: str) -> str:
    """``SHA-256(token)`` en hexadecimal (spec núcleo §3.3; OWASP ASVS V2.10.4).

    Basta un hash rápido sin sal, a diferencia de una contraseña: el token es un JWT firmado con
    256 bits de entropía en la firma, así que no hay diccionario que probar. Si la tabla se filtra,
    el hash no sirve para autenticarse.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def issue_personal_access_token(
    signer: JwtSigner,
    *,
    service_account_id: UUID,
    project_id: UUID,
    environment_id: UUID | None,
    expires_at: datetime | None,
    issuer: str,
    now: datetime | None = None,
) -> IssuedPersonalAccessToken:
    """Emite el PAT de una Aplicación Cliente (Cap. 6 §Autenticación de Aplicaciones Cliente;
    H-09, H-21) con su hash y su prefijo.

    **H-42.** ``token_prefix`` son los **últimos** ``PAT_PREFIX_LENGTH`` caracteres, que caen en
    la firma Ed25519: los primeros serían la cabecera del JWT, igual en todos los tokens
    (``eyJhbGci``). Así el Dashboard puede mostrar "termina en …" para reconocer un token sin
    guardarlo. La firma es pública dentro del token y 8 caracteres (48 bits) no ayudan a
    reconstruirlo.
    """
    issued = issue_service_token(
        signer,
        service_account_id=service_account_id,
        project_id=project_id,
        environment_id=environment_id,
        expires_at=expires_at,
        issuer=issuer,
        now=now,
    )
    return IssuedPersonalAccessToken(
        token=issued.token,
        token_hash=personal_access_token_hash(issued.token),
        token_prefix=issued.token[-PAT_PREFIX_LENGTH:],
        expires_at=issued.expires_at,
    )


# --- Validación ---------------------------------------------------------------------------------


def _parse_uuid(valor: object) -> UUID:
    if not isinstance(valor, str):
        raise TokenRejectedError("claim_invalido")
    try:
        return UUID(valor)
    except ValueError:
        raise TokenRejectedError("claim_invalido") from None


def _parse_scope(valor: object) -> TokenScope:
    if not isinstance(valor, dict):
        raise TokenRejectedError("claim_invalido")
    ambiente = valor.get("environment_id")
    return TokenScope(
        project_id=_parse_uuid(valor.get("project_id")),
        environment_id=_parse_uuid(ambiente) if ambiente is not None else None,
    )


def _parse_auth_time(valor: object, iat: int) -> datetime:
    """``auth_time`` del refresh: entero y no posterior a ``iat`` (H-61). Sin él no se puede
    aplicar el tope de 12 h, así que falla cerrado."""
    if not isinstance(valor, int) or isinstance(valor, bool) or valor > iat:
        raise TokenRejectedError("claim_invalido")
    return datetime.fromtimestamp(valor, UTC)


def _parse_roles(valor: object) -> tuple[str, ...]:
    if not isinstance(valor, list) or not all(isinstance(r, str) for r in valor):
        raise TokenRejectedError("claim_invalido")
    return tuple(valor)


async def validate_token(
    token: str,
    *,
    signer: JwtSigner,
    issuer: str,
    accepted_types: frozenset[TokenType],
    is_revoked: RevocationCheck,
) -> VerifiedToken:
    """Algoritmo de verificación de un JWT entrante (Cap. 6) más dos reglas de esta
    implementación:

    1. Pasos 1–8 en ``JwtSigner.verify_token``: cabecera, firma, ``exp`` si existe, ``iss`` y
       ``aud``.
    2. H-25: ``token_type`` debe ser coherente con ``actor_type`` y estar en ``accepted_types``
       (la API acepta ``API_TOKEN_TYPES``; ``/auth/refresh``, ``REFRESH_TOKEN_TYPES``).
    3. H-09: ``exp`` es obligatorio salvo para ``token_type=service``.
    4. Formato de ``sub``, ``jti``, ``roles`` y ``scope``.
    5. Paso 9: ``jti`` no revocado. Va al final, para que un token falsificado nunca llegue a
       consultar la base de datos.

    Cualquier fallo lanza ``TokenRejectedError``.
    """
    try:
        claims = signer.verify_token(
            token, audience=AUDIENCE, issuer=issuer, required_claims=_REQUIRED_CLAIMS
        )
    except TokenVerificationError as exc:
        raise TokenRejectedError(exc.reason) from None

    token_type = claims["token_type"]
    actor_type = claims["actor_type"]
    if not isinstance(token_type, str) or not isinstance(actor_type, str):
        # H-34: un valor no hashable (p. ej. una lista) haría fallar la búsqueda de abajo con
        # TypeError en lugar de rechazar el token.
        raise TokenRejectedError("claim_invalido")
    if token_type not in _ACTOR_OF_TYPE:
        raise TokenRejectedError("tipo")
    if _ACTOR_OF_TYPE[token_type] != actor_type:
        raise TokenRejectedError("actor")
    if token_type not in accepted_types:
        raise TokenRejectedError("tipo")
    if token_type != "service" and "exp" not in claims:  # noqa: S105  # tipo, no contraseña
        raise TokenRejectedError("exp_faltante")

    sub = _parse_uuid(claims["sub"])
    jti = _parse_uuid(claims["jti"])
    if actor_type == "service":
        scope: TokenScope | None = _parse_scope(claims.get("scope"))
        roles: tuple[str, ...] = ()
    else:
        scope = None
        roles = _parse_roles(claims.get("roles", []))

    if await is_revoked(jti):
        raise TokenRejectedError("revocado", subject=sub)

    exp = claims.get("exp")
    iat = claims["iat"]
    if not isinstance(iat, int):
        raise TokenRejectedError("claim_invalido")
    auth_time = (
        _parse_auth_time(claims.get("auth_time"), iat)
        if token_type == "refresh"  # noqa: S105  # tipo, no contraseña
        else None
    )
    return VerifiedToken(
        sub=sub,
        jti=jti,
        actor_type=actor_type,
        token_type=token_type,
        roles=roles,
        scope=scope,
        expires_at=datetime.fromtimestamp(exp, UTC) if exp is not None else None,
        issued_at=datetime.fromtimestamp(iat, UTC),
        auth_time=auth_time,
    )


# --- Revocación en bloque (H-37) ----------------------------------------------------------------


def cutoff_from(now: datetime) -> datetime:
    """Valor de ``users.tokens_invalid_before`` para un evento ocurrido en ``now`` (H-37; spec
    Fase 5 §3.5): ``T = floor(now) + 1 s``.

    ``iat`` es un entero en segundos y ``now`` tiene microsegundos. Redondear hacia arriba
    garantiza que todo token emitido antes del evento, incluso en el mismo segundo, quede
    invalidado (falla cerrado). El costo es una ventana de a lo más 1 s en la que también cae un
    token recién emitido.
    """
    return _check_aware(now).replace(microsecond=0) + timedelta(seconds=1)


def predates_cutoff(issued_at: datetime, cutoff: datetime | None) -> bool:
    """``True`` si el token se emitió antes del corte y debe rechazarse (H-37). Sin corte
    (``tokens_invalid_before`` en NULL) ningún token queda invalidado."""
    return cutoff is not None and issued_at < cutoff
