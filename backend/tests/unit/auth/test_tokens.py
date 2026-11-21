"""Pruebas de emisión y validación de tokens (Cap. 6 §Estructura del JWT, Algoritmo de
verificación de un JWT entrante; spec §3.2; H-09, H-25).

Cada rechazo se comprueba por su ``reason``, no solo porque "lanzó algo": así una prueba de
``alg=none`` no pasa por accidente porque el token estaba, además, expirado.

Las claves Ed25519 se generan en cada prueba; los tokens "de atacante" se arman con PyJWT o a
mano con la clave de la prueba, igual que lo haría alguien que solo conoce la clave pública.
"""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import portero.auth.tokens as tokens_mod
from portero.auth.tokens import (
    ACCESS_TTL,
    API_TOKEN_TYPES,
    AUDIENCE,
    IDLE_TTL,
    REFRESH_TOKEN_TYPES,
    SESSION_TTL,
    TokenRejectedError,
    TokenType,
    VerifiedToken,
    issue_access_token,
    issue_personal_access_token,
    issue_refresh_token,
    issue_service_token,
    personal_access_token_hash,
    validate_token,
)
from portero.crypto.signing import JwtSigner

ISS = "https://portero.example.test"
USUARIO = UUID("11111111-1111-4111-8111-111111111111")
CUENTA = UUID("22222222-2222-4222-8222-222222222222")
PROYECTO = UUID("33333333-3333-4333-8333-333333333333")
AMBIENTE = UUID("44444444-4444-4444-8444-444444444444")


class Revocados:
    """Doble de la consulta a ``revoked_tokens`` (la función inyectada ``is_revoked``)."""

    def __init__(self, *jtis: UUID) -> None:
        self.jtis = set(jtis)
        self.consultas: list[UUID] = []

    async def __call__(self, jti: UUID) -> bool:
        self.consultas.append(jti)
        return jti in self.jtis


@pytest.fixture
def clave() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def signer(clave: Ed25519PrivateKey) -> JwtSigner:
    pem = clave.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return JwtSigner.from_pem(pem)


def _ahora() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _b64(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def _b64_json(objeto: object) -> str:
    return _b64(json.dumps(objeto, separators=(",", ":")).encode())


def _claims(**cambios: object) -> dict[str, object]:
    """Claims de un access token válido; ``cambios`` sobrescribe (``None`` elimina el claim)."""
    ahora = int(_ahora().timestamp())
    base: dict[str, object] = {
        "iss": ISS,
        "sub": str(USUARIO),
        "aud": AUDIENCE,
        "iat": ahora,
        "exp": ahora + 900,
        "jti": str(uuid4()),
        "actor_type": "human",
        "token_type": "access",
        "roles": ["desarrollador"],
    }
    base.update(cambios)
    return {k: v for k, v in base.items() if v is not None}


async def _validar(
    signer: JwtSigner,
    token: str,
    *,
    tipos: frozenset[TokenType] = API_TOKEN_TYPES,
    revocados: Revocados | None = None,
    issuer: str = ISS,
) -> VerifiedToken:
    return await validate_token(
        token,
        signer=signer,
        issuer=issuer,
        accepted_types=tipos,
        is_revoked=revocados if revocados is not None else Revocados(),
    )


async def _rechazo(signer: JwtSigner, token: str, **kwargs: object) -> str:
    revocados = Revocados()
    with pytest.raises(TokenRejectedError) as exc:
        await _validar(signer, token, revocados=revocados, **kwargs)  # type: ignore[arg-type]
    if token:  # la cadena vacía está "contenida" en cualquier texto
        assert token not in str(exc.value)
    return exc.value.reason


def _payload_sin_verificar(token: str) -> dict[str, object]:
    return jwt.decode(token, options={"verify_signature": False})  # type: ignore[no-any-return]


# --- Tokens válidos -------------------------------------------------------------------------------


async def test_access_token_valido(signer: JwtSigner) -> None:
    ahora = _ahora()
    emitido = issue_access_token(
        signer, user_id=USUARIO, roles=["administrador"], issuer=ISS, now=ahora
    )

    v = await validate_token(
        emitido.token,
        signer=signer,
        issuer=ISS,
        accepted_types=API_TOKEN_TYPES,
        is_revoked=Revocados(),
    )

    assert v.sub == USUARIO
    assert v.jti == emitido.jti
    assert (v.actor_type, v.token_type) == ("human", "access")
    assert v.roles == ("administrador",)
    assert v.scope is None
    assert emitido.expires_at == ahora + ACCESS_TTL == ahora + timedelta(minutes=15)
    assert v.expires_at == emitido.expires_at
    assert set(_payload_sin_verificar(emitido.token)) == {
        "iss", "sub", "aud", "iat", "exp", "jti", "actor_type", "token_type", "roles"
    }  # fmt: skip
    assert _payload_sin_verificar(emitido.token)["aud"] == "portero-cloud"


async def test_refresh_token_valido(signer: JwtSigner) -> None:
    ahora = _ahora()
    emitido = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS, now=ahora)

    v = await _validar(signer, emitido.token, tipos=REFRESH_TOKEN_TYPES)

    assert v.token_type == "refresh"  # noqa: S105  # tipo de token, no una contraseña
    # H-61 (OWASP ASVS V3.3.2, L2): en el login, 30 min de inactividad; auth_time = iat.
    assert emitido.expires_at == ahora + IDLE_TTL == ahora + timedelta(minutes=30)
    assert v.auth_time == ahora
    assert _payload_sin_verificar(emitido.token)["auth_time"] == int(ahora.timestamp())
    assert "roles" not in _payload_sin_verificar(emitido.token)


async def test_refresh_rotado_conserva_auth_time_y_da_otros_30_minutos(signer: JwtSigner) -> None:
    """H-61: renovar reinicia la inactividad, pero el inicio de la sesión no cambia."""
    ahora = _ahora()
    inicio = ahora - timedelta(hours=1)

    emitido = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS, now=ahora, auth_time=inicio)

    v = await _validar(signer, emitido.token, tipos=REFRESH_TOKEN_TYPES)
    assert emitido.expires_at == ahora + IDLE_TTL
    assert v.auth_time == inicio


async def test_refresh_no_rebasa_las_12_horas_desde_el_login(signer: JwtSigner) -> None:
    ahora = _ahora()
    inicio = ahora - timedelta(hours=11, minutes=50)

    emitido = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS, now=ahora, auth_time=inicio)

    assert emitido.expires_at == inicio + SESSION_TTL == ahora + timedelta(minutes=10)


@pytest.mark.parametrize(
    "auth_time",
    [None, "1700000000", 1.5, "futuro"],
    ids=["sin-auth-time", "texto", "flotante", "posterior-al-iat"],
)
async def test_refresh_sin_auth_time_valido_se_rechaza(
    signer: JwtSigner, auth_time: object
) -> None:
    """Sin el inicio de la sesión no se puede aplicar el tope de 12 h: falla cerrado (H-61).
    Tampoco se acepta un ``auth_time`` posterior a la emisión."""
    claims = _claims(token_type="refresh", roles=None)  # noqa: S106  # tipo, no contraseña
    if auth_time == "futuro":
        auth_time = int(claims["iat"]) + 60  # type: ignore[call-overload]
    claims["auth_time"] = auth_time
    token = signer.sign_token({k: v for k, v in claims.items() if v is not None})

    assert await _rechazo(signer, token, tipos=REFRESH_TOKEN_TYPES) == "claim_invalido"


async def test_access_no_vive_mas_que_la_sesion(signer: JwtSigner) -> None:
    """H-61: cerca del fin de la sesión el access vence con ella, no 15 minutos después."""
    ahora = _ahora()
    fin_de_sesion = ahora + timedelta(minutes=5)

    corto = issue_access_token(
        signer, user_id=USUARIO, roles=[], issuer=ISS, now=ahora, not_after=fin_de_sesion
    )
    lejos = issue_access_token(
        signer, user_id=USUARIO, roles=[], issuer=ISS, now=ahora, not_after=ahora + SESSION_TTL
    )

    assert corto.expires_at == fin_de_sesion
    assert lejos.expires_at == ahora + ACCESS_TTL


async def test_jti_distinto_en_cada_emision(signer: JwtSigner) -> None:
    a = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS)
    b = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS)

    assert a.jti != b.jti
    assert a.jti.version == 4


async def test_pat_sin_exp_es_aceptado(signer: JwtSigner) -> None:
    """H-09: un PAT puede no tener ``exp`` (Cap. 6 §Generación del token)."""
    emitido = issue_service_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=AMBIENTE,
        expires_at=None,
        issuer=ISS,
    )

    v = await _validar(signer, emitido.token)

    assert emitido.expires_at is None
    assert "exp" not in _payload_sin_verificar(emitido.token)
    assert "roles" not in _payload_sin_verificar(emitido.token)
    assert v.sub == CUENTA
    assert (v.actor_type, v.token_type) == ("service", "service")
    assert v.scope.project_id == PROYECTO
    assert v.scope.environment_id == AMBIENTE
    assert v.expires_at is None


async def test_emision_de_pat_guarda_solo_hash_y_prefijo(signer: JwtSigner) -> None:
    """Spec núcleo §3.3 y H-42: se persiste ``SHA-256(token)`` en hex y los últimos 8
    caracteres (de la firma), nunca el token. ``token[:8]`` sería siempre ``eyJhbGci``."""
    emitido = issue_personal_access_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=AMBIENTE,
        expires_at=None,
        issuer=ISS,
    )

    assert emitido.token_hash == hashlib.sha256(emitido.token.encode()).hexdigest()
    assert len(emitido.token_hash) == 64
    assert emitido.token_prefix == emitido.token[-8:]
    assert emitido.token_prefix == emitido.token.rsplit(".", 1)[1][-8:]  # de la firma
    assert personal_access_token_hash(emitido.token) == emitido.token_hash
    v = await _validar(signer, emitido.token)
    assert (v.sub, v.token_type, v.expires_at) == (CUENTA, "service", None)
    assert emitido.expires_at is None


def test_dos_pat_tienen_prefijos_y_hashes_distintos(signer: JwtSigner) -> None:
    """H-42: el prefijo sirve para distinguir tokens (con ``token[:8]`` serían iguales)."""
    emitidos = [
        issue_personal_access_token(
            signer,
            service_account_id=uuid4(),
            project_id=PROYECTO,
            environment_id=None,
            expires_at=None,
            issuer=ISS,
        )
        for _ in range(2)
    ]

    assert emitidos[0].token[:8] == emitidos[1].token[:8]  # la cabecera JWT es constante
    assert emitidos[0].token_prefix != emitidos[1].token_prefix
    assert emitidos[0].token_hash != emitidos[1].token_hash


def test_pat_con_expires_at_reporta_el_exp_del_token(signer: JwtSigner) -> None:
    vence = _ahora() + timedelta(days=30, microseconds=500)
    emitido = issue_personal_access_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=None,
        expires_at=vence,
        issuer=ISS,
    )

    assert emitido.expires_at == vence.replace(microsecond=0)
    assert _payload_sin_verificar(emitido.token)["exp"] == int(vence.timestamp())


async def test_pat_de_proyecto_completo_y_con_expiracion(signer: JwtSigner) -> None:
    vence = _ahora() + timedelta(days=30)
    emitido = issue_service_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=None,
        expires_at=vence,
        issuer=ISS,
    )

    v = await _validar(signer, emitido.token)

    assert v.scope.environment_id is None
    assert v.expires_at == vence == emitido.expires_at


def test_la_emision_exige_fechas_con_zona_horaria(signer: JwtSigner) -> None:
    sin_zona = datetime(2026, 10, 8, 12, 0, 0)  # noqa: DTZ001

    with pytest.raises(ValueError, match="zona horaria"):
        issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS, now=sin_zona)
    with pytest.raises(ValueError, match="zona horaria"):
        issue_service_token(
            signer,
            service_account_id=CUENTA,
            project_id=PROYECTO,
            environment_id=None,
            expires_at=sin_zona,
            issuer=ISS,
        )


# --- Vigencia (paso 6 del Algoritmo; H-09) --------------------------------------------------------


async def test_access_expirado(signer: JwtSigner) -> None:
    hace_16_min = _ahora() - timedelta(minutes=16)
    emitido = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS, now=hace_16_min)

    assert await _rechazo(signer, emitido.token) == "expirado"


async def test_pat_con_expires_at_vencido(signer: JwtSigner) -> None:
    emitido = issue_service_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=None,
        expires_at=_ahora() - timedelta(seconds=5),
        issuer=ISS,
        now=_ahora() - timedelta(days=1),
    )

    assert await _rechazo(signer, emitido.token) == "expirado"


async def test_access_sin_exp_es_rechazado(signer: JwtSigner) -> None:
    """H-09: ``exp`` es obligatorio salvo para ``token_type=service``."""
    token = signer.sign_token(_claims(exp=None))

    assert await _rechazo(signer, token) == "exp_faltante"


async def test_refresh_sin_exp_es_rechazado(signer: JwtSigner) -> None:
    sin_exp = _claims(exp=None, token_type="refresh", roles=None)  # noqa: S106  # tipo de token
    token = signer.sign_token(sin_exp)

    assert await _rechazo(signer, token, tipos=REFRESH_TOKEN_TYPES) == "exp_faltante"


# --- Cabecera y firma (pasos 1–5 del Algoritmo) ---------------------------------------------------


async def test_firma_alterada(signer: JwtSigner) -> None:
    token = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS).token
    cabecera, payload, firma = token.split(".")
    # Se cambia un carácter intermedio: el último lleva bits de relleno y podría no cambiar nada.
    otra = firma[:10] + ("A" if firma[10] != "A" else "B") + firma[11:]

    assert await _rechazo(signer, f"{cabecera}.{payload}.{otra}") == "firma"


async def test_payload_alterado_con_firma_original(signer: JwtSigner) -> None:
    token = issue_access_token(signer, user_id=USUARIO, roles=["desarrollador"], issuer=ISS).token
    cabecera, _, firma = token.split(".")
    escalado = _b64_json(_claims(roles=["administrador"]))

    assert await _rechazo(signer, f"{cabecera}.{escalado}.{firma}") == "firma"


async def test_alg_none_rechazado(signer: JwtSigner) -> None:
    token = jwt.encode(_claims(), None, algorithm="none", headers={"kid": signer.kid})

    assert await _rechazo(signer, token) == "cabecera"


async def test_alg_hs256_con_la_clave_publica_como_secreto(
    signer: JwtSigner, clave: Ed25519PrivateKey
) -> None:
    """Ataque clásico de confusión de algoritmo: el atacante firma con HMAC usando la clave
    pública (que es pública) como secreto, esperando que el verificador use esa misma clave
    para HS256 (Cap. 6, paso 2 del Algoritmo; OWASP JWT Cheat Sheet)."""
    publica_pem = clave.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    cabecera = _b64_json({"alg": "HS256", "typ": "JWT", "kid": signer.kid})
    entrada = f"{cabecera}.{_b64_json(_claims())}"
    mac = hmac.HMAC(publica_pem, hashes.SHA256())
    mac.update(entrada.encode())

    assert await _rechazo(signer, f"{entrada}.{_b64(mac.finalize())}") == "cabecera"


async def test_alg_hs256_en_cabecera_de_token_eddsa(signer: JwtSigner) -> None:
    token = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS).token
    _, payload, firma = token.split(".")
    cabecera = _b64_json({"alg": "HS256", "typ": "JWT", "kid": signer.kid})

    assert await _rechazo(signer, f"{cabecera}.{payload}.{firma}") == "cabecera"


async def test_typ_distinto_de_jwt(signer: JwtSigner, clave: Ed25519PrivateKey) -> None:
    token = jwt.encode(
        _claims(), clave, algorithm="EdDSA", headers={"typ": "at+jwt", "kid": signer.kid}
    )

    assert await _rechazo(signer, token) == "cabecera"


async def test_kid_desconocido(signer: JwtSigner, clave: Ed25519PrivateKey) -> None:
    token = jwt.encode(_claims(), clave, algorithm="EdDSA", headers={"kid": "otra-clave"})

    assert await _rechazo(signer, token) == "cabecera"


async def test_otra_clave_ed25519_con_el_mismo_kid(signer: JwtSigner) -> None:
    impostora = Ed25519PrivateKey.generate()
    token = jwt.encode(_claims(), impostora, algorithm="EdDSA", headers={"kid": signer.kid})

    assert await _rechazo(signer, token) == "firma"


@pytest.mark.parametrize(
    ("token", "razon"),
    [
        ("no-es-un-jwt", "malformado"),
        ("a.b.c", "malformado"),
        ("", "malformado"),
        ("e30.e30.e30", "cabecera"),  # cabecera "{}": JSON válido pero sin alg/typ/kid
    ],
)
async def test_texto_que_no_es_jwt(signer: JwtSigner, token: str, razon: str) -> None:
    assert await _rechazo(signer, token) == razon


@pytest.mark.parametrize(
    "kid", [123, None, ["a"], {"x": 1}], ids=["entero", "nulo", "lista", "objeto"]
)
async def test_kid_que_no_es_texto(signer: JwtSigner, kid: object) -> None:
    """H-26: la cabecera se lee antes de autenticar, así que cualquiera la controla. PyJWT
    rechaza un ``kid`` no textual con ``InvalidTokenError`` (no ``DecodeError``); también debe
    terminar en ``TokenRejectedError`` y no escapar como excepción no controlada."""
    token = _b64_json({"alg": "EdDSA", "typ": "JWT", "kid": kid}) + "." + _b64_json({}) + ".AAAA"

    assert await _rechazo(signer, token) == "cabecera"


async def test_sin_firma_valida_no_se_consulta_la_revocacion(signer: JwtSigner) -> None:
    """El paso 9 (consulta a la BD) va al final: un token falsificado no genera consultas."""
    impostora = Ed25519PrivateKey.generate()
    token = jwt.encode(_claims(), impostora, algorithm="EdDSA", headers={"kid": signer.kid})
    revocados = Revocados()

    with pytest.raises(TokenRejectedError):
        await _validar(signer, token, revocados=revocados)

    assert revocados.consultas == []


# --- Claims registrados (pasos 7–8) ---------------------------------------------------------------


async def test_aud_incorrecta(signer: JwtSigner) -> None:
    token = signer.sign_token(_claims(aud="otra-aplicacion"))

    assert await _rechazo(signer, token) == "audiencia"


async def test_iss_incorrecto(signer: JwtSigner) -> None:
    token = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS).token

    assert await _rechazo(signer, token, issuer="https://otra-instalacion.example") == "emisor"


@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "iat", "jti", "actor_type", "token_type"])
async def test_claim_obligatorio_faltante(signer: JwtSigner, claim: str) -> None:
    token = signer.sign_token(_claims(**{claim: None}))

    assert await _rechazo(signer, token) == "claim_faltante"


@pytest.mark.parametrize(
    "cambios",
    [
        {"sub": "no-es-uuid"},
        {"jti": "no-es-uuid"},
        {"roles": "administrador"},
        {"roles": [1, 2]},
        {"actor_type": "service", "token_type": "service", "scope": None},
        {"actor_type": "service", "token_type": "service", "scope": {"project_id": "x"}},
        {"actor_type": "service", "token_type": "service", "scope": ["no-es-objeto"]},
        {"actor_type": "service", "token_type": "service", "scope": {"project_id": 7}},
        {
            "actor_type": "service",
            "token_type": "service",
            "scope": {"project_id": str(PROYECTO), "environment_id": "x"},
        },
    ],
    ids=[
        "sub",
        "jti",
        "roles-no-lista",
        "roles-no-texto",
        "service-sin-scope",
        "scope-proyecto-invalido",
        "scope-no-objeto",
        "scope-proyecto-no-texto",
        "scope-ambiente-invalido",
    ],
)
async def test_claims_con_formato_invalido(signer: JwtSigner, cambios: dict[str, object]) -> None:
    token = signer.sign_token(_claims(**cambios))

    assert await _rechazo(signer, token) == "claim_invalido"


async def test_iat_en_el_futuro(signer: JwtSigner) -> None:
    futuro = int(_ahora().timestamp()) + 3600
    token = signer.sign_token(_claims(iat=futuro, exp=futuro + 900))

    assert await _rechazo(signer, token) == "invalido"


async def test_sub_que_no_es_texto(signer: JwtSigner) -> None:
    """PyJWT exige que ``sub`` sea texto (RFC 7519 §4.1.2) antes de que se intente leer el UUID."""
    token = signer.sign_token(_claims(sub=12345))

    assert await _rechazo(signer, token) == "invalido"


async def test_payload_que_no_es_json_aunque_este_firmado(
    signer: JwtSigner, clave: Ed25519PrivateKey
) -> None:
    """La firma se verifica antes de interpretar el payload; aquí la firma es válida y lo que
    falla es el JSON."""
    token = jwt.api_jws.encode(
        b"no es json", clave, algorithm="EdDSA", headers={"typ": "JWT", "kid": signer.kid}
    )

    assert await _rechazo(signer, token) == "malformado"


# --- H-25: tipo de token y coherencia con el actor ------------------------------------------------


async def test_refresh_no_sirve_como_access(signer: JwtSigner) -> None:
    """Un refresh token (7 días) no autentica peticiones a la API (H-25)."""
    token = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS).token

    assert await _rechazo(signer, token, tipos=API_TOKEN_TYPES) == "tipo"


async def test_access_no_sirve_para_renovar(signer: JwtSigner) -> None:
    token = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS).token

    assert await _rechazo(signer, token, tipos=REFRESH_TOKEN_TYPES) == "tipo"


async def test_pat_no_sirve_para_renovar(signer: JwtSigner) -> None:
    token = issue_service_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=None,
        expires_at=None,
        issuer=ISS,
    ).token

    assert await _rechazo(signer, token, tipos=REFRESH_TOKEN_TYPES) == "tipo"


@pytest.mark.parametrize(
    "cambios",
    [
        {"token_type": ["access"]},
        {"token_type": {"t": "access"}},
        {"actor_type": ["human"]},
        {"token_type": 1},
    ],
    ids=["token-type-lista", "token-type-objeto", "actor-type-lista", "token-type-entero"],
)
async def test_tipos_que_no_son_texto(signer: JwtSigner, cambios: dict[str, object]) -> None:
    """H-34: ``token_type`` y ``actor_type`` deben ser texto. Una lista no es *hashable* y su
    búsqueda en la tabla de coherencia lanzaba ``TypeError`` en lugar de ``TokenRejectedError``.
    Solo alcanzable con un token firmado por el sistema: es robustez del contrato."""
    token = signer.sign_token(_claims(**cambios))

    assert await _rechazo(signer, token) == "claim_invalido"


async def test_token_type_desconocido(signer: JwtSigner) -> None:
    token = signer.sign_token(_claims(token_type="admin"))  # noqa: S106  # tipo de token

    assert await _rechazo(signer, token) == "tipo"


async def test_humano_con_token_type_service_no_evade_exp(signer: JwtSigner) -> None:
    """Sin la regla de coherencia, ``actor_type=human`` + ``token_type=service`` pasaría sin
    ``exp`` (H-09) y llegaría al Módulo RBAC como humano (H-25)."""
    token = signer.sign_token(
        _claims(
            exp=None,
            token_type="service",  # noqa: S106  # tipo de token, no una contraseña
            scope={"project_id": str(PROYECTO), "environment_id": None},
        )
    )

    assert await _rechazo(signer, token) == "actor"


async def test_service_con_token_type_access(signer: JwtSigner) -> None:
    token = signer.sign_token(_claims(actor_type="service"))

    assert await _rechazo(signer, token) == "actor"


# --- Revocación (paso 9) --------------------------------------------------------------------------


async def test_jti_revocado(signer: JwtSigner) -> None:
    emitido = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS)
    revocados = Revocados(emitido.jti)

    with pytest.raises(TokenRejectedError) as exc:
        await _validar(signer, emitido.token, revocados=revocados)

    assert exc.value.reason == "revocado"
    assert revocados.consultas == [emitido.jti]


async def test_pat_revocado(signer: JwtSigner) -> None:
    emitido = issue_service_token(
        signer,
        service_account_id=CUENTA,
        project_id=PROYECTO,
        environment_id=AMBIENTE,
        expires_at=None,
        issuer=ISS,
    )

    with pytest.raises(TokenRejectedError) as exc:
        await _validar(signer, emitido.token, revocados=Revocados(emitido.jti))

    assert exc.value.reason == "revocado"


# --- H-37: revocación en bloque por tokens_invalid_before (spec Fase 5 §3.5) -------------------
#
# Las funciones nuevas se leen como atributos del módulo (no en el ``import`` de arriba) para que,
# mientras no existan, solo fallen estas pruebas y no todo el archivo.


async def test_validate_token_expone_iat_como_issued_at(signer: JwtSigner) -> None:
    ahora = _ahora()
    emitido = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS, now=ahora)

    v = await _validar(signer, emitido.token, tipos=REFRESH_TOKEN_TYPES)

    assert v.issued_at == ahora
    assert v.issued_at.tzinfo is not None


def test_cutoff_redondea_hacia_arriba_al_segundo_siguiente() -> None:
    # T = floor(ahora) + 1 s: falla cerrado, todo token emitido antes del evento cae.
    evento = datetime(2026, 10, 11, 12, 0, 0, 250_000, tzinfo=UTC)

    assert tokens_mod.cutoff_from(evento) == datetime(2026, 10, 11, 12, 0, 1, tzinfo=UTC)


def test_cutoff_en_segundo_exacto_tambien_suma_un_segundo() -> None:
    evento = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)

    assert tokens_mod.cutoff_from(evento) == datetime(2026, 10, 11, 12, 0, 1, tzinfo=UTC)


def test_cutoff_exige_zona_horaria() -> None:
    with pytest.raises(ValueError, match="zona horaria"):
        tokens_mod.cutoff_from(datetime(2026, 10, 11, 12, 0, 0))  # noqa: DTZ001


def test_token_emitido_en_el_segundo_del_evento_queda_invalidado() -> None:
    evento = datetime(2026, 10, 11, 12, 0, 0, 900_000, tzinfo=UTC)
    iat = evento.replace(microsecond=0)  # el iat del JWT es un entero en segundos

    assert tokens_mod.predates_cutoff(iat, tokens_mod.cutoff_from(evento)) is True


def test_token_con_iat_igual_al_corte_es_valido() -> None:
    corte = datetime(2026, 10, 11, 12, 0, 1, tzinfo=UTC)

    assert tokens_mod.predates_cutoff(corte, corte) is False


def test_token_un_segundo_antes_del_corte_queda_invalidado() -> None:
    corte = datetime(2026, 10, 11, 12, 0, 1, tzinfo=UTC)

    assert tokens_mod.predates_cutoff(corte - timedelta(seconds=1), corte) is True


def test_sin_corte_ningun_token_queda_invalidado() -> None:
    # users.tokens_invalid_before es NULL mientras nunca se haya revocado en bloque.
    assert tokens_mod.predates_cutoff(_ahora(), None) is False


@pytest.mark.parametrize("iat", [1_791_000_000.5, "1791000000"], ids=["fraccionario", "texto"])
async def test_iat_que_no_es_entero_se_rechaza(signer: JwtSigner, iat: object) -> None:
    # Este sistema solo emite iat enteros (RFC 7519 NumericDate en segundos). PyJWT acepta
    # cualquier valor convertible con int(); aquí se exige el tipo exacto (falla cerrado).
    token = signer.sign_token(_claims(iat=iat))

    assert await _rechazo(signer, token) == "claim_invalido"


async def test_expires_at_coincide_con_el_claim_exp(signer: JwtSigner) -> None:
    # exp es un entero en segundos (RFC 7519 NumericDate): IssuedToken.expires_at debe decir lo
    # mismo que el token, no la fecha con microsegundos de la que se calculó. Es lo que se guarda
    # en revoked_tokens.expires_at y de donde saldrán expires_in y Max-Age.
    ahora = datetime(2026, 10, 11, 12, 0, 0, 750_000, tzinfo=UTC)

    access = issue_access_token(signer, user_id=USUARIO, roles=[], issuer=ISS, now=ahora)
    refresh = issue_refresh_token(signer, user_id=USUARIO, issuer=ISS, now=ahora)

    for emitido in (access, refresh):
        exp = _payload_sin_verificar(emitido.token)["exp"]
        assert emitido.expires_at == datetime.fromtimestamp(exp, UTC)  # type: ignore[arg-type]
    assert access.expires_at == datetime(2026, 10, 11, 12, 15, 0, tzinfo=UTC)
