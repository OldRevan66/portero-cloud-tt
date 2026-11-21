"""Pruebas de la configuración: arranque fallido si falta algo y valores sensibles ocultos."""

import pytest
from pydantic import SecretStr, ValidationError

from portero.config import Settings


def test_falta_variable_obligatoria_impide_arrancar(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sin PORTERO_KEK_PASSPHRASE en el entorno ni en un .env, Settings debe fallar.
    monkeypatch.delenv("PORTERO_KEK_PASSPHRASE", raising=False)
    monkeypatch.setenv("PORTERO_DATABASE_URL", "postgresql+asyncpg://x@localhost/x")
    monkeypatch.setenv("PORTERO_JWT_PRIVATE_KEY", "marcador")

    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]

    assert "kek_passphrase" in str(exc.value)


def test_valores_sensibles_no_aparecen_en_repr(settings: Settings) -> None:
    texto = repr(settings) + str(settings)

    assert "marcador-de-prueba-no-es-secreto" not in texto
    assert "marcador-de-prueba-no-es-una-clave" not in texto


def test_contrasena_de_la_base_no_aparece_en_repr(settings: Settings) -> None:
    """H-28: la URL de la base lleva la contraseña de PostgreSQL (``usuario:contraseña@host``)."""
    texto = repr(settings) + str(settings) + repr(settings.model_dump())

    assert "portero:test@" not in texto
    assert settings.database_url.get_secret_value().startswith("postgresql+asyncpg://")


def test_por_omision_sin_docs_ni_cors(settings: Settings) -> None:
    assert settings.docs_enabled is False
    assert settings.allowed_origins == []


def test_sin_emisor_jwt_no_arranca(monkeypatch: pytest.MonkeyPatch) -> None:
    """``PORTERO_JWT_ISSUER`` es obligatoria: es el ``iss`` de todos los tokens (Cap. 6)."""
    monkeypatch.delenv("PORTERO_JWT_ISSUER", raising=False)
    monkeypatch.setenv("PORTERO_DATABASE_URL", "postgresql+asyncpg://x@localhost/x")
    monkeypatch.setenv("PORTERO_KEK_PASSPHRASE", "marcador")
    monkeypatch.setenv("PORTERO_JWT_PRIVATE_KEY", "marcador")

    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]

    assert "jwt_issuer" in str(exc.value)


def _settings_con_origenes(origenes: list[str]) -> Settings:
    return Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://portero:test@localhost:5433/portero_test",
        kek_passphrase="marcador-de-prueba-no-es-secreto",  # noqa: S106
        jwt_private_key="marcador-de-prueba-no-es-una-clave",  # noqa: S106
        jwt_issuer="https://portero.example.test",
        allowed_origins=origenes,
    )


@pytest.mark.parametrize(
    "origenes",
    [["*"], ["http://localhost:5173", "*"], ["null"], [" * "]],
    ids=["comodin", "comodin-entre-otros", "null", "comodin-con-espacios"],
)
def test_cors_rechaza_comodin_y_null(origenes: list[str]) -> None:
    """H-29: el refresh token viaja en una cookie (Cap. 6), así que CORS lleva credenciales.
    Con ``*`` Starlette refleja cualquier origen y con ``null`` cualquier iframe con sandbox
    podría usar la cookie: ambos se rechazan al arrancar (OWASP ASVS V14.5.3)."""
    with pytest.raises(ValidationError) as exc:
        _settings_con_origenes(origenes)

    assert "allowed_origins" in str(exc.value)


def test_cors_acepta_origenes_explicitos() -> None:
    settings = _settings_con_origenes(["http://localhost:5173", "https://portero.example.test"])

    assert settings.allowed_origins == ["http://localhost:5173", "https://portero.example.test"]


def test_limite_de_autenticacion_por_omision_es_el_del_cap6(settings: Settings) -> None:
    """H-56: configurable para el stack E2E, pero por omisión vale lo de la tabla del Cap. 6."""
    from portero.api.rate_limit import LIMITS, Category

    assert settings.rate_limit_auth_per_minute == LIMITS[Category.AUTH] == 10


def test_nivel_de_log_por_omision_es_info(settings: Settings) -> None:
    assert settings.log_level == "INFO"


def test_nivel_de_log_se_toma_del_entorno(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OWASP ASVS V7.1: el operador elige el nivel sin reconstruir la imagen."""
    monkeypatch.setenv("PORTERO_DATABASE_URL", "postgresql+asyncpg://x@localhost/x")
    monkeypatch.setenv("PORTERO_KEK_PASSPHRASE", "marcador")
    monkeypatch.setenv("PORTERO_JWT_PRIVATE_KEY", "marcador")
    monkeypatch.setenv("PORTERO_JWT_ISSUER", "https://portero.example.test")
    monkeypatch.setenv("PORTERO_LOG_LEVEL", "WARNING")

    assert Settings(_env_file=None).log_level == "WARNING"  # type: ignore[call-arg]


@pytest.mark.parametrize("valor", ["TRACE", "debug ", "CRITICAL", ""])
def test_nivel_de_log_invalido_no_arranca(settings: Settings, valor: str) -> None:
    with pytest.raises(ValidationError):
        Settings(  # type: ignore[call-arg]
            _env_file=None, **{**settings.model_dump(), "log_level": valor}
        )


@pytest.mark.parametrize("valor", [0, -1])
def test_limite_de_autenticacion_no_admite_cero_ni_negativos(
    settings: Settings, valor: int
) -> None:
    with pytest.raises(ValidationError):
        Settings(  # type: ignore[call-arg]
            _env_file=None, **{**settings.model_dump(), "rate_limit_auth_per_minute": valor}
        )


def test_la_firma_del_cierre_es_opcional_y_viene_apagada(settings: Settings) -> None:
    """H-81: sin llaves configuradas la instalación sigue arrancando; la verificación reporta
    "firma diaria sin configurar"."""
    assert settings.oplog_signing_private_key is None
    assert settings.oplog_signing_public_key is None


def test_la_llave_privada_de_la_firma_no_aparece_en_repr(settings: Settings) -> None:
    con_llave = settings.model_copy(
        update={"oplog_signing_private_key": SecretStr("marcador-de-prueba-llave-de-firma")}
    )

    assert "marcador-de-prueba-llave-de-firma" not in repr(con_llave) + str(con_llave)
