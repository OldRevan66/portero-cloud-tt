"""Configuración del sistema leída de variables de entorno con prefijo ``PORTERO_``.

Las variables sin valor por omisión son obligatorias: si falta alguna, crear ``Settings``
lanza ``pydantic.ValidationError`` y el proceso no arranca (fallar temprano, OWASP ASVS V14.1).
Los valores sensibles se guardan como ``SecretStr`` para que no aparezcan en ``repr`` ni en logs.
"""

from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Parámetros de arranque de Portero Cloud.

    Se buscan en el entorno y, en desarrollo, en un ``.env`` del directorio actual o de su
    padre (la raíz del repositorio cuando se ejecuta desde ``backend/``).
    """

    model_config = SettingsConfigDict(
        env_prefix="PORTERO_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: SecretStr
    """URL de SQLAlchemy hacia PostgreSQL 16 con el controlador asíncrono del Cap. 6,
    p. ej. ``postgresql+asyncpg://...``. Es ``SecretStr`` porque incluye la contraseña de la
    base (H-28; OWASP ASVS V7.1.1)."""

    kek_passphrase: SecretStr
    """Passphrase de la que se deriva la KEK con Argon2id (Cap. 6; spec §1.6)."""

    jwt_private_key: SecretStr
    """Clave privada Ed25519 en PEM para firmar JWT (RFC 8037; spec §3.2). Se genera con
    ``scripts/generate_jwt_key.py``."""

    jwt_issuer: str
    """URL canónica de la instalación: claim ``iss`` de todos los tokens (Cap. 6, tabla del
    payload del JWT). Obligatoria: un valor por omisión podría llegar a producción sin que nadie
    lo note."""

    oplog_signing_private_key: SecretStr | None = None
    """Clave privada Ed25519 en PEM de la firma diaria del cierre de la bitácora (H-81). Solo la
    lee ``python -m portero.cli sign-chain``. **Nunca va en el ``.env`` que carga la API**: si la
    API la tuviera, quien la comprometa (y ya tiene la BD) podría volver a firmar una cadena
    reescrita. Llave dedicada, distinta de la del JWT (NIST SP 800-57 Pt. 1 §5.2). Se genera con
    ``scripts/generate_oplog_key.py``."""

    oplog_signing_public_key: str | None = None
    """Clave pública Ed25519 en PEM con la que la API verifica las firmas del cierre (H-81). Si
    falta, la verificación de la cadena reporta "firma diaria sin configurar". No es secreta."""

    allowed_origins: list[str] = []
    """Orígenes permitidos por CORS. Vacío por omisión: ningún origen externo. No admite ``*`` ni
    ``null`` (H-29; ver ``_sin_comodin_ni_null``)."""

    docs_enabled: bool = False
    """Expone ``/docs`` y ``/api/v1/openapi.json`` (Cap. 6 §OpenAPI). Apagado por omisión
    (producción)."""

    rate_limit_auth_per_minute: int = Field(default=10, gt=0)
    """Peticiones por minuto y por IP a ``/auth/login`` y ``/auth/refresh``. Por omisión, el de
    la tabla de límites de tasa del Cap. 6. Solo el stack E2E lo sube, porque ahí todas las
    peticiones salen de la misma IP (H-56). En producción no se define."""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    """Nivel de los loggers ``portero.*`` (OWASP ASVS V7.1; H-70). Con ``WARNING`` o más no sale
    el log de acceso, que es ``INFO``. Un valor fuera de la lista impide arrancar."""

    @field_validator("allowed_origins")
    @classmethod
    def _sin_comodin_ni_null(cls, origenes: list[str]) -> list[str]:
        """H-29 (OWASP ASVS V14.5.3): el refresh token viaja en una cookie ``HttpOnly``
        (Cap. 6 §Emisión del par de tokens), así que CORS se configura con credenciales. En ese
        modo, ``*`` hace que Starlette refleje cualquier origen, y ``null`` (iframes con
        ``sandbox``, archivos locales) lo puede enviar cualquier página. Se exige una lista
        explícita de orígenes."""
        if any(origen.strip().lower() in {"*", "null"} for origen in origenes):
            raise ValueError("allowed_origins no admite '*' ni 'null'; enumera los orígenes")
        return origenes
