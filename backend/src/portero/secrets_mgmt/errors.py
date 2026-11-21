"""Excepciones del Servicio de Gestión de Secretos.

Los mensajes nunca incluyen valores de secretos ni material criptográfico (OWASP ASVS V7.4.1;
riesgo P-05 del Cap. 5): la API podrá devolver ``str(exc)`` tal cual en la Fase 5.
"""


class SecretsError(Exception):
    """Base de los errores del Servicio de Gestión de Secretos."""


class SecretNotFoundError(SecretsError):
    """El secreto o la versión pedida no existe, o el secreto está archivado (RF-004)."""


class SecretNameConflictError(SecretsError):
    """Ya hay un secreto activo con ese nombre en el ambiente (índice único parcial, Cap. 5)."""


class EnvironmentNotInProjectError(SecretsError):
    """El ambiente no pertenece al proyecto indicado (validación en aplicación, Cap. 5)."""


class KekRotationError(SecretsError):
    """La rotación de KEK no puede hacerse: no hay KEK activa, o la passphrase nueva está vacía
    o es igual a la actual (H-07). Se detecta antes de cambiar nada; el mensaje nunca incluye
    las passphrases."""
