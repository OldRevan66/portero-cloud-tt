"""Excepciones propias del Motor Criptográfico (Cap. 6, Algoritmo 2; spec §1.3).

Ningún mensaje incluye plaintext, DEK, KEK ni fragmentos del ciphertext (OWASP ASVS V7.4.1):
las capas superiores pueden registrar o devolver ``str(exc)`` sin filtrar material sensible.
"""


class CryptoError(Exception):
    """Base de todos los errores del Motor Criptográfico."""


class CryptoIntegrityError(CryptoError):
    """El bundle no pasó la verificación de autenticidad de AES-GCM.

    Cubre etiqueta alterada, nonce o DEK envuelta modificados, contexto (AAD) que no corresponde
    (H-05), KEK equivocada y campos con longitud inválida. No distingue entre esas causas a
    propósito: al atacante no se le da un oráculo (NIST SP 800-38D §5.2.2).
    """


class CryptoAlgorithmError(CryptoError):
    """El bundle declara un algoritmo fuera de la lista blanca (RNF-021; spec §1.2)."""


class KekPassphraseError(CryptoError):
    """La passphrase de arranque no descifra el verificador de la KEK activa (H-06).

    El proceso debe abortar al arrancar en lugar de fallar hasta el primer descifrado. También
    se lanza si el verificador fue alterado: ambos casos son indistinguibles para AES-GCM.
    """


class SigningKeyError(CryptoError):
    """``PORTERO_JWT_PRIVATE_KEY`` (spec §3.2) o una de las llaves de la firma del cierre
    (``PORTERO_OPLOG_SIGNING_*``, H-81) no es un PEM legible o no es una clave Ed25519.

    El mensaje nunca incluye el PEM recibido: podría ser la clave privada correcta mal pegada.
    """


class TokenVerificationError(CryptoError):
    """Un JWT no pasó la verificación criptográfica o de *claims* registrados (Cap. 6, Algoritmo
    de verificación de un JWT entrante).

    ``reason`` es una etiqueta estable (``cabecera``, ``firma``, ``expirado``, ``audiencia``,
    ``emisor``, ``claim_faltante``, ``malformado``, ``invalido``) para el Servicio de Registro de
    Operaciones. El mensaje no incluye el token ni sus *claims*.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"token rechazado: {reason}")
        self.reason = reason
