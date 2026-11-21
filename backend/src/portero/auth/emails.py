"""Forma canónica del correo de un usuario (H-45; OWASP ASVS V5.1.3).

``users.email`` es UNIQUE y se compara tal cual en la BD. Sin una forma canónica, ``Ana@x.mx`` y
``ana@x.mx`` serían dos cuentas distintas (dos ``actor_ref`` que se confunden en la bitácora) y el
login fallaría si el usuario cambia la capitalización. Se normaliza en cada punto de entrada: los
esquemas de la API (login y alta) y el CLI ``create-admin``.
"""


def normalize_email(email: str) -> str:
    """Quita los espacios alrededor y pasa a minúsculas. No cambia la parte local de otra forma:
    las reglas de cada proveedor (puntos, ``+etiqueta``) no son universales."""
    return email.strip().lower()
