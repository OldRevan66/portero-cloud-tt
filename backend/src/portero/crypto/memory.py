"""Borrado best-effort de material sensible en memoria (Algoritmo 4 del Cap. 6, SecureZero)."""

import ctypes


def secure_zero(buf: bytearray) -> None:
    """Sobrescribe con ceros, en sitio, el contenido de ``buf`` (Algoritmo 4 del Cap. 6).

    Se usa ``ctypes.memset`` sobre el mismo búfer del ``bytearray`` en lugar de un ciclo en
    Python, para que la escritura no dependa de crear objetos intermedios.

    Es *best-effort*, como reconoce el Cap. 6: Python no garantiza que no existan otras copias.
    El motor descifra la DEK y el valor con ``AESGCM.decrypt_into`` en búferes borrables (H-16),
    pero quedan copias fuera de su alcance: la DEK nueva sale de ``secrets.token_bytes`` como
    ``bytes`` inmutables, OpenSSL guarda su propia copia de la clave dentro del objeto ``AESGCM``
    y el sistema operativo puede paginar la memoria a disco. Esta función reduce la ventana de
    exposición; no la elimina.
    """
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
