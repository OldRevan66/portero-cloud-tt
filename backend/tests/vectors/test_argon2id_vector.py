"""Vector oficial de Argon2id: RFC 9106 §5.3.

El vector usa *secret* (K) y *associated data* (X), parámetros que ``hash_secret_raw`` no expone.
Por eso se arma el ``argon2_context`` de la biblioteca de referencia con ``argon2.low_level.ffi``
y se invoca ``argon2.low_level.core`` (spec §1.8). Con esto se demuestra que la implementación
que trae ``argon2-cffi`` es la del RFC; la derivación de la KEK y el hash de contraseñas usan
después las funciones de alto nivel de la misma biblioteca.
"""

from argon2.low_level import ARGON2_VERSION, Type, core, ffi

TAG_ESPERADO = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_argon2id_rfc9106_seccion_5_3() -> None:
    assert ARGON2_VERSION == 0x13  # versión 1.3, la que fija el RFC

    pwd = b"\x01" * 32
    salt = b"\x02" * 16
    secret = b"\x03" * 8
    ad = b"\x04" * 12
    out = ffi.new("uint8_t[]", 32)
    # Los búferes de cffi deben seguir vivos mientras ``core`` los use: se guardan en variables.
    c_pwd = ffi.new("uint8_t[]", pwd)
    c_salt = ffi.new("uint8_t[]", salt)
    c_secret = ffi.new("uint8_t[]", secret)
    c_ad = ffi.new("uint8_t[]", ad)

    ctx = ffi.new(
        "argon2_context *",
        {
            "out": out,
            "outlen": 32,
            "pwd": c_pwd,
            "pwdlen": len(pwd),
            "salt": c_salt,
            "saltlen": len(salt),
            "secret": c_secret,
            "secretlen": len(secret),
            "ad": c_ad,
            "adlen": len(ad),
            "t_cost": 3,
            "m_cost": 32,  # KiB
            "lanes": 4,
            "threads": 4,
            "version": ARGON2_VERSION,
            "allocate_cbk": ffi.NULL,
            "free_cbk": ffi.NULL,
            "flags": 0,
        },
    )

    resultado = core(ctx, Type.ID.value)

    assert resultado == 0  # ARGON2_OK
    assert bytes(ffi.buffer(out, 32)).hex() == TAG_ESPERADO
