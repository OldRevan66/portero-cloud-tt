"""Pruebas puras de la cadena de hashes del Servicio de Registro de Operaciones (spec núcleo §5;
spec Fase 5 §5.1; H-11; RF-018; OWASP ASVS V7.3.3).

Sin BD: el JSON canónico, ``compute_hash`` y ``verify_chain`` sobre una lista de filas.
"""

import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import Any
from uuid import UUID

import pytest

from portero.oplog.chain import (
    CHAINED_FIELDS,
    GENESIS_HASH,
    ChainRow,
    canonical_json,
    compute_hash,
    verify_chain,
)

USUARIO = UUID("11111111-1111-1111-1111-111111111111")
PROYECTO = UUID("22222222-2222-2222-2222-222222222222")
INSTANTE = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)


def _campos(**cambios: Any) -> dict[str, Any]:
    """Los 13 campos encadenados de un registro de ejemplo."""
    campos: dict[str, Any] = {
        "event_timestamp": INSTANTE,
        "actor_user_id": USUARIO,
        "actor_type": "human",
        "actor_ref": "ana@example.com",
        "verb": "login",
        "resource_type": "user",
        "resource_id": USUARIO,
        "result": "success",
        "ip_address": "127.0.0.1",
        "user_agent": "python-httpx/0.28",
        "project_id": None,
        "environment_id": None,
        "details": None,
    }
    campos.update(cambios)
    return campos


def _cadena(n: int) -> list[ChainRow]:
    """``n`` filas bien encadenadas con ids 1..n, la primera desde el génesis."""
    filas: list[ChainRow] = []
    anterior = GENESIS_HASH
    for i in range(1, n + 1):
        campos = _campos(
            event_timestamp=INSTANTE + timedelta(seconds=i), actor_ref=f"u{i}@example.com"
        )
        actual = compute_hash(anterior, canonical_json(campos))
        filas.append(ChainRow(id=i, previous_hash=anterior, current_hash=actual, fields=campos))
        anterior = actual
    return filas


# --- JSON canónico -------------------------------------------------------------------------------


def test_campos_encadenados_son_los_de_la_spec() -> None:
    assert CHAINED_FIELDS == (
        "event_timestamp",
        "actor_user_id",
        "actor_type",
        "actor_ref",
        "verb",
        "resource_type",
        "resource_id",
        "result",
        "ip_address",
        "user_agent",
        "project_id",
        "environment_id",
        "details",
    )


def test_misma_entrada_mismos_bytes() -> None:
    assert canonical_json(_campos()) == canonical_json(_campos())


def test_el_orden_de_las_llaves_no_cambia_los_bytes() -> None:
    campos = _campos(details={"to_version": 3, "from_version": 2})
    invertido = dict(reversed(list(campos.items())))
    invertido["details"] = {"from_version": 2, "to_version": 3}

    assert canonical_json(invertido) == canonical_json(campos)


def test_bytes_exactos_de_un_registro_de_ejemplo() -> None:
    """Llaves ordenadas, sin espacios, UUID como texto, fecha UTC ISO 8601 con microsegundos y
    UTF-8 sin escapar."""
    campos = _campos(actor_ref="josé@example.com", details={"b": 1, "a": [1, 2]})

    esperado = (
        '{"actor_ref":"josé@example.com",'
        '"actor_type":"human",'
        '"actor_user_id":"11111111-1111-1111-1111-111111111111",'
        '"details":{"a":[1,2],"b":1},'
        '"environment_id":null,'
        '"event_timestamp":"2026-10-10T12:00:00.000000+00:00",'
        '"ip_address":"127.0.0.1",'
        '"project_id":null,'
        '"resource_id":"11111111-1111-1111-1111-111111111111",'
        '"resource_type":"user",'
        '"result":"success",'
        '"user_agent":"python-httpx/0.28",'
        '"verb":"login"}'
    ).encode()

    assert canonical_json(campos) == esperado


def test_el_resultado_es_json_valido_en_utf8() -> None:
    datos = json.loads(canonical_json(_campos(project_id=PROYECTO)).decode("utf-8"))

    assert datos["project_id"] == str(PROYECTO)


def test_fecha_con_otra_zona_se_normaliza_a_utc() -> None:
    cdmx = INSTANTE.astimezone(timezone(timedelta(hours=-6)))

    assert canonical_json(_campos(event_timestamp=cdmx)) == canonical_json(_campos())


def test_fecha_sin_zona_horaria_se_rechaza() -> None:
    with pytest.raises(ValueError):
        canonical_json(_campos(event_timestamp=datetime(2026, 10, 10, 12, 0, 0)))  # noqa: DTZ001


def test_ip_como_objeto_o_texto_da_los_mismos_bytes() -> None:
    """``asyncpg`` puede devolver ``INET`` como objeto ``ipaddress``."""
    assert canonical_json(_campos(ip_address=IPv4Address("127.0.0.1"))) == canonical_json(_campos())


def test_id_y_hashes_no_entran_al_json() -> None:
    campos = _campos()
    con_extras = {**campos, "id": 7, "previous_hash": "a" * 64, "current_hash": "b" * 64}

    assert canonical_json(con_extras) == canonical_json(campos)
    assert b"previous_hash" not in canonical_json(con_extras)


def test_falta_un_campo_lanza_keyerror() -> None:
    campos = _campos()
    del campos["verb"]

    with pytest.raises(KeyError):
        canonical_json(campos)


# --- compute_hash --------------------------------------------------------------------------------


def test_compute_hash_es_sha256_de_previous_concatenado_con_el_json() -> None:
    canon = canonical_json(_campos())

    assert compute_hash(GENESIS_HASH, canon) == (
        hashlib.sha256(GENESIS_HASH.encode("ascii") + canon).hexdigest()
    )


def test_compute_hash_da_64_hex_en_minuscula() -> None:
    digest = compute_hash(GENESIS_HASH, canonical_json(_campos()))

    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_compute_hash_depende_del_hash_anterior() -> None:
    canon = canonical_json(_campos())

    assert compute_hash(GENESIS_HASH, canon) != compute_hash("f" * 64, canon)


def test_el_genesis_son_64_ceros() -> None:
    assert GENESIS_HASH == "0" * 64
    assert _cadena(5)[0].previous_hash == GENESIS_HASH


# --- verify_chain --------------------------------------------------------------------------------


def test_cadena_integra_es_ok() -> None:
    resultado = verify_chain(_cadena(5))

    assert resultado.ok is True
    assert resultado.broken == []
    assert resultado.total == 5
    assert (resultado.verified_from, resultado.verified_to) == (1, 5)


def test_lista_vacia_es_ok() -> None:
    resultado = verify_chain([])

    assert resultado.ok is True
    assert resultado.total == 0
    assert resultado.broken == []
    assert resultado.verified_from is None
    assert resultado.verified_to is None
    assert resultado.last_hash is None


def test_el_reporte_trae_el_ultimo_hash_almacenado() -> None:
    """H-46: ``last_hash`` es el ancla que el Administrador anota fuera de la BD."""
    filas = _cadena(5)

    assert verify_chain(filas).last_hash == filas[-1].current_hash


def test_truncar_el_final_pasa_la_verificacion_pero_cambia_el_ancla() -> None:
    """H-46, límite del diseño: borrar los últimos registros no rompe ningún eslabón (no hay
    fila siguiente que lo delate), así que ``ok`` sigue en verdadero. Solo comparar
    ``last_hash`` con el valor anotado antes revela el truncado."""
    filas = _cadena(5)
    anclado = verify_chain(filas).last_hash

    truncado = verify_chain(filas[:3])

    assert truncado.ok is True
    assert truncado.last_hash != anclado


def test_un_campo_alterado_marca_solo_esa_fila() -> None:
    filas = _cadena(5)
    fila = filas[2]
    filas[2] = dataclasses.replace(fila, fields={**fila.fields, "result": "failure"})

    resultado = verify_chain(filas)

    assert resultado.ok is False
    assert resultado.broken == [3]


def test_una_fila_borrada_rompe_la_siguiente() -> None:
    filas = _cadena(5)
    del filas[2]

    resultado = verify_chain(filas)

    assert resultado.ok is False
    assert resultado.broken[0] == 4


def test_dos_filas_intercambiadas_se_detectan_en_la_primera_posicion_afectada() -> None:
    filas = _cadena(5)
    filas[1], filas[2] = filas[2], filas[1]

    resultado = verify_chain(filas)

    assert resultado.ok is False
    assert resultado.broken[0] == filas[1].id


def test_primera_fila_sin_genesis_se_marca() -> None:
    filas = _cadena(3)
    primera = filas[0]
    otro_anterior = "f" * 64
    filas[0] = dataclasses.replace(
        primera,
        previous_hash=otro_anterior,
        current_hash=compute_hash(otro_anterior, canonical_json(primera.fields)),
    )

    resultado = verify_chain(filas)

    assert resultado.ok is False
    assert resultado.broken[0] == 1


def test_tipo_desconocido_lanza_typeerror() -> None:
    """Un objeto sin forma canónica definida no se serializa "como sea"."""
    with pytest.raises(TypeError):
        canonical_json(_campos(details={"x": object()}))
