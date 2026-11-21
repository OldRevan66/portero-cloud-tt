"""Resolución por nombres y retornos tipados (Cap. 6 §API pública del SDK; hallazgo H-54).

El Cap. 6 pide ``get_secret_value(project, environment, name)`` y la API identifica por UUID:
el SDK resuelve con ``GET /projects`` → ``GET .../environments`` → ``GET .../secrets`` y memoriza
solo los identificadores. El valor nunca se memoriza (Cap. 6 §Alcance, "Falla de manera
segura"): cada llamada vuelve a pedir ``/value``.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from uuid import UUID

import pytest

from apoyo import (
    AMBIENTE,
    EID,
    NOMBRE,
    PID,
    PROYECTO,
    SID,
    SID_NUEVO,
    SID_OTRO,
    VALOR,
    VALOR_NUEVO,
    FabricaCliente,
    ServidorFalso,
    esperar,
)
from portero_cloud_sdk import Secret, SecretNotFound

RUTA_PROYECTOS = "/projects"
RUTA_AMBIENTES = f"/projects/{PID}/environments"
RUTA_SECRETOS = f"/projects/{PID}/environments/{EID}/secrets"


async def test_get_secret_value_resuelve_y_devuelve_str(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    valor = await esperar(
        cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
    )
    assert valor == VALOR
    assert type(valor) is str
    assert [p.url.path for p in servidor.peticiones] == [
        "/api/v1" + RUTA_PROYECTOS,
        "/api/v1" + RUTA_AMBIENTES,
        "/api/v1" + RUTA_SECRETOS,
        f"/api/v1/secrets/{SID}/value",
    ]
    assert all(p.method == "GET" for p in servidor.peticiones)


async def test_segunda_llamada_no_resuelve_otra_vez_pero_si_pide_el_valor(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    for _ in range(2):
        valor = await esperar(
            cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
        )
        assert valor == VALOR
    assert servidor.contar(RUTA_PROYECTOS) == 1
    assert servidor.contar(RUTA_AMBIENTES) == 1
    assert servidor.contar(RUTA_SECRETOS) == 1
    assert servidor.contar(f"/secrets/{SID}/value") == 2  # el valor nunca se cachea


async def test_el_valor_nuevo_se_ve_sin_reiniciar_el_cliente(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    """Tras una rotación (mismo id, valor nuevo) el cliente devuelve el valor vigente."""
    cliente = crear_cliente()
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    servidor.valor = VALOR_NUEVO
    valor = await esperar(
        cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
    )
    assert valor == VALOR_NUEVO


async def test_get_secret_devuelve_metadatos_tipados_e_inmutables(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    secreto = await esperar(cliente.get_secret(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert isinstance(secreto, Secret)
    assert dataclasses.is_dataclass(secreto)
    assert [f.name for f in dataclasses.fields(secreto)] == [
        "id",
        "name",
        "version",
        "description",
        "created_at",
    ]
    assert secreto.id == SID and isinstance(secreto.id, UUID)
    assert secreto.name == NOMBRE
    assert secreto.version == 3
    assert secreto.description == "Contraseña de la BD de demostración"
    assert secreto.created_at == datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
    with pytest.raises(dataclasses.FrozenInstanceError):
        secreto.version = 4  # type: ignore[misc]
    # Metadatos frescos: se piden a /secrets/{id}, nunca a /value.
    assert servidor.contar(f"/secrets/{SID}") == 1
    assert servidor.contar(f"/secrets/{SID}/value") == 0


async def test_list_secrets_devuelve_tupla_de_secret(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    secretos = await esperar(cliente.list_secrets(project=PROYECTO, environment=AMBIENTE))
    assert isinstance(secretos, tuple)
    assert [s.name for s in secretos] == [NOMBRE, "API_KEY"]
    assert [s.id for s in secretos] == [SID, SID_OTRO]
    assert all(isinstance(s, Secret) for s in secretos)


async def test_list_secrets_llena_la_memoria_de_identificadores(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    await esperar(cliente.list_secrets(project=PROYECTO, environment=AMBIENTE))
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert servidor.contar(RUTA_SECRETOS) == 1
    assert servidor.contar(f"/secrets/{SID}/value") == 1


@pytest.mark.parametrize(
    ("proyecto", "ambiente", "nombre"),
    [
        ("Proyecto inexistente", AMBIENTE, NOMBRE),
        ("tienda en línea", AMBIENTE, NOMBRE),  # igualdad exacta, sensible a mayúsculas
        (PROYECTO, "production", NOMBRE),  # fuera del alcance del PAT: la API no lo lista
        (PROYECTO, AMBIENTE, "NO_EXISTE"),
        (PROYECTO, AMBIENTE, "db_password"),
    ],
)
async def test_nombre_ausente_es_secret_not_found(
    crear_cliente: FabricaCliente, proyecto: str, ambiente: str, nombre: str
) -> None:
    """Inexistente o fuera del alcance → la misma excepción (coherente con H-14)."""
    cliente = crear_cliente()
    with pytest.raises(SecretNotFound):
        await esperar(cliente.get_secret_value(project=proyecto, environment=ambiente, name=nombre))
    with pytest.raises(SecretNotFound):
        await esperar(cliente.get_secret(project=proyecto, environment=ambiente, name=nombre))


@pytest.mark.parametrize(
    ("proyecto", "ambiente"),
    [("Proyecto inexistente", AMBIENTE), (PROYECTO, "production")],
)
async def test_list_secrets_con_ambito_ausente_es_secret_not_found(
    crear_cliente: FabricaCliente, proyecto: str, ambiente: str
) -> None:
    cliente = crear_cliente()
    with pytest.raises(SecretNotFound):
        await esperar(cliente.list_secrets(project=proyecto, environment=ambiente))


async def test_id_obsoleto_se_resuelve_otra_vez_una_sola_vez(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    """Archivar y recrear el secreto cambia su id: el 404 con un id memorizado vacía la
    memoria y se resuelve de nuevo (H-54)."""
    cliente = crear_cliente()
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    servidor.recrear_secreto()
    valor = await esperar(
        cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE)
    )
    assert valor == VALOR_NUEVO
    assert servidor.contar(f"/secrets/{SID}/value") == 2  # el original y el 404
    assert servidor.contar(f"/secrets/{SID_NUEVO}/value") == 1
    assert servidor.contar(RUTA_PROYECTOS) == 2


async def test_id_obsoleto_sin_reemplazo_es_secret_not_found_sin_bucle(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    servidor.borrar_secreto()
    antes = len(servidor.peticiones)
    with pytest.raises(SecretNotFound):
        await esperar(cliente.get_secret_value(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    # 404 de /value + una sola resolución nueva (proyectos, ambientes, secretos).
    assert len(servidor.peticiones) - antes == 4


async def test_id_obsoleto_en_get_secret_tambien_se_resuelve(
    crear_cliente: FabricaCliente, servidor: ServidorFalso
) -> None:
    cliente = crear_cliente()
    await esperar(cliente.get_secret(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    servidor.recrear_secreto()
    secreto = await esperar(cliente.get_secret(project=PROYECTO, environment=AMBIENTE, name=NOMBRE))
    assert str(secreto.id) == SID_NUEVO
