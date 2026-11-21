"""``OperationActor.event``: arma el ``OperationEvent`` de un actor (spec Fase 5 §5.3; H-04,
H-12). Sin BD."""

import uuid

import pytest

from portero.oplog.service import ClientInfo, ForbiddenDetailError, OperationActor

USUARIO = uuid.UUID("11111111-1111-4111-8111-111111111111")
PROYECTO = uuid.UUID("22222222-2222-4222-8222-222222222222")
AMBIENTE = uuid.UUID("33333333-3333-4333-8333-333333333333")


def test_copia_actor_cliente_y_contexto() -> None:
    actor = OperationActor(
        actor_type="human",
        actor_ref="ana@example.com",
        actor_user_id=USUARIO,
        client=ClientInfo(ip_address="127.0.0.1", user_agent="pruebas"),
    )

    evento = actor.event(
        "update_environment",
        "success",
        resource_type="environment",
        resource_id=AMBIENTE,
        project_id=PROYECTO,
        environment_id=AMBIENTE,
        details={"fields": ["description"]},
    )

    assert (evento.actor_type, evento.actor_ref, evento.actor_user_id) == (
        "human",
        "ana@example.com",
        USUARIO,
    )
    assert (evento.verb, evento.result) == ("update_environment", "success")
    assert (evento.resource_type, evento.resource_id) == ("environment", AMBIENTE)
    assert (evento.project_id, evento.environment_id) == (PROYECTO, AMBIENTE)
    assert (evento.ip_address, evento.user_agent) == ("127.0.0.1", "pruebas")
    assert evento.details == {"fields": ["description"]}


def test_sin_cliente_ni_contexto_quedan_nulos() -> None:
    evento = OperationActor("service", "sa:x", None).event("access_denied", "failure")

    assert evento.actor_user_id is None
    assert evento.ip_address is None and evento.user_agent is None
    assert evento.project_id is None and evento.details is None


def test_valida_el_evento() -> None:
    """La validación de ``OperationEvent`` (catálogo, H-12) sigue aplicando."""
    actor = OperationActor("human", "ana@example.com", USUARIO)
    with pytest.raises(ValueError, match="catálogo"):
        actor.event("borrar_todo", "success")
    with pytest.raises(ForbiddenDetailError):
        actor.event("update_project", "success", details={"value": "x"})


ACTOR = OperationActor("human", "ana@example.com", USUARIO)


@pytest.mark.parametrize(
    "llave",
    [
        "value",
        "new_value",
        "password",
        "current_password",
        "New_Password",
        "token",
        "refresh_token",
        "access_token",
        "token_hash",
        "password_hash",
        "secret",
    ],
)
def test_llaves_que_contienen_un_fragmento_prohibido_se_rechazan(llave: str) -> None:
    """H-48: no basta la coincidencia exacta; ``new_value`` o ``refresh_token`` también son
    valores sensibles (spec Fase 5 §5.3; H-12)."""
    with pytest.raises(ForbiddenDetailError):
        ACTOR.event("update_project", "success", details={"anidado": [{llave: "x"}]})


@pytest.mark.parametrize(
    "llave",
    [
        "fields",
        "archived_secrets",
        "removed_role_assignments",
        "from_version",
        "rewrapped_deks",
        "broken_count",
        "last_hash",
        "reason",
    ],
)
def test_llaves_legitimas_de_details_se_aceptan(llave: str) -> None:
    """Guarda de H-48: las llaves que el sistema usa (o usará, ``last_hash`` de H-46) pasan."""
    ACTOR.event("update_project", "success", details={llave: 1})
