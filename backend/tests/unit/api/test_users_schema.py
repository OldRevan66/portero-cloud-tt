"""``UserOut``: el Administrador ve si la cuenta está bloqueada y hasta cuándo (H-78; spec Fase 5
§2, notas de Usuarios). Sin BD.

``locked_until`` sale nulo si el bloqueo ya venció: el Dashboard no compara con el reloj del
navegador ni muestra un bloqueo que ya no aplica (Cap. 6 §Política de bloqueo). El contador de
fallos y el hash nunca se exponen.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest

from portero.api.v1.users import UserOut

AHORA = datetime.now(UTC)


def _usuario(locked_until: datetime | None) -> SimpleNamespace:
    """Objeto con los atributos de ``User`` (``from_attributes``), incluidos los internos."""
    return SimpleNamespace(
        id=UUID("11111111-1111-4111-8111-111111111111"),
        email="beto@example.com",
        name="Beto",
        is_active=True,
        created_at=AHORA,
        updated_at=AHORA,
        locked_until=locked_until,
        failed_login_attempts=5,
        password_hash="marcador-no-es-un-hash",  # noqa: S106  # marcador de prueba
        tokens_invalid_before=None,
    )


def _json(locked_until: datetime | None) -> dict[str, Any]:
    return UserOut.model_validate(_usuario(locked_until)).model_dump(mode="json")


def test_un_bloqueo_vigente_se_expone() -> None:
    hasta = AHORA + timedelta(minutes=10)

    assert UserOut.model_validate(_usuario(hasta)).locked_until == hasta


@pytest.mark.parametrize(
    "locked_until",
    [None, AHORA - timedelta(seconds=1), AHORA - timedelta(days=1)],
    ids=["sin-bloqueo", "recien-vencido", "vencido-ayer"],
)
def test_sin_bloqueo_o_vencido_es_nulo(locked_until: datetime | None) -> None:
    cuerpo = _json(locked_until)

    assert "locked_until" in cuerpo
    assert cuerpo["locked_until"] is None


def test_no_expone_contador_hash_ni_corte_de_tokens() -> None:
    cuerpo = _json(AHORA + timedelta(minutes=10))

    assert set(cuerpo) == {
        "id",
        "email",
        "name",
        "is_active",
        "created_at",
        "updated_at",
        "locked_until",
    }
