"""Catálogo cerrado de verbos del Servicio de Registro de Operaciones (spec Fase 5 §5.2; H-78).
Sin BD."""

import re

import pytest

from portero.oplog.service import VERBS

LARGO_MAXIMO = 32
"""``audit_logs.verb`` es ``VARCHAR(32)`` (Cap. 5 §Tabla audit_logs)."""


@pytest.mark.parametrize("verbo", ["unlock_user", "reset_password"])
def test_los_verbos_de_h78_estan_en_el_catalogo(verbo: str) -> None:
    """H-78: desbloquear y restablecer son escrituras sobre un usuario y se registran."""
    assert verbo in VERBS


def test_todos_los_verbos_son_snake_case_y_caben_en_la_columna() -> None:
    for verbo in VERBS:
        assert re.fullmatch(r"[a-z]+(_[a-z]+)*", verbo), verbo
        assert len(verbo) <= LARGO_MAXIMO, verbo


def test_sign_chain_esta_en_el_catalogo() -> None:
    """H-81: el subcomando ``sign-chain`` registra cada firma del cierre."""
    assert "sign_chain" in VERBS


def test_export_operations_esta_en_el_catalogo() -> None:
    """RF-021 (H-83): exportar la bitácora es una extracción masiva y se registra, a diferencia
    de las consultas (spec Fase 5 §5.2)."""
    assert "export_operations" in VERBS
