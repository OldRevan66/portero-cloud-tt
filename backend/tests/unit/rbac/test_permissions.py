"""Pruebas del catálogo de permisos y de la matriz rol→permisos (Cap. 6, §Modelo RBAC; spec §4).

La matriz es una constante en código (políticas como código, OWASP ASVS V1.4.4): estas pruebas
fijan su contenido y que no se pueda modificar en tiempo de ejecución.
"""

import pytest

from portero.rbac.permissions import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    permissions_of_role,
)


def test_catalogo_de_permisos_cerrado() -> None:
    """Los 8 permisos de la tabla "Catálogo cerrado de permisos", ni uno más ni uno menos."""
    assert {p.value for p in Permission} == {
        "secrets:read",
        "secrets:write",
        "secrets:rotate",
        "secrets:delete",
        "projects:manage",
        "users:manage",
        "audit:read",
        "system:configure",
    }


def test_ids_de_rol_coinciden_con_la_siembra_de_la_migracion() -> None:
    """``roles.id`` se siembra con 1, 2, 3 (spec §2); el enum usa los mismos valores."""
    assert Role.ADMINISTRADOR == 1
    assert Role.LIDER_TECNICO == 2
    assert Role.DESARROLLADOR == 3
    assert len(Role) == 3


def test_la_matriz_cubre_los_tres_roles() -> None:
    assert set(ROLE_PERMISSIONS) == set(Role)


def test_la_matriz_es_inmutable() -> None:
    with pytest.raises(TypeError):
        ROLE_PERMISSIONS[Role.DESARROLLADOR] = frozenset(Permission)  # type: ignore[index]
    assert isinstance(ROLE_PERMISSIONS[Role.DESARROLLADOR], frozenset)


@pytest.mark.parametrize("role_id", [0, 4, 99, -1])
def test_rol_desconocido_no_tiene_permisos(role_id: int) -> None:
    """Un ``role_id`` fuera del catálogo no lanza ``KeyError``: no otorga nada (ASVS V4.1.5)."""
    assert permissions_of_role(role_id) == frozenset()


def test_permissions_of_role_acepta_el_entero_de_la_bd() -> None:
    """La capa de persistencia entrega ``role_id`` como ``int``, no como ``Role``."""
    assert permissions_of_role(1) == ROLE_PERMISSIONS[Role.ADMINISTRADOR]
