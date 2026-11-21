"""Arranque de la aplicación (lifespan del API REST Gateway): KEK, hash señuelo y liberación
de recursos (spec núcleo §1.6; spec Fase 5 §3.8; H-06, H-32).
"""

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.integration.conftest import PASSPHRASE_PRUEBA

from portero.auth import passwords
from portero.config import Settings
from portero.crypto.errors import KekPassphraseError
from portero.crypto.kek import KdfParams, KeyManager
from portero.main import create_app
from portero.secrets_mgmt.kek_store import load_key_manager


async def test_passphrase_de_kek_incorrecta_impide_el_arranque(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    """H-06: si el verificador de la KEK no coincide, la app no llega a atender peticiones."""
    async with fabrica_app() as session:
        km = await load_key_manager(
            session, PASSPHRASE_PRUEBA, new_params=parametros_argon2_solo_pruebas
        )
        km.close()
    otra = settings_app.model_copy(
        update={"kek_passphrase": SecretStr("marcador-de-prueba-passphrase-equivocada")}
    )
    app = create_app(otra, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas)

    with pytest.raises(KekPassphraseError):
        async with app.router.lifespan_context(app):
            pytest.fail("la app arrancó con una passphrase incorrecta")


async def test_hash_senuelo_se_prepara_en_el_lifespan(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
) -> None:
    """H-32: el señuelo se calcula al arrancar (lifespan), no al construir la app ni en el
    primer login fallido."""
    passwords._decoy_hash.cache_clear()

    app = create_app(
        settings_app, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas
    )
    assert passwords._decoy_hash.cache_info().currsize == 0

    async with app.router.lifespan_context(app):
        assert passwords._decoy_hash.cache_info().currsize == 1


async def test_al_cerrar_se_borra_la_kek_de_memoria(
    settings_app: Settings,
    fabrica_app: async_sessionmaker[AsyncSession],
    parametros_argon2_solo_pruebas: KdfParams,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Al apagar la app se llama ``KeyManager.close()`` (spec núcleo §1.6: la KEK no se queda en
    memoria más de lo necesario)."""
    cerrados: list[KeyManager] = []
    cerrar_real = KeyManager.close

    def espia(self: KeyManager) -> None:
        cerrados.append(self)
        cerrar_real(self)

    monkeypatch.setattr(KeyManager, "close", espia)
    app = create_app(
        settings_app, sessionmaker=fabrica_app, kek_params=parametros_argon2_solo_pruebas
    )

    async with app.router.lifespan_context(app):
        assert cerrados == []

    assert len(cerrados) == 1
