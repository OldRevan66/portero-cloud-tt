"""``scripts/carga.py``: ritmo por clave, resumen de latencias y que la salida nunca muestre un
token ni un valor de secreto (RNF-006)."""

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "carga.py"

PAT = "eyJ-pat-de-prueba-no-es-real"
VALOR = "carga-no-es-real-valor-de-prueba"


def _cargar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("carga", SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


carga = _cargar_script()


class RelojFalso:
    def __init__(self) -> None:
        self.ahora = 100.0

    def __call__(self) -> float:
        return self.ahora


# --- Ritmo ---------------------------------------------------------------------------------------


def test_ritmo_separa_los_turnos_por_el_intervalo_con_margen() -> None:
    reloj = RelojFalso()
    ritmo = carga.Ritmo(60, reloj=reloj)
    assert ritmo.intervalo == pytest.approx(60 / 60 * 1.05)
    assert ritmo.reservar() == 0  # el primer turno es inmediato
    assert ritmo.reservar() == pytest.approx(1.05)
    assert ritmo.reservar() == pytest.approx(2.10)


def test_ritmo_no_acumula_turnos_si_la_clave_estuvo_quieta() -> None:
    reloj = RelojFalso()
    ritmo = carga.Ritmo(60, reloj=reloj)
    ritmo.reservar()
    reloj.ahora += 30  # 30 s sin enviar no dan derecho a una ráfaga después
    assert ritmo.reservar() == 0
    assert ritmo.reservar() == pytest.approx(1.05)


@pytest.mark.parametrize("limite", [10, 60, 100, 600])
def test_ritmo_nunca_rebasa_el_limite_en_una_ventana_de_60_s(limite: int) -> None:
    """Mismo criterio que ``api/rate_limit.py``: en cualquier ventana de 60 s, como mucho
    ``limite`` peticiones."""
    reloj = RelojFalso()
    ritmo = carga.Ritmo(limite, reloj=reloj)
    turnos = [reloj.ahora + ritmo.reservar() for _ in range(3 * limite)]
    for i, inicio in enumerate(turnos):
        en_ventana = [t for t in turnos[i:] if t - inicio < 60]
        assert len(en_ventana) <= limite


def test_ritmo_rechaza_un_limite_no_positivo() -> None:
    with pytest.raises(ValueError):
        carga.Ritmo(0)


# --- Resumen -------------------------------------------------------------------------------------


def test_resumir_calcula_percentiles_throughput_y_errores() -> None:
    muestras = [carga.Muestra(float(ms), 200) for ms in range(1, 101)]
    muestras += [carga.Muestra(5.0, 429), carga.Muestra(7.0, 429), carga.Muestra(9.0, 500)]
    resumen = carga.resumir("valor", muestras, duracion_s=10.0)
    assert resumen["n"] == 103
    assert resumen["ok"] == 100
    assert resumen["errores"] == {"429": 2, "500": 1}
    assert resumen["throughput"] == pytest.approx(10.0)  # solo las 2xx cuentan
    assert resumen["p50_ms"] == pytest.approx(50.5)
    assert resumen["p95_ms"] == pytest.approx(95.05)
    assert resumen["p99_ms"] == pytest.approx(99.01)
    assert resumen["max_ms"] == pytest.approx(100.0)


def test_resumir_sin_respuestas_correctas_no_falla() -> None:
    resumen = carga.resumir("login", [carga.Muestra(3.0, 401)], duracion_s=1.0)
    assert resumen["ok"] == 0
    assert resumen["p50_ms"] is None
    assert "sin respuestas 2xx" in carga.formatear(resumen)


# --- Entorno E2E ---------------------------------------------------------------------------------


def test_lee_solo_las_contrasenas_del_entorno_e2e(tmp_path: Path) -> None:
    archivo = tmp_path / "e2e.env"
    archivo.write_text(
        "PORTERO_KEK_PASSPHRASE=no-se-lee\nSEED_PASSWORD_ADMIN=a-1\nSEED_PASSWORD_LIDER=l=2\n",
        encoding="utf-8",
    )
    assert carga.leer_entorno_e2e(archivo) == {
        "SEED_PASSWORD_ADMIN": "a-1",
        "SEED_PASSWORD_LIDER": "l=2",
    }


# --- Escenarios contra un transporte simulado ----------------------------------------------------


def _transporte_value(limite: int | None = None) -> httpx.MockTransport:
    """Responde como ``GET /secrets/{id}/value``; con ``limite``, 429 a partir de ahí."""
    atendidas = 0

    def manejar(request: httpx.Request) -> httpx.Response:
        nonlocal atendidas
        assert request.headers["Authorization"] == f"Bearer {PAT}"
        atendidas += 1
        if limite is not None and atendidas > limite:
            return httpx.Response(
                429, headers={"Retry-After": "42"}, json={"type": "rate-limit-exceeded"}
            )
        return httpx.Response(200, json={"id": "x", "name": "N", "value": VALOR, "version": 1})

    return httpx.MockTransport(manejar)


async def test_escenario_valor_no_imprime_el_pat_ni_el_valor(
    capsys: pytest.CaptureFixture[str],
) -> None:
    async with httpx.AsyncClient(
        transport=_transporte_value(), base_url="http://prueba/api/v1"
    ) as cliente:
        claves = carga.claves_de([PAT, PAT, PAT], limite=60)
        resumen = await carga.escenario_valor(cliente, claves, "s-1", clientes=2, duracion_s=0.3)
    print(carga.formatear(resumen))
    print(json.dumps(resumen))
    salida = capsys.readouterr()
    assert resumen["ok"] == 3  # uno por PAT: el segundo turno de cada uno cae fuera de 0.3 s
    assert resumen["errores"] == {}
    for texto in (salida.out, salida.err):
        assert PAT not in texto
        assert VALOR not in texto


async def test_demostracion_del_429_cuenta_codigos_y_retry_after(
    capsys: pytest.CaptureFixture[str],
) -> None:
    async with httpx.AsyncClient(
        transport=_transporte_value(limite=60), base_url="http://prueba/api/v1"
    ) as cliente:
        resultado = await carga.demostrar_429(cliente, PAT, "s-1", peticiones=65)
    print(carga.formatear_429(resultado))
    salida = capsys.readouterr().out
    assert resultado["codigos"] == {"200": 60, "429": 5}
    assert resultado["retry_after"] == [42]
    assert PAT not in salida and VALOR not in salida
