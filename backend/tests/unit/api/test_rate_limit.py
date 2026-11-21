"""Limitador de tasa del API REST Gateway (Cap. 6 §Rate limiting y controles transversales, tabla
"Límites de tasa aplicados por el API Gateway"; spec Fase 5 §7; OWASP API Security API4).

Pruebas puras: sin BD ni HTTP, con un reloj falso inyectado. Fijan:

- Ventana **deslizante** (registro de marcas de tiempo por clave), no ventana fija: al vencer la
  petición más antigua se libera una sola plaza, no todo el cupo.
- ``Retry-After`` = segundos que faltan para que venza la marca más antigua (hacia arriba, ≥ 1).
- Cuatro categorías con contadores independientes: agotar las operaciones generales no bloquea
  la lectura de valores, y viceversa.
"""

from uuid import uuid4

import pytest

from portero.api.errors import ApiProblem
from portero.api.rate_limit import (
    LIMITS,
    WINDOW_SECONDS,
    Category,
    RateLimiter,
    SlidingWindow,
    classify,
)
from portero.config import Settings
from portero.main import create_app


class RelojFalso:
    """Reloj monotónico controlado por la prueba (segundos)."""

    def __init__(self, inicio: float = 1_000.0) -> None:
        self.ahora = inicio

    def __call__(self) -> float:
        return self.ahora

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos


@pytest.fixture
def reloj() -> RelojFalso:
    return RelojFalso()


def _agotar(limitador: RateLimiter, categoria: Category, clave: str) -> None:
    """Consume exactamente el cupo de la categoría; todas deben pasar."""
    for _ in range(LIMITS[categoria]):
        limitador.enforce(categoria, clave)


def _assert_429(limitador: RateLimiter, categoria: Category, clave: str) -> ApiProblem:
    with pytest.raises(ApiProblem) as info:
        limitador.enforce(categoria, clave)
    problema = info.value
    assert problema.status == 429
    assert problema.kind == "rate-limit-exceeded"
    retry_after = int(problema.headers["Retry-After"])
    assert 1 <= retry_after <= WINDOW_SECONDS
    return problema


# --- Tabla del Cap. 6 ----------------------------------------------------------------------------


def test_limites_son_los_del_cap6() -> None:
    assert WINDOW_SECONDS == 60
    assert dict(LIMITS) == {
        Category.AUTH: 10,
        Category.SECRET_VALUE: 60,
        Category.GENERAL: 100,
        Category.HEALTH: 600,
    }


# --- Ventana deslizante --------------------------------------------------------------------------


def test_ventana_permite_el_limite_y_niega_el_siguiente(reloj: RelojFalso) -> None:
    ventana = SlidingWindow(limit=3, window_seconds=60, clock=reloj)

    decisiones = [ventana.hit("k") for _ in range(3)]

    assert all(d.allowed for d in decisiones)
    negada = ventana.hit("k")
    assert not negada.allowed
    assert negada.retry_after == 60


def test_la_ventana_se_libera_al_pasar_el_tiempo(reloj: RelojFalso) -> None:
    ventana = SlidingWindow(limit=3, window_seconds=60, clock=reloj)
    for _ in range(3):
        assert ventana.hit("k").allowed

    reloj.avanzar(60)

    assert ventana.hit("k").allowed


def test_la_ventana_es_deslizante_y_no_fija(reloj: RelojFalso) -> None:
    """Marcas en t=0, t=20 y t=40. En t=59 sigue llena; en t=60 vence solo la de t=0: entra una
    petición y la siguiente se niega hasta t=80. Una ventana fija reiniciaría todo el cupo."""
    ventana = SlidingWindow(limit=3, window_seconds=60, clock=reloj)
    for _ in range(3):
        assert ventana.hit("k").allowed
        reloj.avanzar(20)
    # ahora es t=60 respecto a la primera marca; se retrocede a t=59 para ver la ventana llena
    reloj.avanzar(-1)

    negada = ventana.hit("k")
    assert not negada.allowed
    assert negada.retry_after == 1

    reloj.avanzar(1)  # t=60: vence la marca de t=0
    assert ventana.hit("k").allowed
    siguiente = ventana.hit("k")
    assert not siguiente.allowed
    assert siguiente.retry_after == 20  # vence la marca de t=20 en t=80


def test_las_peticiones_negadas_no_ocupan_lugar(reloj: RelojFalso) -> None:
    """Un cliente que insiste mientras está bloqueado no alarga su propio bloqueo."""
    ventana = SlidingWindow(limit=2, window_seconds=60, clock=reloj)
    assert ventana.hit("k").allowed
    assert ventana.hit("k").allowed
    for _ in range(10):
        reloj.avanzar(5)
        assert not ventana.hit("k").allowed

    reloj.avanzar(10)  # t=60

    assert ventana.hit("k").allowed


def test_retry_after_redondea_hacia_arriba(reloj: RelojFalso) -> None:
    ventana = SlidingWindow(limit=1, window_seconds=60, clock=reloj)
    assert ventana.hit("k").allowed

    reloj.avanzar(59.2)

    assert ventana.hit("k").retry_after == 1


def test_claves_distintas_no_se_afectan(reloj: RelojFalso) -> None:
    ventana = SlidingWindow(limit=1, window_seconds=60, clock=reloj)
    assert ventana.hit("a").allowed
    assert not ventana.hit("a").allowed

    assert ventana.hit("b").allowed


# --- Categorías del Cap. 6 -----------------------------------------------------------------------


def test_login_10_por_minuto_por_ip_el_11_es_429(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)

    _agotar(limitador, Category.AUTH, "203.0.113.7")

    _assert_429(limitador, Category.AUTH, "203.0.113.7")
    limitador.enforce(Category.AUTH, "203.0.113.8")  # otra IP no se ve afectada


def test_valor_60_por_minuto_por_actor(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)
    actor, otro = str(uuid4()), str(uuid4())

    _agotar(limitador, Category.SECRET_VALUE, actor)

    _assert_429(limitador, Category.SECRET_VALUE, actor)
    limitador.enforce(Category.SECRET_VALUE, otro)


def test_general_100_por_minuto_por_actor(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)
    actor = str(uuid4())

    _agotar(limitador, Category.GENERAL, actor)

    _assert_429(limitador, Category.GENERAL, actor)


def test_salud_600_por_minuto_por_ip(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)

    _agotar(limitador, Category.HEALTH, "198.51.100.1")

    _assert_429(limitador, Category.HEALTH, "198.51.100.1")


def test_las_categorias_tienen_contadores_independientes(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)
    actor = str(uuid4())

    _agotar(limitador, Category.GENERAL, actor)
    limitador.enforce(Category.SECRET_VALUE, actor)  # el general agotado no bloquea /value

    _agotar(limitador, Category.SECRET_VALUE, str(uuid4()))
    limitador.enforce(Category.GENERAL, str(uuid4()))


def test_el_limitador_se_libera_al_pasar_el_minuto(reloj: RelojFalso) -> None:
    limitador = RateLimiter(clock=reloj)
    _agotar(limitador, Category.AUTH, "203.0.113.7")
    problema = _assert_429(limitador, Category.AUTH, "203.0.113.7")

    reloj.avanzar(int(problema.headers["Retry-After"]))

    limitador.enforce(Category.AUTH, "203.0.113.7")


# --- Clasificación de rutas ----------------------------------------------------------------------

_SID = "3f2b8a4c-1d2e-4f5a-9b6c-7d8e9f0a1b2c"


@pytest.mark.parametrize(
    ("metodo", "ruta", "categoria"),
    [
        ("POST", "/api/v1/auth/login", Category.AUTH),
        ("POST", "/api/v1/auth/refresh", Category.AUTH),
        ("GET", f"/api/v1/secrets/{_SID}/value", Category.SECRET_VALUE),
        ("GET", "/api/v1/health", Category.HEALTH),
        ("GET", "/api/v1/health/ready", Category.HEALTH),
        ("GET", "/api/v1/projects", Category.GENERAL),
        ("GET", "/api/v1/auth/me", Category.GENERAL),
        ("POST", "/api/v1/auth/logout", Category.GENERAL),
        ("GET", f"/api/v1/secrets/{_SID}", Category.GENERAL),
        ("POST", f"/api/v1/secrets/{_SID}/rotate", Category.GENERAL),
        ("GET", "/api/v1/operations", Category.GENERAL),
    ],
)
def test_clasificacion_de_rutas(metodo: str, ruta: str, categoria: Category) -> None:
    assert classify(metodo, ruta) is categoria


def test_las_claves_vencidas_se_eliminan_de_la_memoria(reloj: RelojFalso) -> None:
    """OWASP API4: la memoria del limitador no crece con cada IP que pasó alguna vez. Cada 1000
    peticiones se eliminan las claves cuya última marca ya salió de la ventana."""
    ventana = SlidingWindow(limit=5, window_seconds=60, clock=reloj)
    for i in range(999):
        ventana.hit(f"ip-{i}")
    reloj.avanzar(61)

    ventana.hit("ip-nueva")  # petición 1000: dispara la limpieza

    assert set(ventana._hits) == {"ip-nueva"}


# --- H-56: límite de autenticación configurable --------------------------------------------------


def test_el_limite_de_autenticacion_se_puede_ajustar(reloj: RelojFalso) -> None:
    """H-56: el stack E2E sube el límite AUTH; las demás categorías conservan el del Cap. 6."""
    limitador = RateLimiter(clock=reloj, auth_limit=3)

    for _ in range(3):
        limitador.enforce(Category.AUTH, "203.0.113.7")
    _assert_429(limitador, Category.AUTH, "203.0.113.7")
    _agotar(limitador, Category.GENERAL, "actor")
    _assert_429(limitador, Category.GENERAL, "actor")


def test_el_limite_de_autenticacion_debe_ser_positivo(reloj: RelojFalso) -> None:
    with pytest.raises(ValueError):
        RateLimiter(clock=reloj, auth_limit=0)


def test_la_app_toma_el_limite_de_autenticacion_de_settings(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"rate_limit_auth_per_minute": 3}))
    limitador: RateLimiter = app.state.rate_limiter

    for _ in range(3):
        limitador.enforce(Category.AUTH, "203.0.113.7")
    _assert_429(limitador, Category.AUTH, "203.0.113.7")
