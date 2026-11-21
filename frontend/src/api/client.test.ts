// Spec §8.3 (H-36, H-43): interceptores del cliente Axios.
// - Petición: agrega Authorization: Bearer con el token en memoria.
// - Respuesta: ante un 401 de una ruta que no es /auth/*, un solo refresh en vuelo; las
//   peticiones concurrentes esperan esa misma promesa y se reintentan una vez. Si el refresh
//   falla, se limpia la sesión y se avisa a la aplicación para que redirija a /login.
// - withCredentials solo en /auth/*: la cookie HttpOnly del refresh no viaja a otras rutas.
// - cambiarContrasena (spec §3.6, H-74): el 401 de "contraseña actual incorrecta" no lleva el
//   desafío `WWW-Authenticate: Bearer` (solo lo pone la dependencia Bearer, spec §6), así que no
//   se confunde con un access token vencido: ni renueva, ni reintenta, ni cierra la sesión.
//
// En lugar de red, un adaptador simulado de Axios (`api.defaults.adapter`) responde según la
// URL y la cabecera Authorization, y registra cada petición que recibe.
import {
  AxiosError,
  type AxiosAdapter,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from "axios";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import { clear, getAccessToken, setAccessToken } from "../auth/tokenStore";
import { api, cambiarContrasena, configureSession, login, logout, refreshSession } from "./client";

interface Respuesta {
  status: number;
  data?: unknown;
  headers?: Record<string, string>;
}

type Manejador = (config: InternalAxiosRequestConfig) => Respuesta | Promise<Respuesta>;

/** Instala el adaptador simulado y devuelve la lista de peticiones que recibe. */
function instalarAdaptador(manejar: Manejador): InternalAxiosRequestConfig[] {
  const recibidas: InternalAxiosRequestConfig[] = [];
  const adaptador: AxiosAdapter = async (config) => {
    recibidas.push(config);
    const { status, data, headers = {} } = await manejar(config);
    const response: AxiosResponse = { status, statusText: "", data, headers, config };
    if (status >= 200 && status < 300) {
      return response;
    }
    throw new AxiosError(`HTTP ${status}`, AxiosError.ERR_BAD_REQUEST, config, null, response);
  };
  api.defaults.adapter = adaptador;
  return recibidas;
}

function autorizacion(config: InternalAxiosRequestConfig): unknown {
  return config.headers.Authorization;
}

const esRefresh = (c: InternalAxiosRequestConfig) => c.url === "/auth/refresh";
const RESPUESTA_REFRESH = {
  status: 200,
  data: { access_token: "nuevo", token_type: "Bearer", expires_in: 900 },
};

let onSessionExpired: Mock<() => void>;

beforeEach(() => {
  clear();
  onSessionExpired = vi.fn<() => void>();
  configureSession({ onSessionExpired });
});

afterEach(() => {
  clear();
});

describe("interceptor de petición", () => {
  it("agrega Authorization: Bearer con el token en memoria", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador(() => ({ status: 200, data: [] }));

    await api.get("/projects");

    expect(recibidas).toHaveLength(1);
    expect(autorizacion(recibidas[0]!)).toBe("Bearer viejo");
  });

  it("sin token no envía Authorization", async () => {
    const recibidas = instalarAdaptador(() => ({ status: 200, data: [] }));

    await api.get("/health");

    expect(autorizacion(recibidas[0]!)).toBeUndefined();
  });
});

describe("interceptor de respuesta: refresh de vuelo único", () => {
  it("con 3 peticiones en vuelo que reciben 401, llama UNA vez a /auth/refresh y reintenta las 3", async () => {
    setAccessToken("viejo");

    // El refresh no responde hasta que las 3 peticiones hayan recibido su 401: así las tres
    // están en vuelo al mismo tiempo que el refresh.
    let liberarRefresh!: () => void;
    const refreshListo = new Promise<void>((resolve) => {
      liberarRefresh = resolve;
    });
    let rechazadas = 0;

    const recibidas = instalarAdaptador(async (config) => {
      if (esRefresh(config)) {
        await refreshListo;
        return RESPUESTA_REFRESH;
      }
      if (autorizacion(config) === "Bearer nuevo") {
        return { status: 200, data: { url: config.url } };
      }
      rechazadas += 1;
      if (rechazadas === 3) {
        liberarRefresh();
      }
      return { status: 401 };
    });

    const resultados = await Promise.all([
      api.get("/projects"),
      api.get("/projects/1/environments"),
      api.get("/operations"),
    ]);

    expect(resultados.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(recibidas.filter(esRefresh)).toHaveLength(1);
    expect(getAccessToken()).toBe("nuevo");

    const reintentos = recibidas.filter((c) => !esRefresh(c) && autorizacion(c) === "Bearer nuevo");
    expect(reintentos.map((c) => c.url).sort()).toEqual([
      "/operations",
      "/projects",
      "/projects/1/environments",
    ]);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it("si el refresh falla, limpia la sesión, avisa una vez para ir a /login y rechaza las 3", async () => {
    setAccessToken("viejo");
    // Todo responde 401, también el refresh: la cookie ya no es válida.
    const recibidas = instalarAdaptador(() => ({ status: 401 }));

    const resultados = await Promise.allSettled([
      api.get("/projects"),
      api.get("/projects/1/environments"),
      api.get("/operations"),
    ]);

    expect(resultados.map((r) => r.status)).toEqual(["rejected", "rejected", "rejected"]);
    expect(recibidas.filter(esRefresh)).toHaveLength(1);
    expect(getAccessToken()).toBeNull();
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
  });

  it("nunca reintenta en bucle: si el reintento vuelve a dar 401, se rinde", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador((config) =>
      esRefresh(config) ? RESPUESTA_REFRESH : { status: 401 },
    );

    const error: unknown = await api.get("/projects").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(AxiosError);
    expect((error as AxiosError).response?.status).toBe(401);
    expect(recibidas.filter(esRefresh)).toHaveLength(1);
    // La petición original y un único reintento.
    expect(recibidas.filter((c) => c.url === "/projects")).toHaveLength(2);
  });

  it("un 401 de /auth/login no dispara un refresh", async () => {
    const recibidas = instalarAdaptador(() => ({ status: 401 }));

    await expect(login("ana@example.com", "incorrecta")).rejects.toBeInstanceOf(AxiosError);

    expect(recibidas.map((c) => c.url)).toEqual(["/auth/login"]);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it("un 401 de /auth/refresh no dispara otro refresh", async () => {
    const recibidas = instalarAdaptador(() => ({ status: 401 }));

    await expect(refreshSession()).rejects.toBeInstanceOf(AxiosError);

    expect(recibidas.map((c) => c.url)).toEqual(["/auth/refresh"]);
  });
});

describe("withCredentials solo en /auth/*", () => {
  it("/auth/login va con withCredentials y guarda el access token en memoria", async () => {
    const recibidas = instalarAdaptador(() => RESPUESTA_REFRESH);

    await login("ana@example.com", "secreta-de-prueba");

    expect(recibidas[0]!.url).toBe("/auth/login");
    expect(recibidas[0]!.method).toBe("post");
    expect(recibidas[0]!.withCredentials).toBe(true);
    expect(getAccessToken()).toBe("nuevo");
  });

  it("/auth/refresh va con withCredentials y guarda el access token nuevo", async () => {
    const recibidas = instalarAdaptador(() => RESPUESTA_REFRESH);

    await expect(refreshSession()).resolves.toBe("nuevo");

    expect(recibidas[0]!.url).toBe("/auth/refresh");
    expect(recibidas[0]!.method).toBe("post");
    expect(recibidas[0]!.withCredentials).toBe(true);
    expect(getAccessToken()).toBe("nuevo");
  });

  it("el refresh que dispara el interceptor también va con withCredentials", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador((config) => {
      if (esRefresh(config)) return RESPUESTA_REFRESH;
      return autorizacion(config) === "Bearer nuevo" ? { status: 200 } : { status: 401 };
    });

    await api.get("/projects");

    const refresh = recibidas.find(esRefresh);
    expect(refresh?.withCredentials).toBe(true);
  });

  it("las demás rutas no llevan withCredentials", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador(() => ({ status: 200, data: [] }));

    await api.get("/projects");

    expect(recibidas[0]!.withCredentials).toBeFalsy();
  });
});

describe("refreshSession: vuelo único también fuera del interceptor", () => {
  it("dos llamadas simultáneas comparten una sola petición (StrictMode monta dos veces; H-43)", async () => {
    const recibidas = instalarAdaptador(() => RESPUESTA_REFRESH);

    const [a, b] = await Promise.all([refreshSession(), refreshSession()]);

    expect([a, b]).toEqual(["nuevo", "nuevo"]);
    expect(recibidas.filter(esRefresh)).toHaveLength(1);
  });

  it("al terminar, una llamada posterior hace una petición nueva", async () => {
    const recibidas = instalarAdaptador(() => RESPUESTA_REFRESH);

    await refreshSession();
    await refreshSession();

    expect(recibidas.filter(esRefresh)).toHaveLength(2);
  });
});

describe("logout", () => {
  it("llama a POST /auth/logout con Bearer y withCredentials, y borra el token", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador(() => ({ status: 204 }));

    await logout();

    expect(recibidas[0]!.url).toBe("/auth/logout");
    expect(recibidas[0]!.method).toBe("post");
    expect(autorizacion(recibidas[0]!)).toBe("Bearer viejo");
    expect(recibidas[0]!.withCredentials).toBe(true);
    expect(getAccessToken()).toBeNull();
  });

  it("borra el token aunque la petición falle, sin intentar un refresh", async () => {
    setAccessToken("viejo");
    const recibidas = instalarAdaptador(() => ({ status: 401 }));

    await logout();

    expect(getAccessToken()).toBeNull();
    expect(recibidas.map((c) => c.url)).toEqual(["/auth/logout"]);
  });
});

describe("cambiarContrasena (spec §3.6; H-74)", () => {
  const CUERPO = {
    current_password: "actual-de-prueba-no-real",
    new_password: "nueva-de-prueba-no-real",
  };
  const CREDENCIALES_INVALIDAS = {
    status: 401,
    data: { title: "No autenticado", status: 401, detail: "credenciales inválidas" },
  };
  const TOKEN_VENCIDO = {
    status: 401,
    data: { title: "No autenticado", status: 401, detail: "token inválido o expirado" },
    headers: { "www-authenticate": "Bearer" },
  };

  it("hace POST /users/me/password con Bearer y el cuerpo de la spec, sin withCredentials", async () => {
    setAccessToken("vigente");
    const recibidas = instalarAdaptador(() => ({ status: 204 }));

    await cambiarContrasena(CUERPO);

    expect(recibidas).toHaveLength(1);
    expect(recibidas[0]!.url).toBe("/users/me/password");
    expect(recibidas[0]!.method).toBe("post");
    expect(autorizacion(recibidas[0]!)).toBe("Bearer vigente");
    expect(JSON.parse(recibidas[0]!.data as string)).toEqual(CUERPO);
    expect(recibidas[0]!.withCredentials).toBeFalsy();
  });

  it("tras el 204 borra el token en memoria: el backend revocó todos los tokens (H-37)", async () => {
    setAccessToken("vigente");
    instalarAdaptador(() => ({ status: 204 }));

    await cambiarContrasena(CUERPO);

    expect(getAccessToken()).toBeNull();
  });

  it("un 401 sin desafío Bearer (contraseña actual incorrecta) no renueva, no reintenta ni cierra la sesión", async () => {
    setAccessToken("vigente");
    const recibidas = instalarAdaptador(() => CREDENCIALES_INVALIDAS);

    await expect(cambiarContrasena(CUERPO)).rejects.toMatchObject({ response: { status: 401 } });

    // Un reintento contaría como un segundo fallo de login para el bloqueo (spec §3.6).
    expect(recibidas.map((c) => c.url)).toEqual(["/users/me/password"]);
    expect(getAccessToken()).toBe("vigente");
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it("un 401 con WWW-Authenticate: Bearer (access vencido) renueva una vez y reintenta", async () => {
    setAccessToken("vencido");
    const recibidas = instalarAdaptador((c) => {
      if (esRefresh(c)) return RESPUESTA_REFRESH;
      return autorizacion(c) === "Bearer nuevo" ? { status: 204 } : TOKEN_VENCIDO;
    });

    await cambiarContrasena(CUERPO);

    expect(recibidas.map((c) => c.url)).toEqual([
      "/users/me/password",
      "/auth/refresh",
      "/users/me/password",
    ]);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it("si falla (422), el token sigue en memoria", async () => {
    setAccessToken("vigente");
    instalarAdaptador(() => ({ status: 422, data: { title: "Entrada no procesable" } }));

    await expect(cambiarContrasena(CUERPO)).rejects.toMatchObject({ response: { status: 422 } });

    expect(getAccessToken()).toBe("vigente");
  });
});
