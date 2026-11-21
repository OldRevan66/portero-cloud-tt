// Cliente HTTP del Dashboard: única puerta hacia el API REST Gateway (spec §8.3, H-36, H-43).
//
// - Interceptor de petición: agrega `Authorization: Bearer <access token en memoria>`.
// - Interceptor de respuesta: ante un 401 de una ruta que no es /auth/*, renueva la sesión con
//   UN solo refresh en vuelo (las peticiones concurrentes esperan esa misma promesa) y reintenta
//   cada petición una sola vez. Si no se puede renovar, borra el token y avisa a la aplicación.
// - `withCredentials` solo en /auth/login, /auth/refresh y /auth/logout: son las únicas
//   llamadas que necesitan la cookie HttpOnly del refresh (Path=/api/v1/auth).
// - H-74: POST /users/me/password responde 401 si la contraseña actual no coincide. Ese 401 no
//   trae `WWW-Authenticate: Bearer` (solo lo pone la dependencia Bearer, spec §6), así que no se
//   renueva ni se reintenta: un reintento contaría como otro fallo de login para el bloqueo y el
//   segundo 401 cerraría la sesión. Si sí trae el desafío, el access venció y se renueva igual
//   que en cualquier otra ruta.
//
// ¿Por qué un solo refresh? El backend rota el refresh en cada uso y, si ve reusado uno ya
// rotado, lo trata como robo y cierra todas las sesiones del usuario (H-43). Dos refresh
// simultáneos con la misma cookie provocarían justo eso.
import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";

import { clear, getAccessToken, setAccessToken } from "../auth/tokenStore";
import type { components } from "./schema";

type TokenResponse = components["schemas"]["TokenResponse"];
export type PasswordChange = components["schemas"]["PasswordChange"];

/** Ruta que reverifica la contraseña actual (spec §3.6). */
const RUTA_CAMBIO_CONTRASENA = "/users/me/password";

export interface SessionOptions {
  /** Se llama una vez cuando la sesión no se pudo renovar (el token ya se borró). */
  onSessionExpired: () => void;
}

/** Instancia de Axios para toda la API v1. En desarrollo, Vite manda /api a localhost:8000. */
export const api = axios.create({ baseURL: "/api/v1" });

let onSessionExpired: () => void = () => {};
let refreshEnVuelo: Promise<string> | null = null;
let renovacionEnVuelo: Promise<void> | null = null;

/** La aplicación registra aquí qué hacer cuando la sesión expira (vaciar la caché). */
export function configureSession(options: SessionOptions): void {
  onSessionExpired = options.onSessionExpired;
}

/** POST /auth/login (spec §3.1). Guarda el access token en memoria; el refresh llega en cookie. */
export async function login(email: string, password: string): Promise<void> {
  const { data } = await api.post<TokenResponse>(
    "/auth/login",
    { email, password },
    { withCredentials: true },
  );
  setAccessToken(data.access_token);
}

/**
 * POST /auth/refresh (spec §3.2): canjea la cookie por un par nuevo y guarda el access token.
 *
 * Vuelo único: si ya hay un refresh en curso, devuelve esa misma promesa. Cubre el arranque
 * (StrictMode ejecuta dos veces los efectos en desarrollo) y el interceptor.
 */
export function refreshSession(): Promise<string> {
  if (refreshEnVuelo === null) {
    refreshEnVuelo = api
      .post<TokenResponse>("/auth/refresh", undefined, { withCredentials: true })
      .then(({ data }) => {
        setAccessToken(data.access_token);
        return data.access_token;
      })
      .finally(() => {
        refreshEnVuelo = null;
      });
  }
  return refreshEnVuelo;
}

/** POST /auth/logout (spec §3.3). El token en memoria se borra aunque la petición falle. */
export async function logout(): Promise<void> {
  try {
    await api.post("/auth/logout", undefined, { withCredentials: true });
  } catch {
    // La sesión local se cierra de todos modos; el access token caduca solo en 15 min.
  } finally {
    clear();
  }
}

/**
 * POST /users/me/password (spec §3.6). Con el 204, el backend ya revocó todos los tokens del
 * usuario (H-37) y borró la cookie del refresh, así que también se borra el token en memoria.
 * Se llama directo desde el componente, nunca en `useMutation`: el cuerpo lleva contraseñas
 * (spec §8.4). Si falla, el token se conserva y el error se propaga.
 */
export async function cambiarContrasena(cuerpo: PasswordChange): Promise<void> {
  await api.post(RUTA_CAMBIO_CONTRASENA, cuerpo);
  clear();
}

/** Renovación que usa el interceptor: un solo intento y un solo aviso aunque fallen N peticiones. */
function renovarSesion(): Promise<void> {
  if (renovacionEnVuelo === null) {
    renovacionEnVuelo = refreshSession()
      .then(
        () => undefined,
        (error: unknown) => {
          expirarSesion();
          throw error;
        },
      )
      .finally(() => {
        renovacionEnVuelo = null;
      });
  }
  return renovacionEnVuelo;
}

function expirarSesion(): void {
  clear();
  onSessionExpired();
}

function esRutaDeAutenticacion(url: string | undefined): boolean {
  return url?.startsWith("/auth/") ?? false;
}

/** ¿El 401 trae el desafío `WWW-Authenticate: Bearer` de la dependencia Bearer (RFC 6750)? */
function tieneDesafioBearer(error: AxiosError): boolean {
  const desafio: unknown = error.response?.headers["www-authenticate"];
  return typeof desafio === "string" && desafio.toLowerCase().startsWith("bearer");
}

/** 401 por credenciales en el cuerpo (contraseña actual incorrecta), no por el token (H-74). */
function esFalloDeReverificacion(config: InternalAxiosRequestConfig, error: AxiosError): boolean {
  return config.url === RUTA_CAMBIO_CONTRASENA && !tieneDesafioBearer(error);
}

interface ConfigReintentable extends InternalAxiosRequestConfig {
  _reintentada?: boolean;
}

api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token !== null) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(undefined, async (error: unknown) => {
  if (!(error instanceof AxiosError) || error.response?.status !== 401 || !error.config) {
    throw error;
  }
  const config: ConfigReintentable = error.config;
  const tokenActual = getAccessToken();
  if (
    esRutaDeAutenticacion(config.url) ||
    tokenActual === null ||
    esFalloDeReverificacion(config, error)
  ) {
    // Las rutas /auth/* no se renuevan, sin token la sesión ya terminó y la contraseña actual
    // incorrecta no se arregla con un refresh (H-74).
    throw error;
  }
  if (config._reintentada) {
    // Ya se renovó y el reintento volvió a dar 401 (p. ej., corte H-37): no hay bucle.
    expirarSesion();
    throw error;
  }
  config._reintentada = true;

  // Si la petición salió con un token que otra petición ya renovó, basta con reintentarla:
  // otro refresh rotaría la cookie sin necesidad.
  if (config.headers.Authorization === `Bearer ${tokenActual}`) {
    await renovarSesion();
  }
  return api(config);
});
