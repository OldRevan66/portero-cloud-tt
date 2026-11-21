// Almacén del access token (spec §8.3, H-36).
//
// El token vive solo en esta variable de módulo: nunca en localStorage, sessionStorage ni en
// cookies legibles por JavaScript, donde un XSS podría leerlo después (OWASP ASVS V3.2).
// Al recargar la página se pierde; la sesión se recupera con POST /auth/refresh usando la cookie
// HttpOnly del refresh, que JavaScript no ve.
//
// `subscribe` permite que React (useSyncExternalStore) se entere de cada cambio: así, cuando el
// interceptor borra el token porque no pudo renovarlo, la interfaz pasa sola a "sin sesión".

let accessToken: string | null = null;
const suscriptores = new Set<() => void>();

function avisar(): void {
  for (const aviso of suscriptores) {
    aviso();
  }
}

/** Token actual, o `null` si no hay sesión. */
export function getAccessToken(): string | null {
  return accessToken;
}

/** Guarda el token recibido de /auth/login o /auth/refresh. */
export function setAccessToken(token: string): void {
  accessToken = token;
  avisar();
}

/** Borra el token (logout o sesión expirada). */
export function clear(): void {
  accessToken = null;
  avisar();
}

/** Registra una función que se llama en cada cambio; devuelve la función para quitarla. */
export function subscribe(aviso: () => void): () => void {
  suscriptores.add(aviso);
  return () => {
    suscriptores.delete(aviso);
  };
}
