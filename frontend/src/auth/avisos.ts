// Avisos que otra pantalla deja para el login en `location.state` (p. ej., tras cambiar la
// contraseña, spec §3.6). En el state viaja solo la clave; LoginPage muestra el texto fijo de
// esta tabla, nunca un texto tomado del state.
export const AVISOS_LOGIN = {
  "contrasena-cambiada": "Contraseña cambiada. Inicia sesión con tu nueva contraseña.",
} as const;

export type AvisoLogin = keyof typeof AVISOS_LOGIN;

/** Texto del aviso que trae el state de /login, o null si no trae uno conocido. */
export function avisoDe(estado: unknown): string | null {
  if (typeof estado === "object" && estado !== null && "aviso" in estado) {
    const clave = estado.aviso;
    if (typeof clave === "string" && Object.hasOwn(AVISOS_LOGIN, clave)) {
      return AVISOS_LOGIN[clave as AvisoLogin];
    }
  }
  return null;
}
