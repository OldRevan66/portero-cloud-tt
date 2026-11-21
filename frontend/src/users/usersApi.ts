// Llamadas al API REST Gateway para usuarios, asignaciones de rol, desbloqueo y restablecimiento
// de contraseña (CU-05; spec §2, §4.4; H-73, H-78).
// Solo el Administrador las puede usar (users:manage de instancia); a los demás el backend les
// responde 403.
//
// H-62 (OWASP ASVS 4.0.3 V5.1.3 y V5.3): cada `uid` y `aid` debe ser un UUID; si no lo es, se
// rechaza aquí, sin llamar al API, y además va codificado como un solo segmento con `ruta`. Así
// "../me/password" no puede convertir una consulta en otra ruta de /users, aunque una pantalla
// olvide validar lo que llega en su URL.
//
// Regla de la spec §8.4: `crearUsuario` y `restablecerContrasena` llevan una contraseña en el
// cuerpo, así que se llaman directamente desde el componente, nunca dentro de `useMutation` (la
// caché de mutaciones conservaría las variables). Lo demás solo maneja metadatos y va por
// `queries.ts`.
import { api } from "../api/client";
import { ruta } from "../api/ruta";
import type { components } from "../api/schema";
import { esUuid } from "../lib/identificadores";

export type UserOut = components["schemas"]["UserOut"];
export type UserCreate = components["schemas"]["UserCreate"];
export type UserUpdate = components["schemas"]["UserUpdate"];
export type AssignmentCreate = components["schemas"]["AssignmentCreate"];
export type PasswordReset = components["schemas"]["PasswordReset"];
export type AssignmentOut = components["schemas"]["portero__api__v1__users__AssignmentOut"];

/** Lanza `Error` si algún identificador no es un UUID (H-62). */
function exigirUuid(...identificadores: string[]): void {
  if (!identificadores.every(esUuid)) {
    throw new Error("Identificador inválido: se esperaba un UUID");
  }
}

/** GET /users: todos los usuarios, activos e inactivos. */
export async function listarUsuarios(): Promise<UserOut[]> {
  const { data } = await api.get<UserOut[]>("/users");
  return data;
}

/** GET /users/{uid}. */
export async function obtenerUsuario(uid: string): Promise<UserOut> {
  exigirUuid(uid);
  const { data } = await api.get<UserOut>(ruta`/users/${uid}`);
  return data;
}

/**
 * POST /users: alta con contraseña inicial. Llamada directa desde el componente, nunca en
 * `useMutation` (spec §8.4); después se usa `invalidarUsuarios`.
 */
export async function crearUsuario(cuerpo: UserCreate): Promise<UserOut> {
  const { data } = await api.post<UserOut>("/users", cuerpo);
  return data;
}

/** PATCH /users/{uid}: nombre o `is_active` (desactivar y reactivar). */
export async function actualizarUsuario(uid: string, cambios: UserUpdate): Promise<UserOut> {
  exigirUuid(uid);
  const { data } = await api.patch<UserOut>(ruta`/users/${uid}`, cambios);
  return data;
}

/** DELETE /users/{uid}: desactivación lógica; invalida los tokens del usuario (H-37). */
export async function desactivarUsuario(uid: string): Promise<void> {
  exigirUuid(uid);
  await api.delete(ruta`/users/${uid}`);
}

/** GET /users/{uid}/role-assignments (H-73): orden estable por rol, fecha e id. */
export async function listarAsignaciones(uid: string): Promise<AssignmentOut[]> {
  exigirUuid(uid);
  const { data } = await api.get<AssignmentOut[]>(ruta`/users/${uid}/role-assignments`);
  return data;
}

/** POST /users/{uid}/role-assignments: instancia solo para el Administrador (H-22). */
export async function asignarRol(uid: string, cuerpo: AssignmentCreate): Promise<AssignmentOut> {
  exigirUuid(uid);
  const { data } = await api.post<AssignmentOut>(ruta`/users/${uid}/role-assignments`, cuerpo);
  return data;
}

/** POST /users/{uid}/unlock (H-78): reinicia el contador de fallos y quita el bloqueo. */
export async function desbloquearUsuario(uid: string): Promise<void> {
  exigirUuid(uid);
  await api.post(ruta`/users/${uid}/unlock`);
}

/**
 * POST /users/{uid}/password-reset (H-78): contraseña temporal; cierra todas las sesiones del
 * usuario (H-37). Llamada directa desde el componente, nunca en `useMutation` (spec §8.4).
 */
export async function restablecerContrasena(uid: string, nueva: string): Promise<void> {
  exigirUuid(uid);
  const cuerpo: PasswordReset = { new_password: nueva };
  await api.post(ruta`/users/${uid}/password-reset`, cuerpo);
}

/** DELETE /users/{uid}/role-assignments/{aid}: 409 si es la del último Administrador (H-59). */
export async function quitarAsignacion(uid: string, aid: string): Promise<void> {
  exigirUuid(uid, aid);
  await api.delete(ruta`/users/${uid}/role-assignments/${aid}`);
}
