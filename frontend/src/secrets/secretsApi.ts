// Llamadas al API REST Gateway para secretos (spec §2, CU-02, CU-03, CU-04).
//
// Regla de la spec §8.4: las funciones que llevan un valor en claro (`revelarValor`,
// `crearSecreto`, `rotarSecreto`) se llaman directamente desde los componentes, nunca dentro de
// `useQuery` ni `useMutation`: la caché de TanStack guardaría el valor (`data` o `variables`)
// hasta su recolección. El resto son metadatos y sí pasan por los hooks de `queries.ts`.
import { api } from "../api/client";
import { ruta } from "../api/ruta";
import type { components } from "../api/schema";

export type SecretOut = components["schemas"]["SecretOut"];
export type SecretCreate = components["schemas"]["SecretCreate"];
export type SecretUpdate = components["schemas"]["SecretUpdate"];
export type SecretValueOut = components["schemas"]["SecretValueOut"];
export type RotationOut = components["schemas"]["RotationOut"];
export type SecretVersionPage = components["schemas"]["SecretVersionPage"];

/** Versiones por página del historial (el API admite de 1 a 100). */
export const TAMANO_PAGINA_VERSIONES = 10;

/** GET /projects/{pid}/environments/{eid}/secrets: metadatos, nunca valores. */
export async function listarSecretos(pid: string, eid: string): Promise<SecretOut[]> {
  const { data } = await api.get<SecretOut[]>(ruta`/projects/${pid}/environments/${eid}/secrets`);
  return data;
}

/** GET /secrets/{id}: metadatos. Un secreto archivado responde 404. */
export async function obtenerSecreto(sid: string): Promise<SecretOut> {
  const { data } = await api.get<SecretOut>(ruta`/secrets/${sid}`);
  return data;
}

/**
 * GET /secrets/{id}/value (CU-03): la única respuesta del sistema con un valor en claro.
 * Llamada directa; el resultado va a un useState local (spec §8.4).
 */
export async function revelarValor(sid: string): Promise<SecretValueOut> {
  const { data } = await api.get<SecretValueOut>(ruta`/secrets/${sid}/value`);
  return data;
}

/** POST .../secrets (CU-02). Llamada directa: el cuerpo lleva el valor (spec §8.4). */
export async function crearSecreto(
  pid: string,
  eid: string,
  cuerpo: SecretCreate,
): Promise<SecretOut> {
  const { data } = await api.post<SecretOut>(
    ruta`/projects/${pid}/environments/${eid}/secrets`,
    cuerpo,
  );
  return data;
}

/** POST /secrets/{id}/rotate (CU-04). Llamada directa: el cuerpo lleva el valor (spec §8.4). */
export async function rotarSecreto(sid: string, nuevoValor: string): Promise<RotationOut> {
  const { data } = await api.post<RotationOut>(ruta`/secrets/${sid}/rotate`, {
    new_value: nuevoValor,
  });
  return data;
}

/** DELETE /secrets/{id}: archiva (pone `archived_at`); no lleva valores. */
export async function archivarSecreto(sid: string): Promise<void> {
  await api.delete(ruta`/secrets/${sid}`);
}

/** PATCH /secrets/{id}: solo la descripción (H-77); no lleva valores. */
export async function actualizarSecreto(sid: string, cuerpo: SecretUpdate): Promise<SecretOut> {
  const { data } = await api.patch<SecretOut>(ruta`/secrets/${sid}`, cuerpo);
  return data;
}

/** GET /secrets/{id}/versions: una página del historial, sin valores (cursor opaco, spec §1). */
export async function listarVersiones(
  sid: string,
  cursor: string | null,
): Promise<SecretVersionPage> {
  const params: Record<string, string | number> = { limit: TAMANO_PAGINA_VERSIONES };
  if (cursor !== null) {
    params.cursor = cursor;
  }
  const { data } = await api.get<SecretVersionPage>(ruta`/secrets/${sid}/versions`, { params });
  return data;
}
