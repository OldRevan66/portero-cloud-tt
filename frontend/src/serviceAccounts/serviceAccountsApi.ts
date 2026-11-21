// Llamadas al API REST Gateway para las Aplicaciones Cliente (service accounts con PAT; spec §2,
// §3.7, H-21, H-23a). Las gestionan el Administrador y el Líder Técnico del proyecto
// (projects:manage con alcance de proyecto).
//
// Regla de la spec §8.4: `crearAplicacion` devuelve el `token` en claro (una sola vez), así que se
// llama directamente desde el componente, nunca dentro de `useMutation`: la caché de mutaciones
// guardaría la respuesta. Listar y revocar solo manejan metadatos y van por `queries.ts`.
import { api } from "../api/client";
import { ruta } from "../api/ruta";
import type { components } from "../api/schema";

export type ServiceAccountOut = components["schemas"]["ServiceAccountOut"];
export type ServiceAccountCreate = components["schemas"]["ServiceAccountCreate"];
export type ServiceAccountCreated = components["schemas"]["ServiceAccountCreated"];

/** GET /projects/{pid}/service-accounts: metadatos y `token_prefix`, nunca el token. */
export async function listarAplicaciones(pid: string): Promise<ServiceAccountOut[]> {
  const { data } = await api.get<ServiceAccountOut[]>(ruta`/projects/${pid}/service-accounts`);
  return data;
}

/**
 * POST /projects/{pid}/service-accounts: el 201 trae el `token` una sola vez. Llamada directa;
 * el token va a un useState local del modal (spec §8.4).
 */
export async function crearAplicacion(
  pid: string,
  cuerpo: ServiceAccountCreate,
): Promise<ServiceAccountCreated> {
  const { data } = await api.post<ServiceAccountCreated>(
    ruta`/projects/${pid}/service-accounts`,
    cuerpo,
  );
  return data;
}

/** DELETE /service-accounts/{sid}: pone `revoked_at` (idempotente). No lleva valores. */
export async function revocarAplicacion(sid: string): Promise<void> {
  await api.delete(ruta`/service-accounts/${sid}`);
}
