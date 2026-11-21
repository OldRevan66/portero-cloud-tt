// Llamadas al API REST Gateway para proyectos y ambientes (spec §2, CU-07, RF-030 a RF-032).
// Solo metadatos: aquí no viaja ningún valor de secreto, así que los hooks pueden usar TanStack
// Query (spec §8.4).
import { api } from "../api/client";
import { ruta } from "../api/ruta";
import type { components } from "../api/schema";

export type ProjectOut = components["schemas"]["ProjectOut"];
export type ProjectCreate = components["schemas"]["ProjectCreate"];
export type ProjectUpdate = components["schemas"]["ProjectUpdate"];
export type EnvironmentOut = components["schemas"]["EnvironmentOut"];
export type EnvironmentCreate = components["schemas"]["EnvironmentCreate"];
export type EnvironmentUpdate = components["schemas"]["EnvironmentUpdate"];

/** Longitudes máximas del nombre (backend/src/portero/api/v1/projects.py). */
export const MAX_NOMBRE_PROYECTO = 128;
export const MAX_NOMBRE_AMBIENTE = 64;

/** GET /projects: solo los proyectos visibles para el usuario (spec §4.2, H-23c). */
export async function listarProyectos(): Promise<ProjectOut[]> {
  const { data } = await api.get<ProjectOut[]>("/projects");
  return data;
}

/** GET /projects/{pid} (H-23d). */
export async function obtenerProyecto(pid: string): Promise<ProjectOut> {
  const { data } = await api.get<ProjectOut>(ruta`/projects/${pid}`);
  return data;
}

/** POST /projects: crea también development, staging y production (RF-031). */
export async function crearProyecto(cuerpo: ProjectCreate): Promise<ProjectOut> {
  const { data } = await api.post<ProjectOut>("/projects", cuerpo);
  return data;
}

/** PATCH /projects/{pid}. */
export async function actualizarProyecto(pid: string, cuerpo: ProjectUpdate): Promise<ProjectOut> {
  const { data } = await api.patch<ProjectOut>(ruta`/projects/${pid}`, cuerpo);
  return data;
}

/**
 * DELETE /projects/{pid}: archiva el proyecto (RF-032, H-77). Si tiene secretos activos, el API
 * responde 409 salvo que se confirme con `?confirm=true`; entonces archiva también los secretos.
 */
export async function archivarProyecto(pid: string, confirmar: boolean): Promise<void> {
  if (confirmar) {
    await api.delete(ruta`/projects/${pid}`, { params: { confirm: true } });
  } else {
    await api.delete(ruta`/projects/${pid}`);
  }
}

/** GET /projects/{pid}/environments: lista filtrada por las asignaciones (H-23d). */
export async function listarAmbientes(pid: string): Promise<EnvironmentOut[]> {
  const { data } = await api.get<EnvironmentOut[]>(ruta`/projects/${pid}/environments`);
  return data;
}

/** POST /projects/{pid}/environments. */
export async function crearAmbiente(
  pid: string,
  cuerpo: EnvironmentCreate,
): Promise<EnvironmentOut> {
  const { data } = await api.post<EnvironmentOut>(ruta`/projects/${pid}/environments`, cuerpo);
  return data;
}

/** PATCH /projects/{pid}/environments/{eid}. */
export async function actualizarAmbiente(
  pid: string,
  eid: string,
  cuerpo: EnvironmentUpdate,
): Promise<EnvironmentOut> {
  const { data } = await api.patch<EnvironmentOut>(
    ruta`/projects/${pid}/environments/${eid}`,
    cuerpo,
  );
  return data;
}

/** DELETE /projects/{pid}/environments/{eid}: solo si no tiene secretos; si no, 409 (H-39, H-77). */
export async function eliminarAmbiente(pid: string, eid: string): Promise<void> {
  await api.delete(ruta`/projects/${pid}/environments/${eid}`);
}
