// Hooks de TanStack Query para proyectos y ambientes. Son metadatos (spec §8.4): pueden vivir en
// la caché. Cada mutación invalida las consultas afectadas para que la pantalla se refresque.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  actualizarAmbiente,
  actualizarProyecto,
  archivarProyecto,
  crearAmbiente,
  eliminarAmbiente,
  crearProyecto,
  listarAmbientes,
  listarProyectos,
  obtenerProyecto,
  type EnvironmentCreate,
  type EnvironmentUpdate,
  type ProjectCreate,
  type ProjectUpdate,
} from "./projectsApi";

/** Claves de la caché. Todas empiezan con "proyectos" para invalidarlas juntas si hace falta. */
export const clavesProyectos = {
  todas: ["proyectos"] as const,
  lista: () => ["proyectos", "lista"] as const,
  detalle: (pid: string) => ["proyectos", "detalle", pid] as const,
  ambientes: (pid: string) => ["proyectos", "detalle", pid, "ambientes"] as const,
};

export function useProyectos() {
  return useQuery({ queryKey: clavesProyectos.lista(), queryFn: listarProyectos });
}

export function useProyecto(pid: string) {
  return useQuery({ queryKey: clavesProyectos.detalle(pid), queryFn: () => obtenerProyecto(pid) });
}

/** `habilitado` permite pedir los ambientes solo cuando se abre el proyecto en el árbol. */
export function useAmbientes(pid: string, habilitado = true) {
  return useQuery({
    queryKey: clavesProyectos.ambientes(pid),
    queryFn: () => listarAmbientes(pid),
    enabled: habilitado,
  });
}

export function useCrearProyecto() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cuerpo: ProjectCreate) => crearProyecto(cuerpo),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesProyectos.lista() }),
  });
}

export function useActualizarProyecto(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cuerpo: ProjectUpdate) => actualizarProyecto(pid, cuerpo),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: clavesProyectos.lista() }),
        queryClient.invalidateQueries({ queryKey: clavesProyectos.detalle(pid), exact: true }),
      ]),
  });
}

/**
 * Archivar el proyecto (H-77). `confirmar` = reintento con `?confirm=true` tras el 409. El detalle
 * ya responde 404, así que se quita de la caché en vez de pedirlo otra vez.
 */
export function useArchivarProyecto(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (confirmar: boolean) => archivarProyecto(pid, confirmar),
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: clavesProyectos.detalle(pid) });
      await queryClient.invalidateQueries({ queryKey: clavesProyectos.lista() });
    },
  });
}

export function useCrearAmbiente(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cuerpo: EnvironmentCreate) => crearAmbiente(pid, cuerpo),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesProyectos.ambientes(pid) }),
  });
}

export function useActualizarAmbiente(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ eid, cuerpo }: { eid: string; cuerpo: EnvironmentUpdate }) =>
      actualizarAmbiente(pid, eid, cuerpo),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesProyectos.ambientes(pid) }),
  });
}

/** Eliminar un ambiente sin secretos (H-39, H-77). */
export function useEliminarAmbiente(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (eid: string) => eliminarAmbiente(pid, eid),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesProyectos.ambientes(pid) }),
  });
}
