// Hooks de TanStack Query para los metadatos de los secretos (spec §8.4).
//
// Aquí solo hay metadatos: lista, detalle, historial de versiones, archivar y editar la
// descripción. Revelar, crear y rotar llevan el valor en claro y NO pasan por TanStack: se llaman
// directo desde el componente y después se usa `invalidarTrasCambio` para refrescar los metadatos.
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";

import {
  actualizarSecreto,
  archivarSecreto,
  listarSecretos,
  listarVersiones,
  obtenerSecreto,
  type SecretOut,
  type SecretUpdate,
} from "./secretsApi";

export const clavesSecretos = {
  delAmbiente: (pid: string, eid: string) => ["secretos", "ambiente", pid, eid] as const,
  detalle: (sid: string) => ["secretos", "detalle", sid] as const,
  versiones: (sid: string) => ["secretos", "detalle", sid, "versiones"] as const,
};

export function useSecretos(pid: string, eid: string) {
  return useQuery({
    queryKey: clavesSecretos.delAmbiente(pid, eid),
    queryFn: () => listarSecretos(pid, eid),
  });
}

export function useSecreto(sid: string) {
  return useQuery({ queryKey: clavesSecretos.detalle(sid), queryFn: () => obtenerSecreto(sid) });
}

/** Historial paginado con el cursor opaco del API ("Cargar más"). */
export function useVersiones(sid: string) {
  return useInfiniteQuery({
    queryKey: clavesSecretos.versiones(sid),
    queryFn: ({ pageParam }) => listarVersiones(sid, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (pagina) => pagina.next_cursor,
  });
}

/**
 * Refresca los metadatos tras crear o rotar: la lista del ambiente y, si se indica, el detalle
 * del secreto con su historial (la clave del historial cuelga de la del detalle).
 */
export function invalidarTrasCambio(
  queryClient: QueryClient,
  pid: string,
  eid: string,
  sid?: string,
): Promise<unknown> {
  const pendientes = [
    queryClient.invalidateQueries({ queryKey: clavesSecretos.delAmbiente(pid, eid) }),
  ];
  if (sid !== undefined) {
    pendientes.push(queryClient.invalidateQueries({ queryKey: clavesSecretos.detalle(sid) }));
  }
  return Promise.all(pendientes);
}

/** Archivar no lleva valores: puede ser una mutación de TanStack. */
export function useArchivarSecreto(secreto: SecretOut) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => archivarSecreto(secreto.id),
    onSuccess: async () => {
      // Archivado responde 404 en todas sus rutas: su detalle ya no sirve.
      queryClient.removeQueries({ queryKey: clavesSecretos.detalle(secreto.id) });
      await queryClient.invalidateQueries({
        queryKey: clavesSecretos.delAmbiente(secreto.project_id, secreto.environment_id),
      });
    },
  });
}

/** Editar la descripción (H-77): solo metadatos, puede ser una mutación de TanStack (spec §8.4). */
export function useActualizarSecreto(secreto: SecretOut) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cuerpo: SecretUpdate) => actualizarSecreto(secreto.id, cuerpo),
    onSuccess: () =>
      invalidarTrasCambio(queryClient, secreto.project_id, secreto.environment_id, secreto.id),
  });
}
