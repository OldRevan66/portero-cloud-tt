// Hooks de TanStack Query para los metadatos de las Aplicaciones Cliente (spec §8.4).
//
// Aquí no está la creación: su respuesta lleva el token en claro y se hace con una llamada
// directa desde `CreateServiceAccount`; después se usa `invalidarAplicaciones`.
import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";

import { listarAplicaciones, revocarAplicacion } from "./serviceAccountsApi";

export const clavesAplicaciones = {
  delProyecto: (pid: string) => ["aplicaciones", pid] as const,
};

export function useAplicaciones(pid: string) {
  return useQuery({
    queryKey: clavesAplicaciones.delProyecto(pid),
    queryFn: () => listarAplicaciones(pid),
  });
}

/** Refresca la lista del proyecto (tras crear). */
export function invalidarAplicaciones(queryClient: QueryClient, pid: string): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: clavesAplicaciones.delProyecto(pid) });
}

/** Revocar no lleva valores: puede ser una mutación de TanStack. */
export function useRevocarAplicacion(pid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sid: string) => revocarAplicacion(sid),
    onSuccess: () => invalidarAplicaciones(queryClient, pid),
  });
}
