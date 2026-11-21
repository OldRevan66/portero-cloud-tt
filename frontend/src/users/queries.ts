// Hooks de TanStack Query para usuarios y asignaciones de rol. Son metadatos (spec §8.4): pueden
// vivir en la caché. Cada mutación invalida las consultas afectadas.
//
// Aquí no están el alta ni el restablecimiento de contraseña (H-78): su cuerpo lleva una contraseña
// y la caché de mutaciones conservaría las variables. Se hacen con `crearUsuario` y
// `restablecerContrasena` directos y después `invalidarUsuarios` o `invalidarUsuario`.
import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";

import {
  actualizarUsuario,
  asignarRol,
  desactivarUsuario,
  desbloquearUsuario,
  listarAsignaciones,
  listarUsuarios,
  obtenerUsuario,
  quitarAsignacion,
  type AssignmentCreate,
  type UserUpdate,
} from "./usersApi";

/** Claves de la caché. Todas empiezan con "usuarios" para invalidarlas juntas si hace falta. */
export const clavesUsuarios = {
  todas: ["usuarios"] as const,
  lista: () => ["usuarios", "lista"] as const,
  detalle: (uid: string) => ["usuarios", "detalle", uid] as const,
  asignaciones: (uid: string) => ["usuarios", "detalle", uid, "asignaciones"] as const,
};

export function useUsuarios() {
  return useQuery({ queryKey: clavesUsuarios.lista(), queryFn: listarUsuarios });
}

export function useUsuario(uid: string) {
  return useQuery({ queryKey: clavesUsuarios.detalle(uid), queryFn: () => obtenerUsuario(uid) });
}

export function useAsignaciones(uid: string) {
  return useQuery({
    queryKey: clavesUsuarios.asignaciones(uid),
    queryFn: () => listarAsignaciones(uid),
  });
}

/** Refresca la lista de usuarios (tras el alta, que no es una mutación de TanStack). */
export function invalidarUsuarios(queryClient: QueryClient): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: clavesUsuarios.lista() });
}

/** Lista y detalle del usuario: cambian juntos al editar el nombre, el estado o el bloqueo. */
export function invalidarUsuario(queryClient: QueryClient, uid: string): Promise<unknown> {
  return Promise.all([
    invalidarUsuarios(queryClient),
    queryClient.invalidateQueries({ queryKey: clavesUsuarios.detalle(uid), exact: true }),
  ]);
}

/** Nombre o `is_active` (desactivar y reactivar). */
export function useActualizarUsuario(uid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cambios: UserUpdate) => actualizarUsuario(uid, cambios),
    onSuccess: () => invalidarUsuario(queryClient, uid),
  });
}

export function useDesactivarUsuario(uid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => desactivarUsuario(uid),
    onSuccess: () => invalidarUsuario(queryClient, uid),
  });
}

/** H-78: sin cuerpo, así que puede ir por `useMutation`. */
export function useDesbloquearUsuario(uid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => desbloquearUsuario(uid),
    onSuccess: () => invalidarUsuario(queryClient, uid),
  });
}

export function useAsignarRol(uid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (cuerpo: AssignmentCreate) => asignarRol(uid, cuerpo),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesUsuarios.asignaciones(uid) }),
  });
}

export function useQuitarAsignacion(uid: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (aid: string) => quitarAsignacion(uid, aid),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: clavesUsuarios.asignaciones(uid) }),
  });
}
