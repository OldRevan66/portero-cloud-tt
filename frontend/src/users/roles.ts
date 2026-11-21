// Nombres de los roles para la interfaz (Cap. 6, matriz rol→permisos; spec §2, H-22, H-73).
//
// GET /users/{uid}/role-assignments (H-73) solo trae `role_id`; el nombre se pone aquí. Los
// identificadores son los mismos que usa `auth/permissions.ts` (1, 2, 3).
import type { components } from "../api/schema";

export type Role = components["schemas"]["Role"];

export const ROL_ADMINISTRADOR: Role = 1;

export const ROLES: readonly { id: Role; nombre: string }[] = [
  { id: 1, nombre: "Administrador" },
  { id: 2, nombre: "Líder Técnico" },
  { id: 3, nombre: "Desarrollador" },
];

/** Nombre en español del rol; un `role_id` desconocido se muestra como tal. */
export function nombreRol(roleId: number): string {
  return ROLES.find((rol) => rol.id === roleId)?.nombre ?? `Rol ${roleId}`;
}
