// Permisos del menú del Dashboard (spec §8.2).
//
// Replica la matriz rol→permisos del Cap. 6 (backend/src/portero/rbac/permissions.py) para
// decidir qué entradas del menú se muestran. Es solo conveniencia de interfaz: la autoridad es
// el backend, que responde 403/404 a lo que no corresponde aunque alguien teclee la URL.
import type { components } from "../api/schema";

export type Me = components["schemas"]["MeResponse"];
export type Assignment = components["schemas"]["portero__api__v1__auth__AssignmentOut"];

export type Permiso =
  | "secrets:read"
  | "secrets:write"
  | "secrets:rotate"
  | "secrets:delete"
  | "projects:manage"
  | "users:manage"
  | "audit:read"
  | "system:configure";

const GESTION_DE_SECRETOS: readonly Permiso[] = [
  "secrets:read",
  "secrets:write",
  "secrets:rotate",
  "secrets:delete",
];

/** Matriz del Cap. 6 por `role_id` (1 Administrador, 2 Líder Técnico, 3 Desarrollador). */
const PERMISOS_POR_ROL: ReadonlyMap<number, ReadonlySet<Permiso>> = new Map([
  [
    1,
    new Set<Permiso>([
      ...GESTION_DE_SECRETOS,
      "projects:manage",
      "users:manage",
      "audit:read",
      "system:configure",
    ]),
  ],
  [2, new Set<Permiso>([...GESTION_DE_SECRETOS, "projects:manage", "audit:read"])],
  [3, new Set<Permiso>(["secrets:read"])],
]);

/** Unión de los permisos de todas las asignaciones. Un `role_id` desconocido no aporta nada. */
export function permisosDe(me: Me): ReadonlySet<Permiso> {
  const permisos = new Set<Permiso>();
  for (const asignacion of me.assignments) {
    for (const permiso of PERMISOS_POR_ROL.get(asignacion.role_id) ?? []) {
      permisos.add(permiso);
    }
  }
  return permisos;
}

/**
 * ¿El alcance de la asignación cubre el contexto (`projectId`, `environmentId`)? Replica
 * `scope_matches` del Algoritmo 5 del Cap. 6 (backend/src/portero/rbac/evaluator.py):
 * - instancia (ambos nulos): cubre cualquier contexto;
 * - proyecto (solo `project_id`): cubre el proyecto y todos sus ambientes;
 * - ambiente (ambos): exige coincidencia exacta.
 * Un ambiente sin proyecto en el contexto es inválido y no queda cubierto (fallar de forma segura).
 */
function cubre(
  asignacion: Assignment,
  projectId: string | null,
  environmentId: string | null,
): boolean {
  if (environmentId !== null && projectId === null) {
    return false;
  }
  if (asignacion.project_id === null) {
    return asignacion.environment_id === null;
  }
  if (asignacion.environment_id === null) {
    return asignacion.project_id === projectId;
  }
  return asignacion.project_id === projectId && asignacion.environment_id === environmentId;
}

/**
 * Permisos del usuario en un contexto concreto: solo cuentan las asignaciones que lo cubren.
 * Decide los botones de cada pantalla (spec §8.2):
 * - `permisosEn(me, null, null)`: instancia (crear proyecto).
 * - `permisosEn(me, pid, null)`: proyecto (editarlo, crear o editar ambientes).
 * - `permisosEn(me, pid, eid)`: ambiente (crear, rotar, archivar secretos).
 * Es conveniencia de interfaz: el backend vuelve a evaluar cada petición.
 */
export function permisosEn(
  me: Me,
  projectId: string | null,
  environmentId: string | null,
): ReadonlySet<Permiso> {
  const permisos = new Set<Permiso>();
  for (const asignacion of me.assignments) {
    if (!cubre(asignacion, projectId, environmentId)) {
      continue;
    }
    for (const permiso of PERMISOS_POR_ROL.get(asignacion.role_id) ?? []) {
      permisos.add(permiso);
    }
  }
  return permisos;
}

export type MenuLabel = "Proyectos" | "Bitácora" | "Usuarios";

export interface MenuEntry {
  label: MenuLabel;
  path: string;
}

/**
 * Entradas del menú lateral (spec §8.2):
 * - Proyectos: todos (el backend devuelve solo los proyectos visibles, spec §4.2).
 * - Bitácora: con `audit:read` (spec §4.3).
 * - Usuarios: con `users:manage`, solo el Administrador (spec §4.4, H-23a).
 * Las Aplicaciones Cliente no tienen entrada propia: son del proyecto (spec §8.2) y se gestionan
 * dentro de /proyectos/:pid con `permisosEn(me, pid, null)` y `projects:manage` (spec §4.4).
 */
export function menuFor(me: Me): MenuEntry[] {
  const permisos = permisosDe(me);
  const menu: MenuEntry[] = [{ label: "Proyectos", path: "/proyectos" }];
  if (permisos.has("audit:read")) {
    menu.push({ label: "Bitácora", path: "/bitacora" });
  }
  if (permisos.has("users:manage")) {
    menu.push({ label: "Usuarios", path: "/usuarios" });
  }
  return menu;
}
