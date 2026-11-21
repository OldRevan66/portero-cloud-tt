// Spec §8.2: el menú se calcula desde GET /auth/me con una función pura que replica la matriz
// RBAC del Cap. 6 (backend/src/portero/rbac/permissions.py). Es solo conveniencia de interfaz:
// la autoridad es el backend.
//   Bitácora              ↔ audit:read      (Administrador, Líder Técnico)
//   Usuarios              ↔ users:manage    (solo Administrador; spec §4.4, H-23a)
// Las Aplicaciones Cliente no van en el menú: son del proyecto (spec §8.2) y se gestionan dentro
// de /proyectos/:pid con `permisosEn(me, pid, null)` y projects:manage (spec §4.4, sesión 17).
// Se decide por role_id (1, 2, 3), no por el texto `role`.
//
// `permisosEn` decide los botones de una pantalla concreta (Rotar, Archivar...): solo cuentan las
// asignaciones cuyo alcance cubre ese ambiente, como `scope_matches` del Algoritmo 5 del Cap. 6
// (backend/src/portero/rbac/evaluator.py). Instancia cubre todo; proyecto cubre sus ambientes;
// ambiente exige coincidencia exacta.
import { describe, expect, it } from "vitest";

import { menuFor, permisosEn, type Assignment, type Me } from "./permissions";

const ADMINISTRADOR = 1;
const LIDER_TECNICO = 2;
const DESARROLLADOR = 3;

function asignacion(
  role_id: number,
  role: string,
  project_id: string | null = null,
  environment_id: string | null = null,
): Assignment {
  return {
    id: `asig-${role_id}-${project_id ?? "global"}`,
    role_id,
    role,
    project_id,
    environment_id,
  };
}

function usuario(assignments: Assignment[]): Me {
  return { id: "u-1", email: "ana@example.com", name: "Ana", assignments };
}

function etiquetas(me: Me): string[] {
  return menuFor(me).map((entrada) => entrada.label);
}

describe("menuFor", () => {
  it("Administrador (alcance global) ve Proyectos, Bitácora y Usuarios, en ese orden", () => {
    const me = usuario([asignacion(ADMINISTRADOR, "Administrador")]);

    expect(etiquetas(me)).toEqual(["Proyectos", "Bitácora", "Usuarios"]);
  });

  it("la entrada Usuarios lleva a /usuarios", () => {
    const me = usuario([asignacion(ADMINISTRADOR, "Administrador")]);

    expect(menuFor(me)).toContainEqual({ label: "Usuarios", path: "/usuarios" });
  });

  it("Líder Técnico de un proyecto ve Proyectos y Bitácora", () => {
    const me = usuario([asignacion(LIDER_TECNICO, "Líder Técnico", "p-1")]);

    expect(etiquetas(me)).toEqual(["Proyectos", "Bitácora"]);
  });

  it("Desarrollador no ve Bitácora", () => {
    const me = usuario([asignacion(DESARROLLADOR, "Desarrollador", "p-1", "amb-1")]);

    expect(etiquetas(me)).toEqual(["Proyectos"]);
  });

  it("sin asignaciones solo ve Proyectos (la lista que devuelva el backend)", () => {
    expect(etiquetas(usuario([]))).toEqual(["Proyectos"]);
  });

  it("Administrador que además es Desarrollador de un proyecto: la unión conserva el orden", () => {
    const me = usuario([
      asignacion(DESARROLLADOR, "Desarrollador", "p-1", "amb-1"),
      asignacion(ADMINISTRADOR, "Administrador"),
    ]);

    expect(etiquetas(me)).toEqual(["Proyectos", "Bitácora", "Usuarios"]);
  });

  it("con varias asignaciones toma la unión, sin repetir entradas", () => {
    const me = usuario([
      asignacion(DESARROLLADOR, "Desarrollador", "p-1", "amb-1"),
      asignacion(LIDER_TECNICO, "Líder Técnico", "p-2"),
      asignacion(LIDER_TECNICO, "Líder Técnico", "p-3"),
    ]);

    expect(etiquetas(me)).toEqual(["Proyectos", "Bitácora"]);
  });

  it("un role_id desconocido no concede nada extra (denegación por omisión)", () => {
    const me = usuario([asignacion(99, "Administrador")]);

    expect(etiquetas(me)).toEqual(["Proyectos"]);
  });

  it("cada entrada tiene una ruta interna", () => {
    const me = usuario([asignacion(ADMINISTRADOR, "Administrador")]);

    const entradas = menuFor(me);

    expect(entradas.length).toBeGreaterThan(0);
    for (const entrada of entradas) {
      expect(entrada.path).toMatch(/^\/[a-z-]*$/);
    }
  });
});

describe("permisosEn", () => {
  it("Líder del proyecto puede rotar y archivar en cualquiera de sus ambientes", () => {
    const me = usuario([asignacion(LIDER_TECNICO, "Líder Técnico", "p-1")]);

    const permisos = permisosEn(me, "p-1", "amb-1");

    expect(permisos.has("secrets:rotate")).toBe(true);
    expect(permisos.has("secrets:delete")).toBe(true);
    expect(permisos.has("secrets:write")).toBe(true);
  });

  it("la asignación de un proyecto no concede nada en otro proyecto", () => {
    const me = usuario([asignacion(LIDER_TECNICO, "Líder Técnico", "p-1")]);

    expect(permisosEn(me, "p-2", "amb-9").size).toBe(0);
  });

  it("la asignación de ambiente solo cubre ese ambiente", () => {
    const me = usuario([asignacion(LIDER_TECNICO, "Líder Técnico", "p-1", "amb-1")]);

    expect(permisosEn(me, "p-1", "amb-1").has("secrets:rotate")).toBe(true);
    expect(permisosEn(me, "p-1", "amb-2").size).toBe(0);
  });

  it("el Administrador de instancia tiene todos los permisos de secretos en cualquier ambiente", () => {
    const me = usuario([asignacion(ADMINISTRADOR, "Administrador")]);

    const permisos = permisosEn(me, "p-7", "amb-7");

    for (const permiso of [
      "secrets:read",
      "secrets:write",
      "secrets:rotate",
      "secrets:delete",
    ] as const) {
      expect(permisos.has(permiso)).toBe(true);
    }
  });

  it("Líder en un proyecto y Desarrollador en otro: en el segundo solo puede leer", () => {
    const me = usuario([
      asignacion(LIDER_TECNICO, "Líder Técnico", "p-1"),
      asignacion(DESARROLLADOR, "Desarrollador", "p-2"),
    ]);

    expect([...permisosEn(me, "p-2", "amb-2")]).toEqual(["secrets:read"]);
  });

  it("un role_id desconocido no concede nada (denegación por omisión)", () => {
    const me = usuario([asignacion(99, "Administrador")]);

    expect(permisosEn(me, "p-1", "amb-1").size).toBe(0);
  });
});
