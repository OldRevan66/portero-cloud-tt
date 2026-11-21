// Preparación de datos por la API (sin pasar por la interfaz), para que cada archivo de pruebas
// cree lo que necesita y no dependa del orden ni de otros archivos. El access token vive solo en
// variables locales de la prueba, igual que en el Dashboard (H-36).
import { randomUUID } from "node:crypto";

import { expect, type APIRequestContext } from "@playwright/test";

import { credenciales, type Credenciales, type Rol } from "./credenciales";
import { PROYECTO } from "./sesion";

const API = "/api/v1";

/** Nombre único por corrida (mayúsculas, válido como nombre de secreto). */
export function unico(prefijo: string): string {
  return `${prefijo}_${randomUUID().slice(0, 8).toUpperCase()}`;
}

/** Valor de ejemplo, obviamente falso (mismo prefijo que el seed) y único. */
export function valorDemo(): string {
  return `demo-no-es-real-e2e-${randomUUID()}`;
}

export class ApiE2E {
  private constructor(
    private readonly request: APIRequestContext,
    private readonly token: string,
  ) {}

  static async como(request: APIRequestContext, rol: Rol): Promise<ApiE2E> {
    const { correo, contrasena } = credenciales(rol);
    const respuesta = await request.post(`${API}/auth/login`, {
      data: { email: correo, password: contrasena },
    });
    expect(respuesta.status(), "login por la API").toBe(200);
    const { access_token } = (await respuesta.json()) as { access_token: string };
    return new ApiE2E(request, access_token);
  }

  private async get<T>(ruta: string): Promise<T> {
    const respuesta = await this.request.get(`${API}${ruta}`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    expect(respuesta.status(), `GET ${ruta}`).toBe(200);
    return (await respuesta.json()) as T;
  }

  private async post<T>(ruta: string, data: object): Promise<T> {
    const respuesta = await this.request.post(`${API}${ruta}`, {
      headers: { Authorization: `Bearer ${this.token}` },
      data,
    });
    expect(respuesta.status(), `POST ${ruta}`).toBe(201);
    return (await respuesta.json()) as T;
  }

  /** Id del proyecto del seed y de sus ambientes visibles para este actor. */
  async tienda(): Promise<{ pid: string; ambientes: Map<string, string> }> {
    const proyectos = await this.get<{ id: string; name: string }[]>("/projects");
    const proyecto = proyectos.find((p) => p.name === PROYECTO);
    if (proyecto === undefined) throw new Error(`No se ve el proyecto ${PROYECTO}`);
    const ambientes = await this.get<{ id: string; name: string }[]>(
      `/projects/${proyecto.id}/environments`,
    );
    return { pid: proyecto.id, ambientes: new Map(ambientes.map((a) => [a.name, a.id])) };
  }

  /** POST /projects (solo el Administrador): proyecto nuevo con sus tres ambientes (RF-031). */
  async crearProyecto(nombre: string): Promise<{ pid: string; ambientes: Map<string, string> }> {
    const { id } = await this.post<{ id: string }>("/projects", { name: nombre });
    const ambientes = await this.get<{ id: string; name: string }[]>(
      `/projects/${id}/environments`,
    );
    return { pid: id, ambientes: new Map(ambientes.map((a) => [a.name, a.id])) };
  }

  async secretos(pid: string, eid: string): Promise<{ id: string; name: string }[]> {
    return this.get(`/projects/${pid}/environments/${eid}/secrets`);
  }

  async crearSecreto(pid: string, eid: string, nombre: string, valor: string): Promise<string> {
    const creado = await this.post<{ id: string }>(`/projects/${pid}/environments/${eid}/secrets`, {
      name: nombre,
      value: valor,
    });
    return creado.id;
  }

  async crearAplicacion(pid: string, eid: string, nombre: string): Promise<string> {
    const creada = await this.post<{ id: string }>(`/projects/${pid}/service-accounts`, {
      name: nombre,
      environment_id: eid,
    });
    return creada.id;
  }

  /** POST /users (solo el Administrador): alta sin roles; devuelve el id. */
  async crearUsuario(cuenta: Credenciales): Promise<string> {
    const creado = await this.post<{ id: string }>("/users", {
      email: cuenta.correo,
      password: cuenta.contrasena,
    });
    return creado.id;
  }
}
