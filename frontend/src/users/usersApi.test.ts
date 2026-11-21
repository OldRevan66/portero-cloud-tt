// Capa API de usuarios, asignaciones de rol, desbloqueo y restablecimiento (CU-05; spec §2 y §4.4;
// H-73, H-78).
//
// H-62 (OWASP ASVS 4.0.3 V5.1.3 y V5.3): cada identificador va como UN segmento de la ruta con
// `ruta` (api/ruta.ts) y, además, `uid` y `aid` deben ser UUID: lo que no lo sea se rechaza sin
// llamar al API. Así "../me/password" nunca convierte una consulta en otra ruta de /users.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import { ruta } from "../api/ruta";
import {
  actualizarUsuario,
  asignarRol,
  crearUsuario,
  desactivarUsuario,
  desbloquearUsuario,
  listarAsignaciones,
  listarUsuarios,
  obtenerUsuario,
  quitarAsignacion,
  restablecerContrasena,
  type AssignmentCreate,
} from "./usersApi";

vi.mock("../api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

// Espía sobre la función real: la ruta sigue codificándose igual, y se puede comprobar que se usó.
vi.mock("../api/ruta", async (importOriginal) => {
  const real = await importOriginal<typeof import("../api/ruta")>();
  return { ruta: vi.fn(real.ruta) };
});

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const patch = vi.mocked(api.patch);
const borrar = vi.mocked(api.delete);
const espiaRuta = vi.mocked(ruta);

const UID = "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f";
const AID = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
const PID = "fc7d3e0a-6e92-4b6b-bd8a-0123456789ab";
const DATOS = { marca: "respuesta" };

const NO_UUID = ["a/b", "..", "", "../me/password", `${UID}/role-assignments`];

describe("usersApi llama a la ruta correcta", () => {
  beforeEach(() => {
    for (const metodo of [get, post, patch, borrar]) {
      metodo.mockReset().mockResolvedValue({ data: DATOS });
    }
    espiaRuta.mockClear();
  });

  it("listarUsuarios: GET /users", async () => {
    expect(await listarUsuarios()).toBe(DATOS);
    expect(get).toHaveBeenCalledWith("/users");
  });

  it("crearUsuario: POST /users con el cuerpo tal cual", async () => {
    const cuerpo = { email: "nuevo@example.com", name: "Nuevo", password: "marcador-no-real" };

    expect(await crearUsuario(cuerpo)).toBe(DATOS);
    expect(post).toHaveBeenCalledWith("/users", cuerpo);
  });

  it("obtenerUsuario: GET /users/{uid}", async () => {
    expect(await obtenerUsuario(UID)).toBe(DATOS);
    expect(get).toHaveBeenCalledWith(`/users/${UID}`);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("actualizarUsuario: PATCH /users/{uid}", async () => {
    expect(await actualizarUsuario(UID, { is_active: true })).toBe(DATOS);
    expect(patch).toHaveBeenCalledWith(`/users/${UID}`, { is_active: true });
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("desactivarUsuario: DELETE /users/{uid}", async () => {
    await desactivarUsuario(UID);
    expect(borrar).toHaveBeenCalledWith(`/users/${UID}`);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("listarAsignaciones: GET /users/{uid}/role-assignments (H-73)", async () => {
    expect(await listarAsignaciones(UID)).toBe(DATOS);
    expect(get).toHaveBeenCalledWith(`/users/${UID}/role-assignments`);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("asignarRol: POST /users/{uid}/role-assignments", async () => {
    const cuerpo: AssignmentCreate = { role_id: 2, project_id: PID, environment_id: null };

    expect(await asignarRol(UID, cuerpo)).toBe(DATOS);
    expect(post).toHaveBeenCalledWith(`/users/${UID}/role-assignments`, cuerpo);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("quitarAsignacion: DELETE /users/{uid}/role-assignments/{aid}", async () => {
    await quitarAsignacion(UID, AID);
    expect(borrar).toHaveBeenCalledWith(`/users/${UID}/role-assignments/${AID}`);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("desbloquearUsuario: POST /users/{uid}/unlock sin cuerpo (H-78)", async () => {
    await desbloquearUsuario(UID);
    expect(post).toHaveBeenCalledWith(`/users/${UID}/unlock`);
    expect(espiaRuta).toHaveBeenCalled();
  });

  it("restablecerContrasena: POST /users/{uid}/password-reset con new_password (H-78)", async () => {
    await restablecerContrasena(UID, "marcador-no-real");
    expect(post).toHaveBeenCalledWith(`/users/${UID}/password-reset`, {
      new_password: "marcador-no-real",
    });
    expect(espiaRuta).toHaveBeenCalled();
  });
});

describe("usersApi rechaza identificadores que no son UUID sin llamar al API (H-62)", () => {
  beforeEach(() => {
    for (const metodo of [get, post, patch, borrar]) {
      metodo.mockReset().mockResolvedValue({ data: DATOS });
    }
  });

  function sinLlamadas(): void {
    for (const metodo of [get, post, patch, borrar]) {
      expect(metodo).not.toHaveBeenCalled();
    }
  }

  it.each(NO_UUID)("uid %j", async (uid) => {
    await expect(obtenerUsuario(uid)).rejects.toThrow();
    await expect(actualizarUsuario(uid, { name: "otro" })).rejects.toThrow();
    await expect(desactivarUsuario(uid)).rejects.toThrow();
    await expect(listarAsignaciones(uid)).rejects.toThrow();
    await expect(
      asignarRol(uid, { role_id: 3, project_id: PID, environment_id: null }),
    ).rejects.toThrow();
    await expect(quitarAsignacion(uid, AID)).rejects.toThrow();
    await expect(desbloquearUsuario(uid)).rejects.toThrow();
    await expect(restablecerContrasena(uid, "marcador-no-real")).rejects.toThrow();
    sinLlamadas();
  });

  it.each(NO_UUID)("aid %j", async (aid) => {
    await expect(quitarAsignacion(UID, aid)).rejects.toThrow();
    sinLlamadas();
  });

  it("acepta un UUID en mayúsculas (forma canónica, sin distinguir mayúsculas)", async () => {
    await obtenerUsuario(UID.toUpperCase());
    expect(get).toHaveBeenCalledWith(`/users/${UID.toUpperCase()}`);
  });
});
