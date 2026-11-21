// H-62: las funciones del API de proyectos y Aplicaciones Cliente codifican cada identificador
// como un segmento de la ruta (OWASP ASVS 4.0.3 V5.3).
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import {
  crearAplicacion,
  listarAplicaciones,
  revocarAplicacion,
} from "../serviceAccounts/serviceAccountsApi";
import {
  actualizarAmbiente,
  actualizarProyecto,
  archivarProyecto,
  crearAmbiente,
  eliminarAmbiente,
  listarAmbientes,
  obtenerProyecto,
} from "./projectsApi";

vi.mock("../api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const patch = vi.mocked(api.patch);
const borrar = vi.mocked(api.delete);

describe("projectsApi y serviceAccountsApi codifican los identificadores (H-62)", () => {
  beforeEach(() => {
    for (const metodo of [get, post, patch, borrar]) {
      metodo.mockReset().mockResolvedValue({ data: {} });
    }
  });

  it("proyectos y ambientes", async () => {
    await obtenerProyecto("a/b");
    await listarAmbientes("a/b");
    await actualizarProyecto("a/b", {});
    await crearAmbiente("a/b", { name: "qa", description: null });
    await actualizarAmbiente("a/b", "c?d", {});
    expect(get).toHaveBeenNthCalledWith(1, "/projects/a%2Fb");
    expect(get).toHaveBeenNthCalledWith(2, "/projects/a%2Fb/environments");
    expect(patch).toHaveBeenNthCalledWith(1, "/projects/a%2Fb", {});
    expect(post).toHaveBeenCalledWith("/projects/a%2Fb/environments", expect.anything());
    expect(patch).toHaveBeenNthCalledWith(2, "/projects/a%2Fb/environments/c%3Fd", {});
  });

  it("archivar proyecto y eliminar ambiente (H-77)", async () => {
    await archivarProyecto("a/b", false);
    await archivarProyecto("a/b", true);
    await eliminarAmbiente("a/b", "c?d");
    // Sin confirmar no se manda ?confirm: el backend responde 409 si hay secretos activos.
    expect(borrar).toHaveBeenNthCalledWith(1, "/projects/a%2Fb");
    expect(borrar).toHaveBeenNthCalledWith(2, "/projects/a%2Fb", { params: { confirm: true } });
    expect(borrar).toHaveBeenNthCalledWith(3, "/projects/a%2Fb/environments/c%3Fd");
  });

  it("Aplicaciones Cliente", async () => {
    await listarAplicaciones("a/b");
    await crearAplicacion("a/b", { name: "app", environment_id: null, expires_at: null });
    await revocarAplicacion("../users");
    expect(get).toHaveBeenCalledWith("/projects/a%2Fb/service-accounts");
    expect(post).toHaveBeenCalledWith("/projects/a%2Fb/service-accounts", expect.anything());
    expect(borrar).toHaveBeenCalledWith("/service-accounts/..%2Fusers");
  });
});
