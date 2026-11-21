// H-62: las funciones del API de secretos codifican cada identificador como un segmento de la
// ruta. Sin esto, obtenerSecreto("<id>/value") pedía GET /secrets/<id>/value: el valor en claro
// terminaba en la caché de TanStack (spec §8.4) y quedaba un reveal_secret que nadie pidió.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import {
  actualizarSecreto,
  archivarSecreto,
  crearSecreto,
  listarSecretos,
  listarVersiones,
  obtenerSecreto,
  revelarValor,
  rotarSecreto,
} from "./secretsApi";

vi.mock("../api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const patch = vi.mocked(api.patch);
const borrar = vi.mocked(api.delete);

const MALICIOSO = "x/value";

describe("secretsApi codifica los identificadores (H-62)", () => {
  beforeEach(() => {
    get.mockReset().mockResolvedValue({ data: {} });
    post.mockReset().mockResolvedValue({ data: {} });
    patch.mockReset().mockResolvedValue({ data: {} });
    borrar.mockReset().mockResolvedValue({ data: undefined });
  });

  it("obtenerSecreto no puede convertirse en GET /secrets/{id}/value", async () => {
    await obtenerSecreto(MALICIOSO);
    expect(get).toHaveBeenCalledWith("/secrets/x%2Fvalue");
  });

  it("revelarValor, listarVersiones y archivarSecreto", async () => {
    await revelarValor(MALICIOSO);
    await listarVersiones(MALICIOSO, null);
    await archivarSecreto(MALICIOSO);
    expect(get).toHaveBeenNthCalledWith(1, "/secrets/x%2Fvalue/value");
    expect(get).toHaveBeenNthCalledWith(2, "/secrets/x%2Fvalue/versions", expect.anything());
    expect(borrar).toHaveBeenCalledWith("/secrets/x%2Fvalue");
  });

  it("listarSecretos, crearSecreto y rotarSecreto", async () => {
    await listarSecretos("p?a=1", "e/b");
    await crearSecreto("p?a=1", "e/b", { name: "A", value: "v-de-prueba", description: null });
    await rotarSecreto(MALICIOSO, "v-de-prueba");
    expect(get).toHaveBeenCalledWith("/projects/p%3Fa%3D1/environments/e%2Fb/secrets");
    expect(post).toHaveBeenNthCalledWith(
      1,
      "/projects/p%3Fa%3D1/environments/e%2Fb/secrets",
      expect.anything(),
    );
    expect(post).toHaveBeenNthCalledWith(2, "/secrets/x%2Fvalue/rotate", expect.anything());
  });

  it("actualizarSecreto (H-77: editar la descripción)", async () => {
    await actualizarSecreto(MALICIOSO, { description: "nueva" });
    expect(patch).toHaveBeenCalledWith("/secrets/x%2Fvalue", { description: "nueva" });
  });
});
