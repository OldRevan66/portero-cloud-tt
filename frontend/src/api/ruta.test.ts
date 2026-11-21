// H-62 (path traversal del lado del cliente; OWASP ASVS 4.0.3 V5.3): cada dato que se inserta
// en la ruta de una petición se codifica como UN segmento. Un "/" o un "?" dentro de un
// identificador no puede cambiar a qué endpoint va la petición.
import { describe, expect, it } from "vitest";

import { ruta } from "./ruta";

const UUID = "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f";

describe("ruta", () => {
  it("deja igual un identificador normal", () => {
    expect(ruta`/secrets/${UUID}/value`).toBe(`/secrets/${UUID}/value`);
  });

  it("codifica la diagonal: no se puede llegar a otro endpoint", () => {
    expect(ruta`/secrets/${`${UUID}/value`}`).toBe(`/secrets/${UUID}%2Fvalue`);
  });

  it("codifica ? y #: no se pueden inyectar parámetros de consulta", () => {
    expect(ruta`/projects/${"x?verb=login#y"}`).toBe("/projects/x%3Fverb%3Dlogin%23y");
  });

  it("codifica varios valores en la misma ruta", () => {
    expect(ruta`/projects/${"a/b"}/environments/${"c"}/secrets`).toBe(
      "/projects/a%2Fb/environments/c/secrets",
    );
  });

  // "." y ".." son segmentos especiales incluso codificados (%2E%2E): el navegador los resuelve
  // y la petición subiría de nivel. Tampoco se acepta un segmento vacío ("//").
  it.each(["", ".", ".."])("rechaza el segmento %j", (valor) => {
    expect(() => ruta`/secrets/${valor}/value`).toThrow(/identificador inválido/i);
  });
});
