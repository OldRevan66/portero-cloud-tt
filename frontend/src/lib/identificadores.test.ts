// H-62 (OWASP ASVS 4.0.3 V5.1.3, lista permitida): los identificadores de proyectos, ambientes y
// secretos son UUID. Lo que llega en la URL del Dashboard y no tiene esa forma no se envía al API.
import { describe, expect, it } from "vitest";

import { esUuid } from "./identificadores";

describe("esUuid", () => {
  it.each(["0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f", "0B9C6A3E-5F1D-4C2A-9E7B-1A2B3C4D5E6F"])(
    "acepta %s",
    (valor) => {
      expect(esUuid(valor)).toBe(true);
    },
  );

  it.each([
    "",
    "p-1",
    "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f/value",
    "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f?x=1",
    "../0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f",
    " 0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f",
    "0b9c6a3e5f1d4c2a9e7b1a2b3c4d5e6f",
  ])("rechaza %j", (valor) => {
    expect(esUuid(valor)).toBe(false);
  });
});
