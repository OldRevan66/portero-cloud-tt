// RF-029 y spec §6: los errores del API llegan como problem+json (RFC 9457) con `title` y `detail`
// en español. El Dashboard muestra esos dos campos y nada más: ni el mensaje técnico de Axios
// (que trae la URL) ni los datos que se enviaron en la petición (podrían ser un valor de secreto).
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { describe, expect, it } from "vitest";

import { leerProblemaDeBlob, problemaDe } from "./problem";

const VALOR = "valor-de-prueba-no-real";

function errorHttp(status: number, data: unknown): AxiosError {
  const config = {
    headers: {},
    url: "/secrets/sec-1/rotate",
    data: JSON.stringify({ new_value: VALOR }),
  } as InternalAxiosRequestConfig;
  const response = { status, statusText: "", data, headers: {}, config } as AxiosResponse;
  return new AxiosError(`HTTP ${status}`, AxiosError.ERR_BAD_REQUEST, config, null, response);
}

describe("problemaDe", () => {
  it("toma title y detail del problem+json", () => {
    const error = errorHttp(409, {
      type: "https://portero-cloud.example/errors/conflict",
      title: "Conflicto",
      status: 409,
      detail: "ya existe un secreto activo con ese nombre",
    });

    expect(problemaDe(error)).toEqual({
      titulo: "Conflicto",
      detalle: "ya existe un secreto activo con ese nombre",
      status: 409,
    });
  });

  it("sin detail usa solo el título", () => {
    expect(problemaDe(errorHttp(403, { title: "Acceso denegado", status: 403 }))).toEqual({
      titulo: "Acceso denegado",
      detalle: null,
      status: 403,
    });
  });

  it("una respuesta sin problem+json da un mensaje genérico en español con el código", () => {
    const problema = problemaDe(errorHttp(502, "<html>Bad Gateway</html>"));

    expect(problema.titulo).toBe("Error del servidor");
    expect(problema.detalle).toMatch(/502/);
    expect(problema.status).toBe(502);
  });

  it("sin respuesta (red caída) avisa que no hay conexión", () => {
    const error = new AxiosError("Network Error", AxiosError.ERR_NETWORK);

    expect(problemaDe(error)).toEqual({
      titulo: "Sin conexión",
      detalle: "No se pudo contactar al servidor. Revisa tu conexión e inténtalo de nuevo.",
      status: null,
    });
  });

  it("nunca incluye la URL ni los datos enviados en la petición", () => {
    const problema = problemaDe(errorHttp(500, "texto plano"));
    const texto = JSON.stringify(problema);

    expect(texto).not.toContain(VALOR);
    expect(texto).not.toContain("/secrets/");
  });

  it("un error que no es de Axios da un mensaje genérico", () => {
    expect(problemaDe(new Error(`falló con ${VALOR}`))).toEqual({
      titulo: "Error inesperado",
      detalle: "Ocurrió un error inesperado. Inténtalo de nuevo.",
      status: null,
    });
  });
});

// RF-021: la exportación de la bitácora pide `responseType: "blob"`, así que el cuerpo de un error
// (403, 400, 429) también llega como Blob. `leerProblemaDeBlob` lo lee y lo deja como objeto
// para que `problemaDe` muestre su `title` y `detail` en español.
describe("leerProblemaDeBlob", () => {
  it("un Blob problem+json se traduce a su title y detail", async () => {
    const cuerpo = new Blob(
      [
        JSON.stringify({
          title: "Acceso denegado",
          status: 403,
          detail: "Sin permiso audit:read.",
        }),
      ],
      { type: "application/problem+json" },
    );

    const error = await leerProblemaDeBlob(errorHttp(403, cuerpo));

    expect(problemaDe(error)).toEqual({
      titulo: "Acceso denegado",
      detalle: "Sin permiso audit:read.",
      status: 403,
    });
  });

  it("un Blob que no es JSON queda como error genérico con el código", async () => {
    const cuerpo = new Blob(["<html>Bad Gateway</html>"], { type: "text/html" });

    const problema = problemaDe(await leerProblemaDeBlob(errorHttp(502, cuerpo)));

    expect(problema.titulo).toBe("Error del servidor");
    expect(problema.status).toBe(502);
  });

  it("un error sin Blob se devuelve tal cual", async () => {
    const error = errorHttp(409, { title: "Conflicto", status: 409 });

    expect(await leerProblemaDeBlob(error)).toBe(error);
  });
});
