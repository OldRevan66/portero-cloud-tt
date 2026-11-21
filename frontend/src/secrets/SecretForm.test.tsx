// CU-02 (crear secreto) desde el Dashboard.
// - Valida antes de enviar lo mismo que el backend (backend/src/portero/api/v1/secrets.py,
//   SecretCreate): nombre en SCREAMING_SNAKE_CASE (`^[A-Z][A-Z0-9_]*$`, 1 a 255 caracteres) y
//   valor obligatorio. La autoridad sigue siendo el backend; esto solo ahorra un viaje.
// - RF-029: un error del API se muestra con el detalle del problem+json (p. ej. 409 conflict).
// - Spec §8.4: el campo del valor es type="password" con botón para mostrarlo; el formulario se
//   limpia tras enviarse y el envío es una llamada directa (no useMutation: su caché guardaría
//   el valor en `variables`).
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SecretForm } from "./SecretForm";
import { crearSecreto } from "./secretsApi";

vi.mock("./secretsApi", () => ({ crearSecreto: vi.fn() }));

const crearSimulado = vi.mocked(crearSecreto);

const PROYECTO = "p-1";
const AMBIENTE = "e-1";
const VALOR = "valor-de-prueba-no-real";
const FECHA = "2026-10-11T10:00:00Z";

function error409(): AxiosError {
  const config = { headers: {} } as InternalAxiosRequestConfig;
  const response = {
    status: 409,
    statusText: "Conflict",
    data: {
      type: "about:blank",
      title: "Conflicto",
      status: 409,
      detail: "ya existe un secreto activo con ese nombre",
    },
    headers: { "content-type": "application/problem+json" },
    config,
  } as AxiosResponse;
  return new AxiosError("HTTP 409", AxiosError.ERR_BAD_REQUEST, config, null, response);
}

function renderizar(onCreado = vi.fn()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <SecretForm projectId={PROYECTO} environmentId={AMBIENTE} onCreado={onCreado} />
      </QueryClientProvider>
    </MantineProvider>,
  );
  return { queryClient, onCreado };
}

function campoNombre(): HTMLInputElement {
  return screen.getByLabelText(/^nombre/i);
}

function campoValor(): HTMLInputElement {
  return screen.getByLabelText(/^valor/i);
}

async function llenarYEnviar(
  usuario: ReturnType<typeof userEvent.setup>,
  nombre: string,
  valor: string,
) {
  if (nombre !== "") {
    await usuario.click(campoNombre());
    await usuario.paste(nombre);
  }
  if (valor !== "") {
    await usuario.click(campoValor());
    await usuario.paste(valor);
  }
  await usuario.click(screen.getByRole("button", { name: /crear secreto/i }));
}

describe("SecretForm", () => {
  beforeEach(() => {
    crearSimulado.mockReset();
  });

  it.each(["mi_secreto", "1CLAVE", "DATABASE-URL", "_CLAVE"])(
    "rechaza el nombre %s (no es SCREAMING_SNAKE_CASE) sin enviar",
    async (nombre) => {
      const usuario = userEvent.setup();
      renderizar();

      await llenarYEnviar(usuario, nombre, VALOR);

      expect(await screen.findByText(/mayúsculas/i)).toBeInTheDocument();
      expect(crearSimulado).not.toHaveBeenCalled();
    },
  );

  it("rechaza un nombre de más de 255 caracteres sin enviar", async () => {
    const usuario = userEvent.setup();
    renderizar();

    await llenarYEnviar(usuario, "A".repeat(256), VALOR);

    expect(await screen.findByText(/255 caracteres/i)).toBeInTheDocument();
    expect(crearSimulado).not.toHaveBeenCalled();
  });

  it("exige el nombre y el valor", async () => {
    const usuario = userEvent.setup();
    renderizar();

    await llenarYEnviar(usuario, "", "");

    expect(await screen.findByText(/el nombre es obligatorio/i)).toBeInTheDocument();
    expect(screen.getByText(/el valor es obligatorio/i)).toBeInTheDocument();
    expect(crearSimulado).not.toHaveBeenCalled();
  });

  it("muestra el 409 del API: ya existe un secreto con ese nombre", async () => {
    crearSimulado.mockRejectedValueOnce(error409());
    const usuario = userEvent.setup();
    const { onCreado } = renderizar();

    await llenarYEnviar(usuario, "DATABASE_URL", VALOR);

    const alerta = await screen.findByRole("alert");
    expect(alerta).toHaveTextContent(/ya existe un secreto activo con ese nombre/i);
    expect(alerta).not.toHaveTextContent(VALOR);
    expect(onCreado).not.toHaveBeenCalled();
  });

  it("el campo del valor es type=password y el botón 'Mostrar valor' lo descubre", async () => {
    const usuario = userEvent.setup();
    renderizar();

    expect(campoValor()).toHaveAttribute("type", "password");

    await usuario.click(screen.getByRole("button", { name: /mostrar valor/i }));

    expect(campoValor()).toHaveAttribute("type", "text");
  });

  it("un envío válido llama al API directamente, avisa y limpia el formulario", async () => {
    crearSimulado.mockResolvedValueOnce({
      id: "sec-1",
      name: "DATABASE_URL",
      description: null,
      version: 1,
      project_id: PROYECTO,
      environment_id: AMBIENTE,
      created_at: FECHA,
      created_by: "u-1",
      updated_at: FECHA,
    });
    const usuario = userEvent.setup();
    const { queryClient, onCreado } = renderizar();

    await llenarYEnviar(usuario, "DATABASE_URL", VALOR);

    await vi.waitFor(() => {
      expect(onCreado).toHaveBeenCalledTimes(1);
    });
    expect(crearSimulado).toHaveBeenCalledWith(PROYECTO, AMBIENTE, {
      name: "DATABASE_URL",
      value: VALOR,
      description: null,
    });
    expect(campoNombre()).toHaveValue("");
    expect(campoValor()).toHaveValue("");
    expect(queryClient.getMutationCache().getAll()).toEqual([]);
  });
});
