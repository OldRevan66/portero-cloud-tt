// "Cambiar contraseña" para cualquier usuario (spec §3.6, §8.3, §8.4; H-37, H-74).
//
// - Modal con contraseña actual, nueva y confirmación (PasswordInput) y el texto de la política
//   (12 a 128 caracteres y no una contraseña común; `auth/passwords.py`). La decide el backend.
// - Si la nueva y la confirmación no coinciden, el error es local: no se llama al API.
// - 401 (contraseña actual incorrecta) → mensaje fijo, sin el `detail` del servidor (como el
//   login, OWASP ASVS V2.2). 422 (política) → title/detail del problem+json (RF-029).
// - 204: el backend revocó todos los tokens (H-37) y borró la cookie. Se vacía la caché de
//   TanStack y se va a /login con un aviso fijo. (`cambiarContrasena` borra el token en memoria;
//   eso se prueba en api/client.test.ts.)
// - La llamada es directa, nunca useMutation (spec §8.4): las contraseñas no quedan en la caché
//   de TanStack, ni en console, ni en la URL.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

import { cambiarContrasena } from "../api/client";
import { LoginPage } from "../pages/LoginPage";
import { CambiarContrasena } from "./CambiarContrasena";

vi.mock("../api/client", () => ({ cambiarContrasena: vi.fn(), login: vi.fn() }));

const cambiarSimulado = vi.mocked(cambiarContrasena);

const ACTUAL = "actual-de-prueba-no-real";
const NUEVA = "nueva-de-prueba-no-real";
const AVISO = "Contraseña cambiada. Inicia sesión con tu nueva contraseña.";

function problema(status: number, title: string, detail: string): AxiosError {
  const config = { headers: {} } as InternalAxiosRequestConfig;
  const response = {
    status,
    statusText: "",
    data: { type: "about:blank", title, status, detail },
    headers: { "content-type": "application/problem+json" },
    config,
  } as AxiosResponse;
  return new AxiosError(`HTTP ${status}`, AxiosError.ERR_BAD_REQUEST, config, null, response);
}

/** Muestra la URL actual para comprobar que ninguna contraseña llega a ella. */
function Ubicacion() {
  const { pathname, search, hash } = useLocation();
  return <output data-testid="ubicacion">{`${pathname}${search}${hash}`}</output>;
}

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // Un metadato cualquiera en la caché, para comprobar que se vacía al terminar.
  queryClient.setQueryData(["auth", "me"], { id: "u", email: "yo@tienda.example" });
  const vaciar = vi.spyOn(queryClient, "clear");
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/proyectos"]}>
          <Routes>
            <Route path="/proyectos" element={<CambiarContrasena />} />
            <Route path="/login" element={<LoginPage />} />
          </Routes>
          <Ubicacion />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return { queryClient, vaciar };
}

async function abrirModal() {
  const usuario = userEvent.setup();
  await usuario.click(screen.getByRole("button", { name: "Cambiar contraseña" }));
  const modal = await screen.findByRole("dialog", { name: "Cambiar contraseña" });
  return { usuario, modal };
}

function campos(modal: HTMLElement) {
  return {
    actual: within(modal).getByLabelText(/^contraseña actual/i),
    nueva: within(modal).getByLabelText(/^nueva contraseña/i),
    confirmacion: within(modal).getByLabelText(/^confirma la nueva contraseña/i),
  };
}

async function llenarYEnviar(actual: string, nueva: string, confirmacion: string) {
  const { usuario, modal } = await abrirModal();
  const c = campos(modal);
  if (actual !== "") await usuario.type(c.actual, actual);
  if (nueva !== "") await usuario.type(c.nueva, nueva);
  if (confirmacion !== "") await usuario.type(c.confirmacion, confirmacion);
  await usuario.click(within(modal).getByRole("button", { name: "Cambiar contraseña" }));
  return { usuario, modal };
}

let espiasConsola: MockInstance[];

beforeEach(() => {
  cambiarSimulado.mockReset();
  espiasConsola = (["log", "info", "warn", "error", "debug"] as const).map((metodo) =>
    vi.spyOn(console, metodo),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Ninguna llamada a console llevó alguna de las contraseñas. */
function consolaSinContrasenas() {
  for (const espia of espiasConsola) {
    const texto = JSON.stringify(espia.mock.calls.map((args) => args.map(String)));
    expect(texto).not.toContain(ACTUAL);
    expect(texto).not.toContain(NUEVA);
  }
}

/** Ni la caché de consultas ni la de mutaciones conservan las contraseñas (spec §8.4). */
function cacheSinContrasenas(queryClient: QueryClient) {
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const consultas = JSON.stringify(
    queryClient
      .getQueryCache()
      .getAll()
      .map((q) => [q.queryKey, q.state.data]),
  );
  expect(consultas).not.toContain(ACTUAL);
  expect(consultas).not.toContain(NUEVA);
}

describe("CambiarContrasena: el modal", () => {
  it("abre un modal con tres campos type=password y el texto de la política", async () => {
    renderizar();
    const { modal } = await abrirModal();
    const c = campos(modal);

    expect(c.actual).toHaveAttribute("type", "password");
    expect(c.nueva).toHaveAttribute("type", "password");
    expect(c.confirmacion).toHaveAttribute("type", "password");
    expect(c.actual).toHaveAttribute("autocomplete", "current-password");
    expect(c.nueva).toHaveAttribute("autocomplete", "new-password");
    expect(c.confirmacion).toHaveAttribute("autocomplete", "new-password");
    expect(within(modal).getByText(/de 12 a 128 caracteres/i)).toBeInTheDocument();
  });

  it("al cerrarlo y reabrirlo, lo tecleado se descarta", async () => {
    renderizar();
    const { usuario, modal } = await abrirModal();
    await usuario.type(campos(modal).actual, ACTUAL);

    await usuario.click(within(modal).getByRole("button", { name: "Cerrar" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const { modal: otraVez } = await abrirModal();

    expect(campos(otraVez).actual).toHaveValue("");
  });
});

describe("CambiarContrasena: validación local (sin llamar al API)", () => {
  it("si la nueva y la confirmación no coinciden, muestra el error y no llama al API", async () => {
    renderizar();
    const { modal } = await llenarYEnviar(ACTUAL, NUEVA, `${NUEVA}-otra`);

    expect(
      await within(modal).findByText("Las contraseñas nuevas no coinciden."),
    ).toBeInTheDocument();
    expect(cambiarSimulado).not.toHaveBeenCalled();
  });

  it("los tres campos son obligatorios", async () => {
    renderizar();
    const { modal } = await llenarYEnviar("", "", "");

    expect(
      await within(modal).findByText("La contraseña actual es obligatoria."),
    ).toBeInTheDocument();
    expect(within(modal).getByText("La contraseña nueva es obligatoria.")).toBeInTheDocument();
    expect(cambiarSimulado).not.toHaveBeenCalled();
  });
});

describe("CambiarContrasena: errores del API", () => {
  it("401 (contraseña actual incorrecta): mensaje fijo en español, sin el detail del servidor", async () => {
    cambiarSimulado.mockRejectedValueOnce(
      problema(401, "No autenticado", "credenciales inválidas"),
    );
    const { queryClient, vaciar } = renderizar();
    const { modal } = await llenarYEnviar(ACTUAL, NUEVA, NUEVA);

    const alerta = await within(modal).findByRole("alert");
    expect(alerta).toHaveTextContent("La contraseña actual no es correcta.");
    expect(alerta).not.toHaveTextContent("credenciales inválidas");
    expect(screen.getByTestId("ubicacion")).toHaveTextContent(/^\/proyectos$/);
    expect(vaciar).not.toHaveBeenCalled();
    cacheSinContrasenas(queryClient);
    consolaSinContrasenas();
  });

  it("422 (política): muestra el title y el detail del problem+json", async () => {
    cambiarSimulado.mockRejectedValueOnce(
      problema(422, "Entrada no procesable", "la contraseña debe tener al menos 12 caracteres"),
    );
    const { queryClient, vaciar } = renderizar();
    const { modal } = await llenarYEnviar(ACTUAL, NUEVA, NUEVA);

    const alerta = await within(modal).findByRole("alert");
    expect(alerta).toHaveTextContent("Entrada no procesable");
    expect(alerta).toHaveTextContent("la contraseña debe tener al menos 12 caracteres");
    expect(vaciar).not.toHaveBeenCalled();
    cacheSinContrasenas(queryClient);
    consolaSinContrasenas();
  });

  it("429: pide esperar, en español", async () => {
    cambiarSimulado.mockRejectedValueOnce(
      problema(429, "Demasiadas solicitudes", "Intenta más tarde."),
    );
    renderizar();
    const { modal } = await llenarYEnviar(ACTUAL, NUEVA, NUEVA);

    expect(await within(modal).findByRole("alert")).toHaveTextContent(
      "Demasiados intentos. Espera un momento e inténtalo de nuevo.",
    );
  });
});

describe("CambiarContrasena: éxito (204)", () => {
  it("llama directo a cambiarContrasena con el cuerpo de la spec §3.6", async () => {
    cambiarSimulado.mockResolvedValueOnce(undefined);
    renderizar();
    await llenarYEnviar(ACTUAL, NUEVA, NUEVA);

    await waitFor(() => expect(cambiarSimulado).toHaveBeenCalledTimes(1));
    expect(cambiarSimulado).toHaveBeenCalledWith({
      current_password: ACTUAL,
      new_password: NUEVA,
    });
  });

  it("vacía la caché de TanStack y lleva a /login con el aviso", async () => {
    cambiarSimulado.mockResolvedValueOnce(undefined);
    const { queryClient, vaciar } = renderizar();
    await llenarYEnviar(ACTUAL, NUEVA, NUEVA);

    expect(await screen.findByText(AVISO)).toBeInTheDocument();
    expect(screen.getByTestId("ubicacion")).toHaveTextContent(/^\/login$/);
    expect(vaciar).toHaveBeenCalled();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(screen.queryByRole("dialog", { name: "Cambiar contraseña" })).not.toBeInTheDocument();
  });

  it("ninguna contraseña queda en la URL, la caché ni console", async () => {
    cambiarSimulado.mockResolvedValueOnce(undefined);
    const { queryClient } = renderizar();
    await llenarYEnviar(ACTUAL, NUEVA, NUEVA);
    await screen.findByText(AVISO);

    const url = screen.getByTestId("ubicacion").textContent ?? "";
    expect(url).not.toContain(ACTUAL);
    expect(url).not.toContain(NUEVA);
    cacheSinContrasenas(queryClient);
    consolaSinContrasenas();
  });
});
