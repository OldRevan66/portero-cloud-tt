// Spec §8.3 (H-36): ciclo de vida de la sesión en el Dashboard.
// - Al cargar la aplicación se intenta POST /auth/refresh: si responde, hay sesión (se carga
//   /auth/me); si no, la ruta protegida manda a /login.
// - Cerrar sesión llama a /auth/logout, borra el token en memoria y vacía la caché de TanStack.
// - Si el token se borra por otra vía (el interceptor no pudo renovar), se vuelve a /login.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AxiosResponse } from "axios";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, logout, refreshSession } from "../api/client";
import type { Me } from "./permissions";
import { ProtectedRoute } from "./ProtectedRoute";
import { SessionProvider, useSession } from "./SessionProvider";
import { clear, getAccessToken, setAccessToken } from "./tokenStore";

vi.mock("../api/client", () => ({
  api: { get: vi.fn() },
  configureSession: vi.fn(),
  logout: vi.fn(),
  refreshSession: vi.fn(),
}));

const refreshSimulado = vi.mocked(refreshSession);
const logoutSimulado = vi.mocked(logout);
const getSimulado = vi.mocked(api.get);

const ANA: Me = {
  id: "u-1",
  email: "ana@example.com",
  name: "Ana",
  assignments: [
    { id: "a-1", role_id: 3, role: "Desarrollador", project_id: "p-1", environment_id: null },
  ],
};

function Contenido() {
  const sesion = useSession();
  return (
    <>
      <p>Hola, {sesion.usuario?.name}</p>
      <p>Menú: {sesion.menu.map((m) => m.label).join(", ")}</p>
      <button type="button" onClick={() => void sesion.cerrarSesion()}>
        Salir
      </button>
    </>
  );
}

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <SessionProvider>
            <Routes>
              <Route path="/login" element={<p>Pantalla de inicio de sesión</p>} />
              <Route element={<ProtectedRoute />}>
                <Route path="/" element={<Contenido />} />
              </Route>
            </Routes>
          </SessionProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

function refreshExitoso() {
  refreshSimulado.mockImplementation(async () => {
    setAccessToken("token-recuperado");
    return "token-recuperado";
  });
  getSimulado.mockResolvedValue({ data: ANA } as AxiosResponse);
}

beforeEach(() => {
  clear();
  refreshSimulado.mockReset();
  logoutSimulado.mockReset();
  getSimulado.mockReset();
});

afterEach(() => {
  clear();
});

describe("SessionProvider y ProtectedRoute", () => {
  it("al cargar recupera la sesión con /auth/refresh y carga /auth/me", async () => {
    refreshExitoso();
    renderizar();

    expect(await screen.findByText("Hola, Ana")).toBeInTheDocument();
    expect(screen.getByText("Menú: Proyectos")).toBeInTheDocument();
    expect(refreshSimulado).toHaveBeenCalled();
    expect(getSimulado).toHaveBeenCalledWith("/auth/me");
  });

  it("mientras se intenta el refresh no muestra ni el contenido ni el login", () => {
    refreshSimulado.mockReturnValue(new Promise<string>(() => {}));
    renderizar();

    expect(screen.queryByText(/Hola/)).not.toBeInTheDocument();
    expect(screen.queryByText("Pantalla de inicio de sesión")).not.toBeInTheDocument();
  });

  it("si el refresh falla, la ruta protegida manda a /login sin pedir /auth/me", async () => {
    refreshSimulado.mockRejectedValue(new Error("401"));
    renderizar();

    expect(await screen.findByText("Pantalla de inicio de sesión")).toBeInTheDocument();
    expect(getSimulado).not.toHaveBeenCalled();
  });

  it("cerrar sesión llama a logout, borra el token, vacía la caché y vuelve a /login", async () => {
    refreshExitoso();
    logoutSimulado.mockImplementation(async () => {
      clear();
    });
    const queryClient = renderizar();
    await screen.findByText("Hola, Ana");

    await userEvent.setup().click(screen.getByRole("button", { name: "Salir" }));

    expect(await screen.findByText("Pantalla de inicio de sesión")).toBeInTheDocument();
    expect(logoutSimulado).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBeNull();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });

  it("si el token se borra por expiración, vuelve a /login", async () => {
    refreshExitoso();
    renderizar();
    await screen.findByText("Hola, Ana");

    act(() => {
      clear();
    });

    expect(await screen.findByText("Pantalla de inicio de sesión")).toBeInTheDocument();
  });
});
