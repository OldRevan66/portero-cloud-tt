// Encabezado de AppLayout: "Cambiar contraseña" junto a "Cerrar sesión" para cualquier usuario
// (spec §3.6: POST /users/me/password solo pide ser humano, no un permiso de la matriz).
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Assignment, Me, MenuEntry } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { AppLayout } from "./AppLayout";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../api/client", () => ({ cambiarContrasena: vi.fn() }));

const sesionSimulada = vi.mocked(useSession);

const PID = "fc7d3e0a-6e92-4b6b-bd8a-0123456789ab";

const ADMINISTRADOR: Assignment[] = [
  { id: "a-1", role_id: 1, role: "Administrador", project_id: null, environment_id: null },
];
const DESARROLLADOR: Assignment[] = [
  { id: "a-3", role_id: 3, role: "Desarrollador", project_id: PID, environment_id: null },
];

function conSesion(assignments: Assignment[], menu: MenuEntry[]) {
  const me: Me = { id: "u", email: "yo@tienda.example", name: "Yo", assignments };
  sesionSimulada.mockReturnValue({
    estado: "autenticado",
    usuario: me,
    menu,
    cerrarSesion: vi.fn(),
  });
}

function renderizar() {
  render(
    <MantineProvider>
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={["/proyectos"]}>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/proyectos" element={<p>Contenido</p>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("AppLayout: encabezado", () => {
  beforeEach(() => {
    sesionSimulada.mockReset();
  });

  it.each([
    ["Administrador", ADMINISTRADOR, [{ path: "/usuarios", label: "Usuarios" }]],
    ["Desarrollador", DESARROLLADOR, [{ path: "/proyectos", label: "Proyectos" }]],
    ["sin roles", [], []],
  ] as const)("%s ve «Cambiar contraseña» junto a «Cerrar sesión»", (_rol, assignments, menu) => {
    conSesion([...assignments], [...menu]);
    renderizar();

    const encabezado = screen.getByRole("banner");
    expect(
      within(encabezado).getByRole("button", { name: "Cambiar contraseña" }),
    ).toBeInTheDocument();
    expect(within(encabezado).getByRole("button", { name: "Cerrar sesión" })).toBeInTheDocument();
  });

  it("«Cambiar contraseña» abre el modal", async () => {
    conSesion(DESARROLLADOR, []);
    renderizar();

    await userEvent
      .setup()
      .click(
        within(screen.getByRole("banner")).getByRole("button", { name: "Cambiar contraseña" }),
      );

    expect(await screen.findByRole("dialog", { name: "Cambiar contraseña" })).toBeInTheDocument();
  });
});
