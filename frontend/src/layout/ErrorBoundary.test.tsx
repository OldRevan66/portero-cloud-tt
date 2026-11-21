// H-62: una respuesta con una forma inesperada no debe dejar la aplicación en blanco. El error de
// una pantalla se contiene en el área principal, con un mensaje en español (RF-029), y el menú
// sigue funcionando para salir de ahí.
import { MantineProvider } from "@mantine/core";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useSession } from "../auth/SessionProvider";
import { AppLayout } from "./AppLayout";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));

function PantallaRota(): never {
  throw new Error("respuesta inesperada");
}

describe("ErrorBoundary en AppLayout", () => {
  beforeEach(() => {
    vi.mocked(useSession).mockReturnValue({
      estado: "autenticado",
      usuario: { id: "u-1", email: "ana@example.com", name: "Ana", assignments: [] },
      menu: [{ label: "Proyectos", path: "/proyectos" }],
      cerrarSesion: vi.fn(),
    });
    // React informa en la consola el error capturado; aquí solo se silencia ese aviso esperado.
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  it("muestra un mensaje en español y se recupera al cambiar de pantalla", async () => {
    const usuario = userEvent.setup();
    render(
      <MantineProvider>
        <MemoryRouter initialEntries={["/bitacora"]}>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/bitacora" element={<PantallaRota />} />
              <Route path="/proyectos" element={<p>Lista de proyectos</p>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </MantineProvider>,
    );

    expect(await screen.findByText("No se pudo mostrar esta pantalla")).toBeInTheDocument();
    expect(screen.queryByText(/respuesta inesperada/)).not.toBeInTheDocument();

    await usuario.click(screen.getByRole("link", { name: "Proyectos" }));
    expect(await screen.findByText("Lista de proyectos")).toBeInTheDocument();
    expect(screen.queryByText("No se pudo mostrar esta pantalla")).not.toBeInTheDocument();
  });
});
