// RF-027: navegación jerárquica proyecto → ambiente → secretos.
// Spec §4.2 (H-23c, H-23d): GET /projects y GET /projects/{pid}/environments ya vienen filtrados
// por el backend según las asignaciones del usuario. El árbol muestra exactamente lo que responde
// el API: no agrega proyectos ni ambientes por su cuenta (la autoridad es el backend).
// Son metadatos, así que aquí sí se usa useQuery (spec §8.4).
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useParams } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import { ProjectTree } from "./ProjectTree";
import { listarAmbientes, listarProyectos } from "./projectsApi";

vi.mock("./projectsApi", () => ({ listarProyectos: vi.fn(), listarAmbientes: vi.fn() }));

type ProjectOut = components["schemas"]["ProjectOut"];
type EnvironmentOut = components["schemas"]["EnvironmentOut"];

const proyectosSimulados = vi.mocked(listarProyectos);
const ambientesSimulados = vi.mocked(listarAmbientes);

const FECHA = "2026-10-11T10:00:00Z";

function proyecto(id: string, name: string): ProjectOut {
  return { id, name, description: null, created_at: FECHA, updated_at: FECHA };
}

function ambiente(id: string, project_id: string, name: string): EnvironmentOut {
  return { id, project_id, name, description: null, created_at: FECHA };
}

function PantallaSecretos() {
  const { pid, eid } = useParams();
  return (
    <p>
      Secretos de {pid}/{eid}
    </p>
  );
}

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/proyectos"]}>
          <Routes>
            <Route path="/proyectos" element={<ProjectTree />} />
            <Route path="/proyectos/:pid/ambientes/:eid" element={<PantallaSecretos />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("ProjectTree", () => {
  beforeEach(() => {
    proyectosSimulados.mockReset();
    ambientesSimulados.mockReset();
  });

  it("muestra exactamente los proyectos visibles que devuelve el API", async () => {
    proyectosSimulados.mockResolvedValue([
      proyecto("p-1", "tienda-en-linea"),
      proyecto("p-2", "facturacion"),
    ]);
    renderizar();

    expect(await screen.findByText("tienda-en-linea")).toBeInTheDocument();
    expect(screen.getByText("facturacion")).toBeInTheDocument();
    expect(proyectosSimulados).toHaveBeenCalledTimes(1);
    // Hasta abrir un proyecto no se piden sus ambientes.
    expect(ambientesSimulados).not.toHaveBeenCalled();
  });

  it("sin proyectos visibles lo dice en español", async () => {
    proyectosSimulados.mockResolvedValue([]);
    renderizar();

    expect(await screen.findByText(/no tienes proyectos/i)).toBeInTheDocument();
  });

  it("al abrir un proyecto muestra solo los ambientes que devuelve el API", async () => {
    proyectosSimulados.mockResolvedValue([proyecto("p-2", "facturacion")]);
    // Un Desarrollador con asignación de ambiente: el backend devuelve solo `development`.
    ambientesSimulados.mockResolvedValue([ambiente("e-1", "p-2", "development")]);
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(await screen.findByRole("button", { name: /facturacion/i }));

    expect(ambientesSimulados).toHaveBeenCalledWith("p-2");
    const enlace = await screen.findByRole("link", { name: /development/i });
    expect(enlace).toBeInTheDocument();
    expect(screen.queryByText("staging")).not.toBeInTheDocument();
    expect(screen.queryByText("production")).not.toBeInTheDocument();
  });

  it("navega proyecto → ambiente → secretos", async () => {
    proyectosSimulados.mockResolvedValue([proyecto("p-2", "facturacion")]);
    ambientesSimulados.mockResolvedValue([
      ambiente("e-1", "p-2", "development"),
      ambiente("e-2", "p-2", "staging"),
    ]);
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(await screen.findByRole("button", { name: /facturacion/i }));
    const lista = await screen.findByRole("list", { name: /ambientes de facturacion/i });
    await usuario.click(within(lista).getByRole("link", { name: /staging/i }));

    expect(await screen.findByText("Secretos de p-2/e-2")).toBeInTheDocument();
  });
});
