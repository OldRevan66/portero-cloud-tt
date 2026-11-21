// H-77: archivar el proyecto y eliminar ambientes desde el Dashboard (CU-07, RF-032, spec §8.2).
// - Visibles con `projects:manage` en el proyecto, igual que "Editar proyecto" (decisión del
//   29 oct: la interfaz sigue a la API). Es conveniencia de interfaz; el backend vuelve a autorizar.
// - Archivar pide confirmación. Si el proyecto tiene secretos activos, la API responde 409 sin
//   `?confirm=true`: se muestra el `detail` y una segunda confirmación reintenta con confirm.
// - Eliminar un ambiente con secretos responde 409 (H-39): se muestra el `title` y el `detail`
//   del problem+json (RF-029); no hay reintento.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import type { Assignment, Me } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { ProjectDetailPage } from "./ProjectDetailPage";
import {
  archivarProyecto,
  eliminarAmbiente,
  listarAmbientes,
  obtenerProyecto,
} from "./projectsApi";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../serviceAccounts/ServiceAccountsSection", () => ({
  ServiceAccountsSection: () => null,
}));
vi.mock("./projectsApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./projectsApi")>()),
  obtenerProyecto: vi.fn(),
  listarAmbientes: vi.fn(),
  archivarProyecto: vi.fn(),
  eliminarAmbiente: vi.fn(),
}));

type ProjectOut = components["schemas"]["ProjectOut"];
type EnvironmentOut = components["schemas"]["EnvironmentOut"];

const sesionSimulada = vi.mocked(useSession);
const proyectoSimulado = vi.mocked(obtenerProyecto);
const ambientesSimulados = vi.mocked(listarAmbientes);
const archivarSimulado = vi.mocked(archivarProyecto);
const eliminarSimulado = vi.mocked(eliminarAmbiente);

const LIDER_TECNICO = 2;
const DESARROLLADOR = 3;
const FECHA = "2026-10-11T10:00:00Z";
const PID = "0b9a3c1e-5d2f-4a6b-8c7d-9e0f1a2b3c4d";
const OTRO_PID = "1c0b4d2f-6e3a-4b7c-9d8e-0f1a2b3c4d5e";
const EID_DEV = "2d1c5e3a-7f4b-4c8d-ae9f-1a2b3c4d5e6f";
const EID_QA = "3e2d6f4b-8a5c-4d9e-bf0a-2b3c4d5e6f7a";

const PROYECTO: ProjectOut = {
  id: PID,
  name: "Tienda en línea",
  description: null,
  created_at: FECHA,
  updated_at: FECHA,
};

const AMBIENTES: EnvironmentOut[] = [
  { id: EID_DEV, project_id: PID, name: "development", description: null, created_at: FECHA },
  { id: EID_QA, project_id: PID, name: "qa", description: null, created_at: FECHA },
];

function asignacion(role_id: number, project_id: string): Assignment {
  return { id: `a-${role_id}-${project_id}`, role_id, role: "", project_id, environment_id: null };
}

function conSesion(assignments: Assignment[]) {
  const usuario: Me = { id: "u-1", email: "ana@example.com", name: "Ana", assignments };
  sesionSimulada.mockReturnValue({
    estado: "autenticado",
    usuario,
    menu: [],
    cerrarSesion: vi.fn(),
  });
}

/** 409 problem+json como lo responde el API REST Gateway (spec §6). */
function error409(detail: string): AxiosError {
  const config = { headers: {} } as InternalAxiosRequestConfig;
  const response = {
    status: 409,
    statusText: "Conflict",
    data: { type: "about:blank", title: "Conflicto", status: 409, detail },
    headers: {},
    config,
  } as AxiosResponse;
  return new AxiosError("HTTP 409", AxiosError.ERR_BAD_REQUEST, config, null, response);
}

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/proyectos/${PID}`]}>
          <Routes>
            <Route path="/proyectos" element={<p>Lista de proyectos</p>} />
            <Route path="/proyectos/:pid" element={<ProjectDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

/** Espera a que la tabla de ambientes esté pintada. */
async function esperarAmbientes() {
  await screen.findByRole("link", { name: "development" });
}

function filaDe(nombre: string): HTMLElement {
  const fila = screen.getByRole("link", { name: nombre }).closest("tr");
  if (fila === null) throw new Error(`Sin fila para ${nombre}`);
  return fila;
}

describe("ProjectDetailPage: archivar proyecto y eliminar ambiente (H-77)", () => {
  beforeEach(() => {
    sesionSimulada.mockReset();
    proyectoSimulado.mockReset().mockResolvedValue(PROYECTO);
    ambientesSimulados.mockReset().mockResolvedValue(AMBIENTES);
    archivarSimulado.mockReset();
    eliminarSimulado.mockReset();
  });

  it("un Desarrollador no ve 'Archivar proyecto' ni 'Eliminar'", async () => {
    conSesion([asignacion(DESARROLLADOR, PID)]);
    renderizar();
    await esperarAmbientes();

    expect(screen.queryByRole("button", { name: /archivar proyecto/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^eliminar$/i })).not.toBeInTheDocument();
  });

  it("el Líder Técnico del proyecto ve 'Archivar proyecto' y 'Eliminar' en cada ambiente", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    renderizar();
    await esperarAmbientes();

    expect(screen.getByRole("button", { name: /archivar proyecto/i })).toBeInTheDocument();
    for (const nombre of ["development", "qa"]) {
      expect(within(filaDe(nombre)).getByRole("button", { name: /^eliminar$/i })).toBeVisible();
    }
  });

  it("ser Líder en otro proyecto no da esas acciones en este", async () => {
    conSesion([asignacion(LIDER_TECNICO, OTRO_PID), asignacion(DESARROLLADOR, PID)]);
    renderizar();
    await esperarAmbientes();

    expect(screen.queryByRole("button", { name: /archivar proyecto/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^eliminar$/i })).not.toBeInTheDocument();
  });

  it("'Archivar proyecto' pide confirmación: cancelar no archiva", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(screen.getByRole("button", { name: /archivar proyecto/i }));
    const dialogo = await screen.findByRole("dialog");
    expect(dialogo).toHaveTextContent(/Tienda en línea/);
    await usuario.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

    expect(archivarSimulado).not.toHaveBeenCalled();
  });

  it("archivar sin secretos activos llama al API sin confirm y vuelve a /proyectos", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    archivarSimulado.mockResolvedValueOnce(undefined);
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(screen.getByRole("button", { name: /archivar proyecto/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /^archivar$/i }));

    expect(await screen.findByText("Lista de proyectos")).toBeInTheDocument();
    expect(archivarSimulado).toHaveBeenCalledTimes(1);
    expect(archivarSimulado).toHaveBeenCalledWith(PID, false);
  });

  it("409 al archivar: segunda confirmación con el detail y reintento con confirm", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    archivarSimulado
      .mockRejectedValueOnce(error409("el proyecto tiene secretos activos; confirma el archivado"))
      .mockResolvedValueOnce(undefined);
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(screen.getByRole("button", { name: /archivar proyecto/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /^archivar$/i }));

    expect(
      await within(dialogo).findByText(/el proyecto tiene secretos activos/i),
    ).toBeInTheDocument();
    expect(archivarSimulado).toHaveBeenCalledTimes(1);
    await usuario.click(
      within(dialogo).getByRole("button", { name: /archivar proyecto y sus secretos/i }),
    );

    expect(await screen.findByText("Lista de proyectos")).toBeInTheDocument();
    expect(archivarSimulado).toHaveBeenNthCalledWith(1, PID, false);
    expect(archivarSimulado).toHaveBeenNthCalledWith(2, PID, true);
  });

  it("409 al archivar: cancelar la segunda confirmación no reintenta", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    archivarSimulado.mockRejectedValueOnce(
      error409("el proyecto tiene secretos activos; confirma el archivado"),
    );
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(screen.getByRole("button", { name: /archivar proyecto/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /^archivar$/i }));
    await within(dialogo).findByText(/el proyecto tiene secretos activos/i);
    await usuario.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

    expect(archivarSimulado).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Lista de proyectos")).not.toBeInTheDocument();
  });

  it("'Eliminar' ambiente pide confirmación; cancelar no llama y confirmar sí", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    eliminarSimulado.mockResolvedValueOnce(undefined);
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(within(filaDe("qa")).getByRole("button", { name: /^eliminar$/i }));
    let dialogo = await screen.findByRole("dialog");
    expect(dialogo).toHaveTextContent(/qa/);
    await usuario.click(within(dialogo).getByRole("button", { name: /cancelar/i }));
    expect(eliminarSimulado).not.toHaveBeenCalled();

    await usuario.click(within(filaDe("qa")).getByRole("button", { name: /^eliminar$/i }));
    dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /eliminar ambiente/i }));

    await vi.waitFor(() => {
      expect(eliminarSimulado).toHaveBeenCalledWith(PID, EID_QA);
    });
  });

  it("409 al eliminar un ambiente con secretos (H-39): muestra title y detail, sin reintento", async () => {
    conSesion([asignacion(LIDER_TECNICO, PID)]);
    eliminarSimulado.mockRejectedValueOnce(error409("el ambiente tiene secretos"));
    const usuario = userEvent.setup();
    renderizar();
    await esperarAmbientes();

    await usuario.click(within(filaDe("development")).getByRole("button", { name: /^eliminar$/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /eliminar ambiente/i }));

    const alerta = await within(dialogo).findByRole("alert");
    expect(alerta).toHaveTextContent("Conflicto");
    expect(alerta).toHaveTextContent("el ambiente tiene secretos");
    expect(eliminarSimulado).toHaveBeenCalledTimes(1);
    expect(eliminarSimulado).toHaveBeenCalledWith(PID, EID_DEV);
    expect(screen.getByRole("link", { name: "development" })).toBeInTheDocument();
  });
});
