// H-62 (OWASP ASVS 4.0.3 V5.1.3, lista permitida): las pantallas que leen identificadores de la
// URL (`:pid`, `:eid`, `:sid`) solo llaman al API si los tres tienen forma de UUID. Con un enlace
// como /proyectos/<p>/ambientes/<e>/secretos/<s>%2Fvalue, React Router entrega `sid` = "<s>/value";
// antes, eso terminaba en GET /secrets/<s>/value sin pulsar "Revelar".
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import { useSession } from "../auth/SessionProvider";
import { ProjectDetailPage } from "../projects/ProjectDetailPage";
import { listarAmbientes, obtenerProyecto } from "../projects/projectsApi";
import { EnvironmentSecretsPage } from "../secrets/EnvironmentSecretsPage";
import { SecretDetailPage } from "../secrets/SecretDetailPage";
import {
  listarSecretos,
  listarVersiones,
  obtenerSecreto,
  revelarValor,
} from "../secrets/secretsApi";
import { listarAplicaciones } from "../serviceAccounts/serviceAccountsApi";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../projects/projectsApi", async (original) => ({
  ...(await original<typeof import("../projects/projectsApi")>()),
  obtenerProyecto: vi.fn(),
  listarAmbientes: vi.fn(),
}));
vi.mock("../secrets/secretsApi", async (original) => ({
  ...(await original<typeof import("../secrets/secretsApi")>()),
  listarSecretos: vi.fn(),
  obtenerSecreto: vi.fn(),
  revelarValor: vi.fn(),
  listarVersiones: vi.fn(),
}));
vi.mock("../serviceAccounts/serviceAccountsApi", () => ({ listarAplicaciones: vi.fn() }));

type SecretOut = components["schemas"]["SecretOut"];

const P = "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f";
const E = "1c8d7b4f-6a2e-4d3b-8f9c-2b3c4d5e6f70";
const S = "2d7e8c5a-7b3f-4e4c-9a8d-3c4d5e6f7081";
const FECHA = "2026-10-14T10:00:00Z";

const llamadas = [
  vi.mocked(obtenerProyecto),
  vi.mocked(listarAmbientes),
  vi.mocked(listarSecretos),
  vi.mocked(obtenerSecreto),
  vi.mocked(revelarValor),
  vi.mocked(listarVersiones),
  vi.mocked(listarAplicaciones),
];

function renderizar(url: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route path="/proyectos/:pid" element={<ProjectDetailPage />} />
            <Route path="/proyectos/:pid/ambientes/:eid" element={<EnvironmentSecretsPage />} />
            <Route
              path="/proyectos/:pid/ambientes/:eid/secretos/:sid"
              element={<SecretDetailPage />}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

describe("identificadores en la URL del Dashboard (H-62)", () => {
  beforeEach(() => {
    for (const llamada of llamadas) {
      llamada.mockReset();
    }
    vi.mocked(useSession).mockReturnValue({
      estado: "autenticado",
      usuario: { id: "u-1", email: "ana@example.com", name: "Ana", assignments: [] },
      menu: [],
      cerrarSesion: vi.fn(),
    });
  });

  it.each([
    ["secreto seguido de /value", `/proyectos/${P}/ambientes/${E}/secretos/${S}%2Fvalue`],
    ["secreto con ..", `/proyectos/${P}/ambientes/${E}/secretos/..%2F..%2Foperations`],
    ["secreto con ?", `/proyectos/${P}/ambientes/${E}/secretos/${S}%3Fx%3D1`],
    ["ambiente que no es UUID", `/proyectos/${P}/ambientes/e-1`],
    ["proyecto con /", `/proyectos/${P}%2Fenvironments`],
    [
      "proyecto que no es UUID en el detalle del secreto",
      `/proyectos/p/ambientes/${E}/secretos/${S}`,
    ],
  ])("%s → página no encontrada y ninguna petición", async (_caso, url) => {
    const queryClient = renderizar(url);

    expect(await screen.findByText("Página no encontrada")).toBeInTheDocument();
    for (const llamada of llamadas) {
      expect(llamada).not.toHaveBeenCalled();
    }
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });

  it("con UUID válidos el detalle del secreto sí consulta el API, sin pedir el valor", async () => {
    const secreto: SecretOut = {
      id: S,
      name: "DATABASE_URL",
      description: null,
      version: 1,
      project_id: P,
      environment_id: E,
      created_at: FECHA,
      created_by: "3e8f9d6b-8c4a-4f5d-8b9e-4d5e6f708192",
      updated_at: FECHA,
    };
    vi.mocked(obtenerSecreto).mockResolvedValue(secreto);
    vi.mocked(obtenerProyecto).mockResolvedValue({
      id: P,
      name: "tienda",
      description: null,
      created_at: FECHA,
      updated_at: FECHA,
    });
    vi.mocked(listarAmbientes).mockResolvedValue([]);
    vi.mocked(listarVersiones).mockResolvedValue({ items: [], next_cursor: null });

    renderizar(`/proyectos/${P}/ambientes/${E}/secretos/${S}`);

    expect(await screen.findByRole("heading", { name: "DATABASE_URL" })).toBeInTheDocument();
    expect(vi.mocked(obtenerSecreto)).toHaveBeenCalledWith(S);
    expect(vi.mocked(revelarValor)).not.toHaveBeenCalled();
  });
});
