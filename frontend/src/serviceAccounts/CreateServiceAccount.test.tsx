// Aplicaciones Cliente del proyecto (spec §2, §3.7, §8.2, §8.4; H-21, H-23a).
// La sección vive dentro de /proyectos/:pid y solo se muestra con projects:manage en el proyecto
// (Administrador o Líder Técnico del proyecto); la autoridad sigue siendo el backend.
// - POST /projects/{pid}/service-accounts responde el `token` (el PAT) UNA sola vez. Es un valor
//   en claro: se pide con una llamada directa, nunca con useMutation (spec §8.4), y vive en un
//   useState del modal. El modal tiene "Copiar" y avisa que no se volverá a mostrar; al cerrarlo
//   el token se borra del estado y no queda en la caché de TanStack Query.
// - La lista (GET) solo trae metadatos: se muestra `token_prefix` como "termina en …" (H-42),
//   nunca el token.
// - "Revocar" (DELETE /service-accounts/{sid}) es irreversible: pide confirmación.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import { listarAmbientes } from "../projects/projectsApi";
import { ServiceAccountsSection } from "./ServiceAccountsSection";
import { crearAplicacion, listarAplicaciones, revocarAplicacion } from "./serviceAccountsApi";

vi.mock("../projects/projectsApi", () => ({ listarAmbientes: vi.fn() }));
vi.mock("./serviceAccountsApi", () => ({
  listarAplicaciones: vi.fn(),
  crearAplicacion: vi.fn(),
  revocarAplicacion: vi.fn(),
}));

type ServiceAccountOut = components["schemas"]["ServiceAccountOut"];
type ServiceAccountCreated = components["schemas"]["ServiceAccountCreated"];

const ambientesSimulados = vi.mocked(listarAmbientes);
const listarSimulado = vi.mocked(listarAplicaciones);
const crearSimulado = vi.mocked(crearAplicacion);
const revocarSimulado = vi.mocked(revocarAplicacion);

const PROYECTO = "p-1";
const FECHA = "2026-10-11T10:00:00Z";
const TOKEN = "ptk_ab12.token-de-prueba-no-real";
const PREFIJO = "ptk_ab12";

function aplicacion(id: string, name: string, revoked_at: string | null = null): ServiceAccountOut {
  return {
    id,
    name,
    project_id: PROYECTO,
    environment_id: null,
    token_prefix: PREFIJO,
    created_at: FECHA,
    created_by: "u-9",
    last_used_at: null,
    expires_at: null,
    revoked_at,
  };
}

const CREADA: ServiceAccountCreated = { ...aplicacion("sa-2", "ci-deploy"), token: TOKEN };

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <ServiceAccountsSection pid={PROYECTO} />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

/** Abre el formulario, escribe el nombre y crea la aplicación; devuelve el modal del token. */
async function crear(usuario: ReturnType<typeof userEvent.setup>, ambiente?: string) {
  await usuario.click(await screen.findByRole("button", { name: /nueva aplicación/i }));
  const formulario = await screen.findByRole("dialog");
  await usuario.type(within(formulario).getByLabelText(/^nombre/i), "ci-deploy");
  if (ambiente !== undefined) {
    await screen.findByRole("option", { name: "production" });
    await usuario.selectOptions(within(formulario).getByLabelText(/^ambiente/i), ambiente);
  }
  await usuario.click(within(formulario).getByRole("button", { name: /^crear$/i }));
  await screen.findByText(TOKEN);
  return screen.getByRole("dialog");
}

describe("Aplicaciones Cliente del proyecto", () => {
  beforeEach(() => {
    ambientesSimulados.mockReset();
    listarSimulado.mockReset();
    crearSimulado.mockReset();
    revocarSimulado.mockReset();
    ambientesSimulados.mockResolvedValue([
      { id: "e-3", project_id: PROYECTO, name: "production", description: null, created_at: FECHA },
    ]);
    listarSimulado.mockResolvedValue([aplicacion("sa-1", "monitoreo")]);
    crearSimulado.mockResolvedValue(CREADA);
  });

  it("crear llama al API con el nombre; sin ambiente ni expiración van nulos", async () => {
    const usuario = userEvent.setup();
    renderizar();

    await crear(usuario);

    expect(crearSimulado).toHaveBeenCalledWith(PROYECTO, {
      name: "ci-deploy",
      environment_id: null,
      expires_at: null,
    });
  });

  it("el ambiente elegido se envía como `environment_id`", async () => {
    const usuario = userEvent.setup();
    renderizar();

    await crear(usuario, "e-3");

    expect(crearSimulado).toHaveBeenCalledWith(PROYECTO, {
      name: "ci-deploy",
      environment_id: "e-3",
      expires_at: null,
    });
  });

  it("el token se muestra una vez, con 'Copiar' y la advertencia", async () => {
    const usuario = userEvent.setup(); // instala un portapapeles simulado en navigator
    const escribir = vi.spyOn(navigator.clipboard, "writeText");
    renderizar();

    const modal = await crear(usuario);

    expect(modal).toHaveTextContent(/no se volverá a mostrar/i);
    expect(screen.getAllByText(TOKEN)).toHaveLength(1);
    await usuario.click(within(modal).getByRole("button", { name: /copiar/i }));
    expect(escribir).toHaveBeenCalledWith(TOKEN);
  });

  it("al cerrar el modal el token desaparece y no queda en la caché", async () => {
    const usuario = userEvent.setup();
    const queryClient = renderizar();
    const modal = await crear(usuario);
    listarSimulado.mockResolvedValue([
      aplicacion("sa-1", "monitoreo"),
      aplicacion("sa-2", "ci-deploy"),
    ]);

    await usuario.click(within(modal).getByRole("button", { name: /ya lo guardé/i }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(document.body.textContent).not.toContain(TOKEN);
    expect(await screen.findByText("ci-deploy")).toBeInTheDocument();
    expect(listarSimulado.mock.calls.length).toBeGreaterThanOrEqual(2);

    const consultas = queryClient
      .getQueryCache()
      .getAll()
      .map((q) => ({ key: q.queryKey, data: q.state.data }));
    const mutaciones = queryClient
      .getMutationCache()
      .getAll()
      .map((m) => ({ variables: m.state.variables, data: m.state.data }));
    expect(JSON.stringify(consultas)).not.toContain(TOKEN);
    expect(JSON.stringify(mutaciones)).not.toContain(TOKEN);
  });

  it("nunca escribe el token en console", async () => {
    const espias = (["log", "info", "debug", "warn", "error"] as const).map((metodo) =>
      vi.spyOn(console, metodo).mockImplementation(() => {}),
    );
    const usuario = userEvent.setup();
    renderizar();
    const modal = await crear(usuario);
    await usuario.click(within(modal).getByRole("button", { name: /copiar/i }));
    await usuario.click(within(modal).getByRole("button", { name: /ya lo guardé/i }));

    for (const espia of espias) {
      for (const argumentos of espia.mock.calls) {
        expect(JSON.stringify(argumentos.map(String))).not.toContain(TOKEN);
      }
    }
  });

  it("la lista muestra solo el token_prefix como «termina en …» (H-42)", async () => {
    renderizar();

    expect(await screen.findByText("monitoreo")).toBeInTheDocument();
    // token_prefix son los ÚLTIMOS 8 caracteres del PAT: el inicio de todo JWT es igual.
    expect(screen.getByText(`termina en ${PREFIJO}`)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it("'Revocar' pide confirmación: cancelar no revoca", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("monitoreo");

    await usuario.click(screen.getByRole("button", { name: /revocar/i }));
    const dialogo = await screen.findByRole("dialog");
    expect(dialogo).toHaveTextContent(/monitoreo/);
    await usuario.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

    expect(revocarSimulado).not.toHaveBeenCalled();
  });

  it("'Revocar' confirmado llama al API", async () => {
    revocarSimulado.mockResolvedValueOnce(undefined);
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("monitoreo");

    await usuario.click(screen.getByRole("button", { name: /revocar/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /^revocar$/i }));

    await vi.waitFor(() => {
      expect(revocarSimulado).toHaveBeenCalledWith("sa-1");
    });
  });

  it("una aplicación revocada se marca así y no tiene botón 'Revocar'", async () => {
    listarSimulado.mockResolvedValue([aplicacion("sa-1", "monitoreo", FECHA)]);
    renderizar();

    expect(await screen.findByText(/revocada/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /revocar/i })).not.toBeInTheDocument();
  });
});
