// Spec §8.2: crear, rotar, editar y archivar secretos solo para Administrador y Líder Técnico.
// Los botones se calculan con `permisosEn` (auth/permissions.ts) en el alcance del secreto: solo
// cuentan las asignaciones que cubren su proyecto y ambiente (Algoritmo 5 del Cap. 6). Es
// conveniencia de interfaz; la autoridad es el backend (un 403/404 se muestra como tal).
// - Archivar (DELETE /secrets/{id}) es irreversible desde el Dashboard: pide confirmación.
// - Rotar (CU-04) lleva el valor nuevo: llamada directa, nunca useMutation (spec §8.4).
// - Editar descripción (PATCH /secrets/{id}, H-77) con `secrets:write`: solo metadatos.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import type { Assignment, Me } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { SecretActions } from "./SecretActions";
import { actualizarSecreto, archivarSecreto, rotarSecreto } from "./secretsApi";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("./secretsApi", () => ({
  actualizarSecreto: vi.fn(),
  archivarSecreto: vi.fn(),
  rotarSecreto: vi.fn(),
}));

type SecretOut = components["schemas"]["SecretOut"];

const sesionSimulada = vi.mocked(useSession);
const archivarSimulado = vi.mocked(archivarSecreto);
const rotarSimulado = vi.mocked(rotarSecreto);
const actualizarSimulado = vi.mocked(actualizarSecreto);

const LIDER_TECNICO = 2;
const DESARROLLADOR = 3;
const FECHA = "2026-10-11T10:00:00Z";
const NUEVO_VALOR = "valor-nuevo-de-prueba-no-real";

const SECRETO: SecretOut = {
  id: "sec-1",
  name: "DATABASE_URL",
  description: "Conexión a la base de datos",
  version: 3,
  project_id: "p-1",
  environment_id: "e-1",
  created_at: FECHA,
  created_by: "u-9",
  updated_at: FECHA,
};

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

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <SecretActions secret={SECRETO} />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

describe("SecretActions", () => {
  beforeEach(() => {
    sesionSimulada.mockReset();
    archivarSimulado.mockReset();
    rotarSimulado.mockReset();
    actualizarSimulado.mockReset();
  });

  it("un Desarrollador no ve 'Rotar' ni 'Archivar'", () => {
    conSesion([asignacion(DESARROLLADOR, "p-1")]);
    renderizar();

    expect(screen.queryByRole("button", { name: /rotar/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /archivar/i })).not.toBeInTheDocument();
  });

  it("un Líder Técnico del proyecto ve 'Rotar' y 'Archivar'", () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    renderizar();

    expect(screen.getByRole("button", { name: /rotar/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /archivar/i })).toBeInTheDocument();
  });

  it("ser Líder en otro proyecto no da acciones en este", () => {
    conSesion([asignacion(LIDER_TECNICO, "p-2"), asignacion(DESARROLLADOR, "p-1")]);
    renderizar();

    expect(screen.queryByRole("button", { name: /rotar/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /archivar/i })).not.toBeInTheDocument();
  });

  it("'Archivar' pide confirmación: cancelar no archiva", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(screen.getByRole("button", { name: /archivar/i }));
    const dialogo = await screen.findByRole("dialog");
    expect(dialogo).toHaveTextContent(/DATABASE_URL/);
    await usuario.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

    expect(archivarSimulado).not.toHaveBeenCalled();
  });

  it("'Archivar' confirmado llama al API", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    archivarSimulado.mockResolvedValueOnce(undefined);
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(screen.getByRole("button", { name: /archivar/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.click(within(dialogo).getByRole("button", { name: /^archivar$/i }));

    await vi.waitFor(() => {
      expect(archivarSimulado).toHaveBeenCalledWith("sec-1");
    });
  });

  it("'Rotar' pide el valor nuevo en un campo password y no lo deja en la caché", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    rotarSimulado.mockResolvedValueOnce({ id: "sec-1", version: 4, rotated_at: FECHA });
    const usuario = userEvent.setup();
    const queryClient = renderizar();

    await usuario.click(screen.getByRole("button", { name: /rotar/i }));
    const dialogo = await screen.findByRole("dialog");
    const campo = within(dialogo).getByLabelText(/^nuevo valor/i);
    expect(campo).toHaveAttribute("type", "password");
    await usuario.click(campo);
    await usuario.paste(NUEVO_VALOR);
    await usuario.click(within(dialogo).getByRole("button", { name: /^rotar$/i }));

    await vi.waitFor(() => {
      expect(rotarSimulado).toHaveBeenCalledWith("sec-1", NUEVO_VALOR);
    });
    const mutaciones = queryClient
      .getMutationCache()
      .getAll()
      .map((m) => ({ variables: m.state.variables, data: m.state.data }));
    expect(JSON.stringify(mutaciones)).not.toContain(NUEVO_VALOR);
  });

  it("'Editar descripción': la ve el Líder (secrets:write), no el Desarrollador", () => {
    conSesion([asignacion(DESARROLLADOR, "p-1")]);
    renderizar();
    expect(screen.queryByRole("button", { name: /editar descripción/i })).not.toBeInTheDocument();
  });

  it("'Editar descripción' parte de la actual y envía la nueva", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    actualizarSimulado.mockResolvedValueOnce({ ...SECRETO, description: "nueva" });
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(screen.getByRole("button", { name: /editar descripción/i }));
    const dialogo = await screen.findByRole("dialog");
    const campo = within(dialogo).getByLabelText(/^descripción/i);
    expect(campo).toHaveValue("Conexión a la base de datos");
    await usuario.clear(campo);
    await usuario.type(campo, "nueva");
    await usuario.click(within(dialogo).getByRole("button", { name: /^guardar$/i }));

    await vi.waitFor(() => {
      expect(actualizarSimulado).toHaveBeenCalledWith("sec-1", { description: "nueva" });
    });
  });

  it("'Editar descripción' vacía envía null", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    actualizarSimulado.mockResolvedValueOnce({ ...SECRETO, description: null });
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(screen.getByRole("button", { name: /editar descripción/i }));
    const dialogo = await screen.findByRole("dialog");
    await usuario.clear(within(dialogo).getByLabelText(/^descripción/i));
    await usuario.click(within(dialogo).getByRole("button", { name: /^guardar$/i }));

    await vi.waitFor(() => {
      expect(actualizarSimulado).toHaveBeenCalledWith("sec-1", { description: null });
    });
  });

  it("'Editar descripción' con más de 1024 caracteres no llama al API", async () => {
    conSesion([asignacion(LIDER_TECNICO, "p-1")]);
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(screen.getByRole("button", { name: /editar descripción/i }));
    const dialogo = await screen.findByRole("dialog");
    const campo = within(dialogo).getByLabelText(/^descripción/i);
    await usuario.clear(campo);
    await usuario.click(campo);
    await usuario.paste("x".repeat(1025));
    await usuario.click(within(dialogo).getByRole("button", { name: /^guardar$/i }));

    expect(await within(dialogo).findByText(/como máximo 1024 caracteres/i)).toBeInTheDocument();
    expect(actualizarSimulado).not.toHaveBeenCalled();
  });
});
