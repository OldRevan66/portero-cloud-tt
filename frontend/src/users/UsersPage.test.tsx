// Lista de usuarios (CU-05; spec §2 notas de Usuarios, §3.5, §8.2, §8.4; H-37, H-59).
//
// - Tabla: correo (enlace a /usuarios/:uid), nombre, estado y fecha de alta.
// - "Nuevo usuario": el cuerpo lleva la contraseña inicial, así que `crearUsuario` se llama
//   directo, nunca con useMutation (spec §8.4), y después se invalida la lista. La contraseña no
//   queda en la caché de TanStack Query, ni en console, ni en la URL. La política (12 a 128
//   caracteres) solo se muestra: la decide el backend (422) y su problem+json se ve tal cual.
// - Desactivar pide confirmación y avisa que se cierran las sesiones del usuario (H-37); el 409
//   por autodesactivación o por último Administrador (H-59) se muestra tal cual. Reactivar es
//   PATCH {is_active: true}.
// - Los botones solo aparecen con users:manage de instancia (`permisosEn(me, null, null)`), como
//   exige el backend (H-23a); la autoridad sigue siendo el backend.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { notificarError, notificarExito } from "../api/problem";
import type { Assignment, Me } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha } from "../lib/formato";
import { UsersPage } from "./UsersPage";
import {
  actualizarUsuario,
  crearUsuario,
  desactivarUsuario,
  listarUsuarios,
  type UserOut,
} from "./usersApi";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../api/problem", async (original) => ({
  ...(await original<typeof import("../api/problem")>()),
  notificarExito: vi.fn(),
  notificarError: vi.fn(),
}));
vi.mock("./usersApi", () => ({
  listarUsuarios: vi.fn(),
  obtenerUsuario: vi.fn(),
  crearUsuario: vi.fn(),
  actualizarUsuario: vi.fn(),
  desactivarUsuario: vi.fn(),
  listarAsignaciones: vi.fn(),
  asignarRol: vi.fn(),
  quitarAsignacion: vi.fn(),
}));

const sesionSimulada = vi.mocked(useSession);
const listarSimulado = vi.mocked(listarUsuarios);
const crearSimulado = vi.mocked(crearUsuario);
const actualizarSimulado = vi.mocked(actualizarUsuario);
const desactivarSimulado = vi.mocked(desactivarUsuario);
const exitoSimulado = vi.mocked(notificarExito);
const errorSimulado = vi.mocked(notificarError);

const ADMINISTRADOR = 1;
const DESARROLLADOR = 3;
const UID_YO = "3e8f9d6b-8c4a-4f5d-8b9e-4d5e6f708192";
const UID_ANA = "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f";
const UID_BETO = "1c8d7b4f-6a2e-4d3b-8f9c-2b3c4d5e6f70";
const PID = "fc7d3e0a-6e92-4b6b-bd8a-0123456789ab";
const FECHA_ANA = "2026-10-11T16:00:00Z";
const FECHA_BETO = "2026-10-12T15:30:00Z";
const CORREO = "nuevo@tienda.example";
const CONTRASENA = "contraseña-de-prueba-no-real";
const AVISO_H37 = "Se cerrarán todas las sesiones de este usuario.";

function usuario(
  id: string,
  email: string,
  name: string | null,
  is_active: boolean,
  fecha: string,
): UserOut {
  return { id, email, name, is_active, created_at: fecha, updated_at: fecha, locked_until: null };
}

const ANA = usuario(UID_ANA, "ana@tienda.example", "Ana", true, FECHA_ANA);
const BETO = usuario(UID_BETO, "beto@tienda.example", null, false, FECHA_BETO);
const NUEVO = usuario("4f9a0e7c-9d5b-4a6e-9caf-5e6f708192a3", CORREO, null, true, FECHA_BETO);

function asignacion(role_id: number, project_id: string | null): Assignment {
  return { id: `a-${role_id}`, role_id, role: "", project_id, environment_id: null };
}

function conSesion(assignments: Assignment[]) {
  const me: Me = { id: UID_YO, email: "yo@tienda.example", name: "Yo", assignments };
  sesionSimulada.mockReturnValue({
    estado: "autenticado",
    usuario: me,
    menu: [],
    cerrarSesion: vi.fn(),
  });
}

/** Error de Axios con un problem+json (RFC 9457), como lo responde el API REST Gateway. */
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

/** Muestra la URL actual para comprobar que la contraseña nunca llega a ella. */
function Ubicacion() {
  const { pathname, search, hash } = useLocation();
  return <output data-testid="ubicacion">{`${pathname}${search}${hash}`}</output>;
}

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/usuarios"]}>
          <Routes>
            <Route
              path="/usuarios"
              element={
                <>
                  <UsersPage />
                  <Ubicacion />
                </>
              }
            />
            <Route path="/usuarios/:uid" element={<p>Detalle simulado</p>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

/** Abre "Nuevo usuario" y llena el formulario; devuelve el modal. */
async function llenarAlta(usuarioEv: ReturnType<typeof userEvent.setup>, nombre?: string) {
  await usuarioEv.click(await screen.findByRole("button", { name: /nuevo usuario/i }));
  const modal = await screen.findByRole("dialog");
  await usuarioEv.type(within(modal).getByLabelText(/^correo/i), CORREO);
  if (nombre !== undefined) {
    await usuarioEv.type(within(modal).getByLabelText(/^nombre/i), nombre);
  }
  await usuarioEv.type(within(modal).getByLabelText(/^contraseña/i), CONTRASENA);
  return modal;
}

async function enviarAlta(usuarioEv: ReturnType<typeof userEvent.setup>, modal: HTMLElement) {
  await usuarioEv.click(within(modal).getByRole("button", { name: /^crear$/i }));
}

function fila(texto: string): HTMLElement {
  const celda = screen.getByText(texto);
  const tr = celda.closest("tr");
  if (tr === null) {
    throw new Error(`"${texto}" no está en una fila de la tabla`);
  }
  return tr;
}

describe("UsersPage: lista", () => {
  beforeEach(() => {
    conSesion([asignacion(ADMINISTRADOR, null)]);
    listarSimulado.mockReset().mockResolvedValue([ANA, BETO]);
  });

  it("muestra correo, nombre, estado y fecha de alta", async () => {
    renderizar();

    expect(await screen.findByText("ana@tienda.example")).toBeInTheDocument();
    const ana = fila("ana@tienda.example");
    expect(ana).toHaveTextContent("Ana");
    expect(ana).toHaveTextContent("Activo");
    expect(ana).toHaveTextContent(formatearFecha(FECHA_ANA));
    const beto = fila("beto@tienda.example");
    expect(beto).toHaveTextContent("—");
    expect(beto).toHaveTextContent("Inactivo");
    expect(beto).toHaveTextContent(formatearFecha(FECHA_BETO));
  });

  it("el correo lleva al detalle /usuarios/:uid", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    const enlace = await screen.findByRole("link", { name: "ana@tienda.example" });
    expect(enlace).toHaveAttribute("href", `/usuarios/${UID_ANA}`);
    await usuarioEv.click(enlace);
    expect(await screen.findByText("Detalle simulado")).toBeInTheDocument();
  });

  it.each([
    ["un Desarrollador", [asignacion(DESARROLLADOR, PID)]],
    ["un Administrador solo de proyecto", [asignacion(ADMINISTRADOR, PID)]],
  ])("con %s no hay botones de gestión", async (_caso, asignaciones) => {
    conSesion(asignaciones);
    renderizar();

    await screen.findByText("ana@tienda.example");
    expect(screen.queryByRole("button", { name: /nuevo usuario/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /desactivar/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reactivar/i })).not.toBeInTheDocument();
  });

  it("un error de carga muestra el problem+json en español", async () => {
    listarSimulado
      .mockReset()
      .mockRejectedValue(problema(403, "Acceso denegado", "no tienes permiso para esta operación"));
    renderizar();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "no tienes permiso para esta operación",
    );
  });
});

describe("UsersPage: nuevo usuario", () => {
  beforeEach(() => {
    conSesion([asignacion(ADMINISTRADOR, null)]);
    listarSimulado.mockReset().mockResolvedValue([ANA, BETO]);
    crearSimulado.mockReset().mockResolvedValue(NUEVO);
    exitoSimulado.mockReset();
  });

  it("muestra la política y la contraseña va en un campo type=password", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    await usuarioEv.click(await screen.findByRole("button", { name: /nuevo usuario/i }));
    const modal = await screen.findByRole("dialog");

    expect(modal).toHaveTextContent(/12 a 128 caracteres/);
    expect(within(modal).getByLabelText(/^contraseña/i)).toHaveAttribute("type", "password");
  });

  it("sin nombre llama a crearUsuario con name: null", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    await enviarAlta(usuarioEv, await llenarAlta(usuarioEv));

    await waitFor(() => {
      expect(crearSimulado).toHaveBeenCalledWith({
        email: CORREO,
        name: null,
        password: CONTRASENA,
      });
    });
  });

  it("con nombre lo envía", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    await enviarAlta(usuarioEv, await llenarAlta(usuarioEv, "Nuevo"));

    await waitFor(() => {
      expect(crearSimulado).toHaveBeenCalledWith({
        email: CORREO,
        name: "Nuevo",
        password: CONTRASENA,
      });
    });
  });

  it("201: notifica, refresca la lista, cierra el modal y al reabrir los campos están vacíos", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();
    const modal = await llenarAlta(usuarioEv, "Nuevo");
    listarSimulado.mockResolvedValue([ANA, BETO, NUEVO]);

    await enviarAlta(usuarioEv, modal);

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(exitoSimulado).toHaveBeenCalled();
    expect(await screen.findByText(CORREO)).toBeInTheDocument();
    expect(listarSimulado.mock.calls.length).toBeGreaterThanOrEqual(2);

    await usuarioEv.click(screen.getByRole("button", { name: /nuevo usuario/i }));
    const otra = await screen.findByRole("dialog");
    expect(within(otra).getByLabelText(/^correo/i)).toHaveValue("");
    expect(within(otra).getByLabelText(/^nombre/i)).toHaveValue("");
    expect(within(otra).getByLabelText(/^contraseña/i)).toHaveValue("");
  });

  it("la contraseña no queda en la caché de TanStack Query, ni en el DOM, ni en la URL", async () => {
    const usuarioEv = userEvent.setup();
    const queryClient = renderizar();

    await enviarAlta(usuarioEv, await llenarAlta(usuarioEv));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    const consultas = queryClient
      .getQueryCache()
      .getAll()
      .map((q) => ({ key: q.queryKey, data: q.state.data }));
    const mutaciones = queryClient
      .getMutationCache()
      .getAll()
      .map((m) => ({ variables: m.state.variables, data: m.state.data }));
    expect(JSON.stringify(consultas)).not.toContain(CONTRASENA);
    expect(JSON.stringify(mutaciones)).not.toContain(CONTRASENA);
    expect(document.body.innerHTML).not.toContain(CONTRASENA);
    expect(screen.getByTestId("ubicacion").textContent).not.toContain(CONTRASENA);
    expect(screen.getByTestId("ubicacion").textContent).toBe("/usuarios");
    expect(decodeURIComponent(window.location.href)).not.toContain(CONTRASENA);
  });

  it("nunca escribe la contraseña en console, tampoco cuando el API la rechaza", async () => {
    const espias = (["log", "info", "debug", "warn", "error"] as const).map((metodo) =>
      vi.spyOn(console, metodo).mockImplementation(() => {}),
    );
    crearSimulado
      .mockRejectedValueOnce(
        problema(422, "Contraseña no válida", "la contraseña debe tener al menos 12 caracteres"),
      )
      .mockResolvedValueOnce(NUEVO);
    const usuarioEv = userEvent.setup();
    renderizar();

    const modal = await llenarAlta(usuarioEv);
    await enviarAlta(usuarioEv, modal);
    await within(modal).findByRole("alert");
    await enviarAlta(usuarioEv, modal);
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    for (const espia of espias) {
      for (const argumentos of espia.mock.calls) {
        expect(JSON.stringify(argumentos.map(String))).not.toContain(CONTRASENA);
      }
    }
  });

  it.each([
    [422, "Contraseña no válida", "la contraseña debe tener al menos 12 caracteres"],
    [409, "Conflicto", "ya existe un usuario con ese correo"],
  ])(
    "%i: muestra title y detail del problem+json y el modal sigue abierto",
    async (status, title, detail) => {
      crearSimulado.mockReset().mockRejectedValue(problema(status, title, detail));
      const usuarioEv = userEvent.setup();
      renderizar();

      const modal = await llenarAlta(usuarioEv);
      await enviarAlta(usuarioEv, modal);

      const alerta = await within(modal).findByRole("alert");
      expect(alerta).toHaveTextContent(title);
      expect(alerta).toHaveTextContent(detail);
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(exitoSimulado).not.toHaveBeenCalled();
    },
  );
});

describe("UsersPage: desactivar y reactivar", () => {
  beforeEach(() => {
    conSesion([asignacion(ADMINISTRADOR, null)]);
    listarSimulado.mockReset().mockResolvedValue([ANA, BETO]);
    desactivarSimulado.mockReset().mockResolvedValue(undefined);
    actualizarSimulado.mockReset().mockResolvedValue({ ...BETO, is_active: true });
    errorSimulado.mockReset();
  });

  /** Pulsa "Desactivar" en la fila de Ana y devuelve el diálogo de confirmación. */
  async function pedirDesactivar(usuarioEv: ReturnType<typeof userEvent.setup>) {
    await screen.findByText("ana@tienda.example");
    await usuarioEv.click(
      within(fila("ana@tienda.example")).getByRole("button", { name: /desactivar/i }),
    );
    return screen.findByRole("dialog");
  }

  it("la confirmación nombra al usuario y avisa que se cierran sus sesiones (H-37)", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    const dialogo = await pedirDesactivar(usuarioEv);

    expect(dialogo).toHaveTextContent("ana@tienda.example");
    expect(dialogo).toHaveTextContent(AVISO_H37);
  });

  it("cancelar no desactiva", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    const dialogo = await pedirDesactivar(usuarioEv);
    await usuarioEv.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

    expect(desactivarSimulado).not.toHaveBeenCalled();
  });

  it("confirmar llama a desactivarUsuario", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();

    const dialogo = await pedirDesactivar(usuarioEv);
    await usuarioEv.click(within(dialogo).getByRole("button", { name: /^desactivar$/i }));

    await waitFor(() => {
      expect(desactivarSimulado).toHaveBeenCalledWith(UID_ANA);
    });
  });

  it.each([
    ["autodesactivación", "un Administrador no puede desactivarse a sí mismo"],
    ["último Administrador (H-59)", "no se puede desactivar al último Administrador"],
  ])("409 por %s: se muestra el detail tal cual", async (_caso, detail) => {
    desactivarSimulado.mockReset().mockRejectedValue(problema(409, "Conflicto", detail));
    const usuarioEv = userEvent.setup();
    renderizar();

    const dialogo = await pedirDesactivar(usuarioEv);
    await usuarioEv.click(within(dialogo).getByRole("button", { name: /^desactivar$/i }));

    expect(await within(dialogo).findByRole("alert")).toHaveTextContent(detail);
  });

  it("un usuario inactivo tiene 'Reactivar' (PATCH is_active: true) y no 'Desactivar'", async () => {
    const usuarioEv = userEvent.setup();
    renderizar();
    await screen.findByText("beto@tienda.example");
    const beto = fila("beto@tienda.example");

    expect(within(beto).queryByRole("button", { name: /desactivar/i })).not.toBeInTheDocument();
    await usuarioEv.click(within(beto).getByRole("button", { name: /reactivar/i }));

    await waitFor(() => {
      expect(actualizarSimulado).toHaveBeenCalledWith(UID_BETO, { is_active: true });
    });
  });

  it("un error al reactivar se notifica con el problem+json", async () => {
    const error = problema(409, "Conflicto", "no se pudo reactivar");
    actualizarSimulado.mockReset().mockRejectedValue(error);
    const usuarioEv = userEvent.setup();
    renderizar();
    await screen.findByText("beto@tienda.example");

    await usuarioEv.click(
      within(fila("beto@tienda.example")).getByRole("button", { name: /reactivar/i }),
    );

    await waitFor(() => {
      expect(errorSimulado.mock.calls[0]?.[0]).toBe(error);
    });
  });
});
