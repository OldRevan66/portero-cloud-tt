// Detalle de un usuario con sus roles (CU-05; spec §2 notas de Usuarios y Asignaciones, §3.5,
// §8.2, §8.4; H-22, H-37, H-59, H-62, H-73).
//
// - /usuarios/:uid valida que `uid` sea UUID antes de cualquier petición; si no, NotFoundPage (H-62).
// - "Editar nombre" es PATCH /users/{uid}; el nombre es obligatorio (el backend exige 1–255).
// - Tabla de roles (GET /users/{uid}/role-assignments, H-73): rol, proyecto y ambiente por nombre;
//   "Instancia" si ambos son nulos.
// - "Asignar rol": proyecto obligatorio salvo para el Administrador; la instancia solo se ofrece
//   al Administrador (H-22), que también puede tener alcance de proyecto. El ambiente es opcional
//   y se llena al elegir proyecto. 409 (duplicado) y 422 (ambiente de otro proyecto) → problem+json.
// - "Quitar" pide confirmación; 409 del último Administrador (H-59) → problem+json.
// - Asignar y quitar cierran todas las sesiones del usuario (H-37): se avisa. Si el Administrador
//   se modifica a sí mismo, sus tokens ya no sirven: tras el éxito se cierra la sesión y va al login.
// - Los botones solo aparecen con users:manage de instancia (`permisosEn(me, null, null)`, H-23a).
// - H-78: "Bloqueada hasta" y "Desbloquear" solo si `locked_until` no es nulo; "Restablecer
//   contraseña" con una contraseña temporal. Ninguno de los dos sobre uno mismo (409 en el backend).
//   La contraseña temporal se envía con una llamada directa, nunca con useMutation: no queda en la
//   caché de mutaciones ni en la de consultas (spec §8.4, regla 8), ni en la notificación.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { notificarExito } from "../api/problem";
import type { Assignment, Me } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { listarAmbientes, listarProyectos, type EnvironmentOut } from "../projects/projectsApi";
import { UserDetailPage } from "./UserDetailPage";
import {
  actualizarUsuario,
  asignarRol,
  listarAsignaciones,
  obtenerUsuario,
  quitarAsignacion,
  desbloquearUsuario,
  restablecerContrasena,
  type AssignmentOut,
  type UserOut,
} from "./usersApi";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../api/problem", async (original) => ({
  ...(await original<typeof import("../api/problem")>()),
  notificarExito: vi.fn(),
  notificarError: vi.fn(),
}));
vi.mock("../projects/projectsApi", async (original) => ({
  ...(await original<typeof import("../projects/projectsApi")>()),
  listarProyectos: vi.fn(),
  listarAmbientes: vi.fn(),
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
  desbloquearUsuario: vi.fn(),
  restablecerContrasena: vi.fn(),
}));

const sesionSimulada = vi.mocked(useSession);
const obtenerSimulado = vi.mocked(obtenerUsuario);
const asignacionesSimuladas = vi.mocked(listarAsignaciones);
const actualizarSimulado = vi.mocked(actualizarUsuario);
const asignarSimulado = vi.mocked(asignarRol);
const quitarSimulado = vi.mocked(quitarAsignacion);
const proyectosSimulados = vi.mocked(listarProyectos);
const ambientesSimulados = vi.mocked(listarAmbientes);
const exitoSimulado = vi.mocked(notificarExito);
const desbloquearSimulado = vi.mocked(desbloquearUsuario);
const restablecerSimulado = vi.mocked(restablecerContrasena);

const ADMINISTRADOR = 1;
const LIDER_TECNICO = 2;
const DESARROLLADOR = 3;
const UID_YO = "3e8f9d6b-8c4a-4f5d-8b9e-4d5e6f708192";
const UID_ANA = "0b9c6a3e-5f1d-4c2a-9e7b-1a2b3c4d5e6f";
const PID_TIENDA = "fc7d3e0a-6e92-4b6b-bd8a-0123456789ab";
const PID_PAGOS = "ad5e1f2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b";
const EID_DEV = "2d7e8c5a-7b3f-4e4c-9a8d-3c4d5e6f7081";
const EID_PROD = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const EID_STAGING = "6b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e";
const AID_ADMIN = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
const AID_LIDER = "8e2f3a4b-5c6d-4e7f-9081-92a3b4c5d6e7";
const AID_DEV = "9f3a4b5c-6d7e-4f80-a192-a3b4c5d6e7f8";
const FECHA = "2026-10-11T16:00:00Z";
const AVISO_H37 = "Se cerrarán todas las sesiones de este usuario.";
const BLOQUEO = "2026-10-30T18:15:00Z";
const TEMPORAL = "marcador-temporal-larga";

function usuario(id: string, email: string, name: string | null): UserOut {
  return {
    id,
    email,
    name,
    is_active: true,
    created_at: FECHA,
    updated_at: FECHA,
    locked_until: null,
  };
}

const ANA = usuario(UID_ANA, "ana@tienda.example", "Ana");
const YO = usuario(UID_YO, "yo@tienda.example", "Yo");

function rol(
  id: string,
  role_id: number,
  project_id: string | null,
  environment_id: string | null = null,
): AssignmentOut {
  return { id, role_id, project_id, environment_id };
}

const ROLES_DE_ANA = [
  rol(AID_ADMIN, ADMINISTRADOR, null),
  rol(AID_LIDER, LIDER_TECNICO, PID_TIENDA),
  rol(AID_DEV, DESARROLLADOR, PID_TIENDA, EID_DEV),
];

function ambiente(id: string, project_id: string, name: string): EnvironmentOut {
  return { id, project_id, name, description: null, created_at: FECHA };
}

const AMBIENTES: Record<string, EnvironmentOut[]> = {
  [PID_TIENDA]: [
    ambiente(EID_DEV, PID_TIENDA, "development"),
    ambiente(EID_PROD, PID_TIENDA, "production"),
  ],
  [PID_PAGOS]: [ambiente(EID_STAGING, PID_PAGOS, "staging")],
};

function asignacionMe(role_id: number, project_id: string | null): Assignment {
  return { id: `a-${role_id}`, role_id, role: "", project_id, environment_id: null };
}

/** Sesión simulada; devuelve el `cerrarSesion` espía. */
function conSesion(assignments: Assignment[]) {
  const me: Me = { id: UID_YO, email: YO.email, name: YO.name, assignments };
  const cerrarSesion = vi.fn().mockResolvedValue(undefined);
  sesionSimulada.mockReturnValue({ estado: "autenticado", usuario: me, menu: [], cerrarSesion });
  return cerrarSesion;
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

function renderizar(url: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route path="/usuarios/:uid" element={<UserDetailPage />} />
            <Route path="/usuarios" element={<p>Lista simulada</p>} />
            <Route path="/login" element={<p>Inicio de sesión simulado</p>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

/** Fila de la tabla de roles cuyo texto empieza con el nombre del rol. */
async function filaDeRol(nombre: string): Promise<HTMLElement> {
  const celda = await screen.findByRole("cell", { name: nombre });
  const tr = celda.closest("tr");
  if (tr === null) {
    throw new Error(`"${nombre}" no está en una fila`);
  }
  return tr;
}

type Usuario = ReturnType<typeof userEvent.setup>;

/** Abre "Asignar rol" y devuelve el modal. */
async function abrirAsignar(usuarioEv: Usuario): Promise<HTMLElement> {
  await usuarioEv.click(await screen.findByRole("button", { name: /asignar rol/i }));
  return screen.findByRole("dialog");
}

function campo(modal: HTMLElement, etiqueta: RegExp): HTMLSelectElement {
  return within(modal).getByLabelText(etiqueta) as HTMLSelectElement;
}

async function elegirProyecto(usuarioEv: Usuario, modal: HTMLElement, nombre: string) {
  await within(modal).findByRole("option", { name: nombre });
  await usuarioEv.selectOptions(campo(modal, /^proyecto/i), nombre);
}

describe("UserDetailPage: identificador en la URL (H-62)", () => {
  beforeEach(() => {
    conSesion([asignacionMe(ADMINISTRADOR, null)]);
    for (const simulado of [
      obtenerSimulado,
      asignacionesSimuladas,
      proyectosSimulados,
      ambientesSimulados,
    ]) {
      simulado.mockReset();
    }
  });

  it.each([
    ["no es UUID", "/usuarios/u-1"],
    ["UUID seguido de /role-assignments", `/usuarios/${UID_ANA}%2Frole-assignments`],
    ["sube de nivel", "/usuarios/..%2Fme"],
  ])("%s → página no encontrada y ninguna petición", async (_caso, url) => {
    const queryClient = renderizar(url);

    expect(await screen.findByText("Página no encontrada")).toBeInTheDocument();
    expect(obtenerSimulado).not.toHaveBeenCalled();
    expect(asignacionesSimuladas).not.toHaveBeenCalled();
    expect(proyectosSimulados).not.toHaveBeenCalled();
    expect(ambientesSimulados).not.toHaveBeenCalled();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });
});

describe("UserDetailPage", () => {
  let cerrarSesion: ReturnType<typeof conSesion>;

  beforeEach(() => {
    cerrarSesion = conSesion([asignacionMe(ADMINISTRADOR, null)]);
    obtenerSimulado
      .mockReset()
      .mockImplementation((uid) => Promise.resolve(uid === UID_YO ? YO : ANA));
    asignacionesSimuladas.mockReset().mockResolvedValue(ROLES_DE_ANA);
    proyectosSimulados.mockReset().mockResolvedValue([
      {
        id: PID_TIENDA,
        name: "Tienda en línea",
        description: null,
        created_at: FECHA,
        updated_at: FECHA,
      },
      { id: PID_PAGOS, name: "Pagos", description: null, created_at: FECHA, updated_at: FECHA },
    ]);
    ambientesSimulados
      .mockReset()
      .mockImplementation((pid) => Promise.resolve(AMBIENTES[pid] ?? []));
    actualizarSimulado.mockReset().mockResolvedValue({ ...ANA, name: "Ana María" });
    asignarSimulado.mockReset().mockResolvedValue(rol(AID_DEV, DESARROLLADOR, PID_PAGOS));
    quitarSimulado.mockReset().mockResolvedValue(undefined);
    desbloquearSimulado.mockReset().mockResolvedValue(undefined);
    restablecerSimulado.mockReset().mockResolvedValue(undefined);
    exitoSimulado.mockReset();
  });

  describe("datos y nombre", () => {
    it("muestra correo, nombre y estado", async () => {
      renderizar(`/usuarios/${UID_ANA}`);

      expect(
        await screen.findByRole("heading", { name: "ana@tienda.example" }),
      ).toBeInTheDocument();
      expect(obtenerSimulado).toHaveBeenCalledWith(UID_ANA);
      expect(screen.getByText("Ana")).toBeInTheDocument();
      expect(screen.getByText("Activo")).toBeInTheDocument();
    });

    it("'Editar nombre' envía PATCH con el nombre nuevo", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      await usuarioEv.click(await screen.findByRole("button", { name: /editar nombre/i }));
      const modal = await screen.findByRole("dialog");
      const nombre = within(modal).getByLabelText(/^nombre/i);
      expect(nombre).toHaveValue("Ana");
      await usuarioEv.clear(nombre);
      await usuarioEv.type(nombre, "Ana María");
      await usuarioEv.click(within(modal).getByRole("button", { name: /guardar/i }));

      await waitFor(() => {
        expect(actualizarSimulado).toHaveBeenCalledWith(UID_ANA, { name: "Ana María" });
      });
    });

    it("el nombre vacío no se envía", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      await usuarioEv.click(await screen.findByRole("button", { name: /editar nombre/i }));
      const modal = await screen.findByRole("dialog");
      await usuarioEv.clear(within(modal).getByLabelText(/^nombre/i));
      await usuarioEv.click(within(modal).getByRole("button", { name: /guardar/i }));

      expect(await within(modal).findByText(/el nombre es obligatorio/i)).toBeInTheDocument();
      expect(actualizarSimulado).not.toHaveBeenCalled();
    });
  });

  describe("tabla de roles", () => {
    it("muestra rol, proyecto y ambiente por nombre; 'Instancia' si ambos son nulos", async () => {
      renderizar(`/usuarios/${UID_ANA}`);

      expect(await filaDeRol("Administrador")).toHaveTextContent("Instancia");
      const lider = await filaDeRol("Líder Técnico");
      await waitFor(() => {
        expect(lider).toHaveTextContent("Tienda en línea");
      });
      expect(lider).toHaveTextContent("Todo el proyecto");
      const desarrollador = await filaDeRol("Desarrollador");
      await waitFor(() => {
        expect(desarrollador).toHaveTextContent("development");
      });
      expect(desarrollador).toHaveTextContent("Tienda en línea");
      expect(document.body.textContent).not.toContain(PID_TIENDA);
      expect(document.body.textContent).not.toContain(EID_DEV);
    });

    it("sin roles lo dice", async () => {
      asignacionesSimuladas.mockResolvedValue([]);
      renderizar(`/usuarios/${UID_ANA}`);

      expect(await screen.findByText(/no tiene roles asignados/i)).toBeInTheDocument();
    });
  });

  describe("asignar rol", () => {
    it("avisa que se cerrarán las sesiones del usuario (H-37)", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const modal = await abrirAsignar(usuarioEv);

      expect(modal).toHaveTextContent(AVISO_H37);
    });

    it("Desarrollador en un proyecto y ambiente → asignarRol con los tres identificadores", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Desarrollador");
      await elegirProyecto(usuarioEv, modal, "Tienda en línea");
      await within(modal).findByRole("option", { name: "development" });
      await usuarioEv.selectOptions(campo(modal, /^ambiente/i), "development");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      await waitFor(() => {
        expect(asignarSimulado).toHaveBeenCalledWith(UID_ANA, {
          role_id: DESARROLLADOR,
          project_id: PID_TIENDA,
          environment_id: EID_DEV,
        });
      });
      expect(exitoSimulado).toHaveBeenCalled();
      expect(cerrarSesion).not.toHaveBeenCalled();
    });

    it("sin ambiente, environment_id va nulo (todo el proyecto)", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Líder Técnico");
      await elegirProyecto(usuarioEv, modal, "Pagos");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      await waitFor(() => {
        expect(asignarSimulado).toHaveBeenCalledWith(UID_ANA, {
          role_id: LIDER_TECNICO,
          project_id: PID_PAGOS,
          environment_id: null,
        });
      });
    });

    it("Administrador de instancia → project_id y environment_id nulos (H-22)", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Administrador");
      await usuarioEv.selectOptions(
        campo(modal, /^proyecto/i),
        within(modal).getByRole("option", { name: /instancia/i }),
      );
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      await waitFor(() => {
        expect(asignarSimulado).toHaveBeenCalledWith(UID_ANA, {
          role_id: ADMINISTRADOR,
          project_id: null,
          environment_id: null,
        });
      });
    });

    it("el Administrador también puede tener alcance de proyecto", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Administrador");
      await elegirProyecto(usuarioEv, modal, "Pagos");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      await waitFor(() => {
        expect(asignarSimulado).toHaveBeenCalledWith(UID_ANA, {
          role_id: ADMINISTRADOR,
          project_id: PID_PAGOS,
          environment_id: null,
        });
      });
    });

    it.each(["Líder Técnico", "Desarrollador"])(
      "%s: no se ofrece 'Instancia' y sin proyecto no se envía (H-22)",
      async (nombreRol) => {
        const usuarioEv = userEvent.setup();
        renderizar(`/usuarios/${UID_ANA}`);
        const modal = await abrirAsignar(usuarioEv);

        await usuarioEv.selectOptions(campo(modal, /^rol/i), nombreRol);
        await within(modal).findByRole("option", { name: "Pagos" });

        expect(within(modal).queryByRole("option", { name: /instancia/i })).not.toBeInTheDocument();
        await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));
        expect(await within(modal).findByText(/elige un proyecto/i)).toBeInTheDocument();
        expect(asignarSimulado).not.toHaveBeenCalled();
      },
    );

    it("el ambiente se habilita al elegir proyecto, se llena con sus ambientes y se reinicia al cambiarlo", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);
      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Desarrollador");

      expect(campo(modal, /^ambiente/i)).toBeDisabled();

      await elegirProyecto(usuarioEv, modal, "Tienda en línea");
      await within(modal).findByRole("option", { name: "development" });
      expect(campo(modal, /^ambiente/i)).toBeEnabled();
      expect(ambientesSimulados).toHaveBeenCalledWith(PID_TIENDA);
      await usuarioEv.selectOptions(campo(modal, /^ambiente/i), "development");

      await elegirProyecto(usuarioEv, modal, "Pagos");
      await within(modal).findByRole("option", { name: "staging" });
      expect(within(modal).queryByRole("option", { name: "development" })).not.toBeInTheDocument();
      const ambienteElegido = campo(modal, /^ambiente/i).selectedOptions[0];
      expect(ambienteElegido).toHaveTextContent(/todo el proyecto/i);
    });

    it.each([
      [409, "Conflicto", "el usuario ya tiene esa asignación"],
      [422, "Ambiente inválido", "el ambiente no pertenece al proyecto"],
    ])("%i: muestra title y detail en el modal", async (status, title, detail) => {
      asignarSimulado.mockReset().mockRejectedValue(problema(status, title, detail));
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Desarrollador");
      await elegirProyecto(usuarioEv, modal, "Tienda en línea");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      const alerta = await within(modal).findByRole("alert");
      expect(alerta).toHaveTextContent(title);
      expect(alerta).toHaveTextContent(detail);
      expect(cerrarSesion).not.toHaveBeenCalled();
    });
  });

  describe("quitar rol", () => {
    async function pedirQuitar(usuarioEv: Usuario, nombreRol: string) {
      const fila = await filaDeRol(nombreRol);
      await usuarioEv.click(within(fila).getByRole("button", { name: /quitar/i }));
      return screen.findByRole("dialog");
    }

    it("la confirmación nombra el rol y avisa que se cerrarán las sesiones (H-37)", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const dialogo = await pedirQuitar(usuarioEv, "Desarrollador");

      expect(dialogo).toHaveTextContent("Desarrollador");
      expect(dialogo).toHaveTextContent(AVISO_H37);
    });

    it("cancelar no quita", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const dialogo = await pedirQuitar(usuarioEv, "Desarrollador");
      await usuarioEv.click(within(dialogo).getByRole("button", { name: /cancelar/i }));

      expect(quitarSimulado).not.toHaveBeenCalled();
    });

    it("confirmar llama a quitarAsignacion con el id de la asignación", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const dialogo = await pedirQuitar(usuarioEv, "Desarrollador");
      await usuarioEv.click(within(dialogo).getByRole("button", { name: /^quitar$/i }));

      await waitFor(() => {
        expect(quitarSimulado).toHaveBeenCalledWith(UID_ANA, AID_DEV);
      });
      expect(cerrarSesion).not.toHaveBeenCalled();
    });

    it("409 del último Administrador (H-59): se muestra el detail", async () => {
      const detail = "no se puede quitar el rol al último Administrador";
      quitarSimulado.mockReset().mockRejectedValue(problema(409, "Conflicto", detail));
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const dialogo = await pedirQuitar(usuarioEv, "Administrador");
      await usuarioEv.click(within(dialogo).getByRole("button", { name: /^quitar$/i }));

      expect(await within(dialogo).findByRole("alert")).toHaveTextContent(detail);
    });
  });

  describe("el Administrador se modifica a sí mismo (H-37)", () => {
    beforeEach(() => {
      asignacionesSimuladas.mockResolvedValue([
        rol(AID_ADMIN, ADMINISTRADOR, null),
        rol(AID_LIDER, LIDER_TECNICO, PID_TIENDA),
      ]);
    });

    it("el aviso dice que tendrá que iniciar sesión de nuevo", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_YO}`);

      const modal = await abrirAsignar(usuarioEv);

      expect(modal).toHaveTextContent(/tendrás que iniciar sesión/i);
    });

    it("tras asignarse un rol cierra la sesión y va al login", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_YO}`);
      const modal = await abrirAsignar(usuarioEv);

      await usuarioEv.selectOptions(campo(modal, /^rol/i), "Desarrollador");
      await elegirProyecto(usuarioEv, modal, "Pagos");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^asignar$/i }));

      expect(await screen.findByText("Inicio de sesión simulado")).toBeInTheDocument();
      expect(asignarSimulado).toHaveBeenCalledWith(UID_YO, {
        role_id: DESARROLLADOR,
        project_id: PID_PAGOS,
        environment_id: null,
      });
      expect(cerrarSesion).toHaveBeenCalledTimes(1);
    });

    it("tras quitarse un rol cierra la sesión y va al login", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_YO}`);
      const fila = await filaDeRol("Líder Técnico");

      await usuarioEv.click(within(fila).getByRole("button", { name: /quitar/i }));
      const dialogo = await screen.findByRole("dialog");
      await usuarioEv.click(within(dialogo).getByRole("button", { name: /^quitar$/i }));

      expect(await screen.findByText("Inicio de sesión simulado")).toBeInTheDocument();
      expect(quitarSimulado).toHaveBeenCalledWith(UID_YO, AID_LIDER);
      expect(cerrarSesion).toHaveBeenCalledTimes(1);
    });

    it("si el API lo rechaza, la sesión sigue abierta", async () => {
      quitarSimulado
        .mockReset()
        .mockRejectedValue(
          problema(409, "Conflicto", "no se puede quitar el rol al último Administrador"),
        );
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_YO}`);
      const fila = await filaDeRol("Administrador");

      await usuarioEv.click(within(fila).getByRole("button", { name: /quitar/i }));
      const dialogo = await screen.findByRole("dialog");
      await usuarioEv.click(within(dialogo).getByRole("button", { name: /^quitar$/i }));

      await within(dialogo).findByRole("alert");
      expect(cerrarSesion).not.toHaveBeenCalled();
      expect(screen.queryByText("Inicio de sesión simulado")).not.toBeInTheDocument();
    });
  });

  describe("permisos de la interfaz (users:manage de instancia)", () => {
    it.each([
      ["un Desarrollador", [asignacionMe(DESARROLLADOR, PID_TIENDA)]],
      ["un Administrador solo de proyecto", [asignacionMe(ADMINISTRADOR, PID_TIENDA)]],
    ])("con %s no hay botones de gestión", async (_caso, asignaciones) => {
      conSesion(asignaciones);
      renderizar(`/usuarios/${UID_ANA}`);

      await filaDeRol("Desarrollador");
      expect(screen.queryByRole("button", { name: /editar nombre/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /asignar rol/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /quitar/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /desbloquear/i })).not.toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /restablecer contraseña/i }),
      ).not.toBeInTheDocument();
    });
  });

  describe("desbloquear (H-78)", () => {
    const ANA_BLOQUEADA = { ...ANA, locked_until: BLOQUEO };

    it("con la cuenta bloqueada muestra 'Bloqueada hasta' y el botón", async () => {
      obtenerSimulado.mockResolvedValue(ANA_BLOQUEADA);
      renderizar(`/usuarios/${UID_ANA}`);

      expect(await screen.findByText(/bloqueada hasta/i)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /^desbloquear$/i })).toBeInTheDocument();
    });

    it("sin bloqueo no hay botón ni dato de bloqueo", async () => {
      renderizar(`/usuarios/${UID_ANA}`);

      await filaDeRol("Desarrollador");
      expect(screen.queryByText(/bloqueada hasta/i)).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /desbloquear/i })).not.toBeInTheDocument();
    });

    it("pide confirmación, llama a desbloquearUsuario y vuelve a pedir el usuario", async () => {
      const usuarioEv = userEvent.setup();
      obtenerSimulado.mockResolvedValueOnce(ANA_BLOQUEADA).mockResolvedValue(ANA);
      renderizar(`/usuarios/${UID_ANA}`);

      await usuarioEv.click(await screen.findByRole("button", { name: /^desbloquear$/i }));
      const modal = await screen.findByRole("dialog");
      expect(desbloquearSimulado).not.toHaveBeenCalled();
      await usuarioEv.click(within(modal).getByRole("button", { name: /^desbloquear$/i }));

      await waitFor(() => {
        expect(desbloquearSimulado).toHaveBeenCalledWith(UID_ANA);
      });
      await waitFor(() => {
        expect(screen.queryByText(/bloqueada hasta/i)).not.toBeInTheDocument();
      });
      expect(obtenerSimulado.mock.calls.length).toBeGreaterThanOrEqual(2);
      expect(exitoSimulado).toHaveBeenCalled();
      expect(cerrarSesion).not.toHaveBeenCalled();
    });

    it("el 409 se muestra con su detail", async () => {
      const usuarioEv = userEvent.setup();
      obtenerSimulado.mockResolvedValue(ANA_BLOQUEADA);
      desbloquearSimulado.mockRejectedValue(
        problema(409, "Conflicto", "no puedes desbloquear tu propia cuenta"),
      );
      renderizar(`/usuarios/${UID_ANA}`);

      await usuarioEv.click(await screen.findByRole("button", { name: /^desbloquear$/i }));
      const modal = await screen.findByRole("dialog");
      await usuarioEv.click(within(modal).getByRole("button", { name: /^desbloquear$/i }));

      expect(
        await within(modal).findByText("no puedes desbloquear tu propia cuenta"),
      ).toBeInTheDocument();
    });
  });

  describe("restablecer contraseña (H-78)", () => {
    async function abrirRestablecer(usuarioEv: Usuario): Promise<HTMLElement> {
      await usuarioEv.click(
        await screen.findByRole("button", { name: /^restablecer contraseña$/i }),
      );
      return screen.findByRole("dialog");
    }

    function campoTemporal(modal: HTMLElement): HTMLInputElement {
      return within(modal).getByLabelText(/contraseña temporal/i) as HTMLInputElement;
    }

    it("avisa que se cerrarán las sesiones del usuario (H-37)", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const modal = await abrirRestablecer(usuarioEv);

      expect(within(modal).getByText(AVISO_H37)).toBeInTheDocument();
      expect(campoTemporal(modal)).toHaveAttribute("type", "password");
      expect(campoTemporal(modal)).toHaveAttribute("autocomplete", "new-password");
    });

    it("envía la contraseña temporal y no la deja en ninguna caché de TanStack", async () => {
      const usuarioEv = userEvent.setup();
      const queryClient = renderizar(`/usuarios/${UID_ANA}`);

      const modal = await abrirRestablecer(usuarioEv);
      await usuarioEv.type(campoTemporal(modal), TEMPORAL);
      await usuarioEv.click(within(modal).getByRole("button", { name: /^restablecer$/i }));

      await waitFor(() => {
        expect(restablecerSimulado).toHaveBeenCalledWith(UID_ANA, TEMPORAL);
      });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      });
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
      const consultas = queryClient
        .getQueryCache()
        .getAll()
        .map((q) => ({ llave: q.queryKey, datos: q.state.data }));
      expect(JSON.stringify(consultas)).not.toContain(TEMPORAL);
      expect(exitoSimulado).toHaveBeenCalled();
      expect(JSON.stringify(exitoSimulado.mock.calls)).not.toContain(TEMPORAL);
      expect(screen.queryByDisplayValue(TEMPORAL)).not.toBeInTheDocument();
    });

    it("sin contraseña no se envía", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      const modal = await abrirRestablecer(usuarioEv);
      await usuarioEv.click(within(modal).getByRole("button", { name: /^restablecer$/i }));

      expect(await within(modal).findByText("La contraseña es obligatoria.")).toBeInTheDocument();
      expect(restablecerSimulado).not.toHaveBeenCalled();
    });

    it("cerrar el diálogo descarta lo tecleado", async () => {
      const usuarioEv = userEvent.setup();
      renderizar(`/usuarios/${UID_ANA}`);

      let modal = await abrirRestablecer(usuarioEv);
      await usuarioEv.type(campoTemporal(modal), TEMPORAL);
      await usuarioEv.click(within(modal).getByRole("button", { name: "Cerrar" }));
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      });

      modal = await abrirRestablecer(usuarioEv);
      expect(campoTemporal(modal)).toHaveValue("");
      expect(restablecerSimulado).not.toHaveBeenCalled();
    });

    it("el 422 de la política se muestra con su detail, sin la contraseña", async () => {
      const usuarioEv = userEvent.setup();
      restablecerSimulado.mockRejectedValue(
        problema(
          422,
          "Error semántico",
          "la contraseña aparece en la lista de contraseñas comunes",
        ),
      );
      renderizar(`/usuarios/${UID_ANA}`);

      const modal = await abrirRestablecer(usuarioEv);
      await usuarioEv.type(campoTemporal(modal), TEMPORAL);
      await usuarioEv.click(within(modal).getByRole("button", { name: /^restablecer$/i }));

      const alerta = await within(modal).findByRole("alert");
      expect(alerta).toHaveTextContent("la contraseña aparece en la lista de contraseñas comunes");
      expect(alerta).not.toHaveTextContent(TEMPORAL);
      expect(exitoSimulado).not.toHaveBeenCalled();
    });
  });

  describe("sobre uno mismo no hay desbloqueo ni restablecimiento (H-78)", () => {
    it("en el propio detalle no aparecen los botones", async () => {
      obtenerSimulado.mockResolvedValue({ ...YO, locked_until: BLOQUEO });
      renderizar(`/usuarios/${UID_YO}`);

      await filaDeRol("Desarrollador");
      expect(screen.queryByRole("button", { name: /desbloquear/i })).not.toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /restablecer contraseña/i }),
      ).not.toBeInTheDocument();
    });
  });
});
