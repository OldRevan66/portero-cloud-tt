// RF-028 y CU-06: bitácora filtrable (spec §4.3, §8.1, §8.2).
// - Los filtros (verbo, resultado, actor, fechas, proyecto) se traducen a los query params de
//   GET /operations; los vacíos no se envían (el API respondería 400 a un UUID vacío).
// - Las fechas se capturan en hora de México y viajan en ISO 8601 con zona, como exige el API.
//   México no tiene horario de verano desde 2022: el desfase es fijo, -06:00. "Desde" empieza en
//   el segundo :00 del minuto y "Hasta" termina en el :59 (los dos extremos son inclusivos).
// - "Cargar más" pide la página siguiente con el cursor opaco del API (spec §1).
// - "Verificar integridad" (POST /operations/verify-chain) solo para el Administrador: audit:read
//   de instancia, `permisosEn(me, null, null)`. El Líder Técnico ve la bitácora de sus proyectos,
//   pero no verifica la cadena (H-23b). Es conveniencia de interfaz; el backend responde 403.
// - H-81: el resultado dice la fecha de la última firma válida del cierre, avisa si tiene más de
//   48 h, si aún no hay firmas o si la firma no está configurada, y lista las firmas inválidas o
//   borradas.
// - RF-021 (H-83): "Exportar CSV" y "Exportar JSON" descargan con los filtros **aplicados** (no
//   con lo que el formulario tenga sin aplicar). El Blob no pasa por la caché: se crea una URL
//   con URL.createObjectURL, se hace clic en un <a download> y la URL se revoca enseguida.
// Los selectores son nativos (NativeSelect de Mantine): accesibles y fáciles de probar.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "../api/schema";
import type { Assignment, Me } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { listarProyectos } from "../projects/projectsApi";
import { notificarError } from "../api/problem";
import { exportarOperaciones, listarOperaciones, verificarCadena } from "./operationsApi";
import { OperationsTable } from "./OperationsTable";

vi.mock("../auth/SessionProvider", () => ({ useSession: vi.fn() }));
vi.mock("../projects/projectsApi", () => ({ listarProyectos: vi.fn() }));
vi.mock("./operationsApi", () => ({
  listarOperaciones: vi.fn(),
  verificarCadena: vi.fn(),
  exportarOperaciones: vi.fn(),
}));
vi.mock("../api/problem", async (original) => ({
  ...(await original<typeof import("../api/problem")>()),
  notificarError: vi.fn(),
}));

type OperationOut = components["schemas"]["OperationOut"];
type ChainReport = components["schemas"]["ChainReport"];

/** Reporte de verify-chain íntegro y sin firma configurada; cada prueba cambia lo que necesita. */
function reporte(cambios: Partial<ChainReport> = {}): ChainReport {
  return {
    verified_from: 1,
    verified_to: 42,
    total: 42,
    ok: true,
    broken: [],
    last_hash: "a".repeat(64),
    signing_configured: false,
    signatures_total: 0,
    invalid_signatures: [],
    missing_signatures: [],
    last_signed_at: null,
    last_signed_audit_id: null,
    ...cambios,
  };
}

const HORA = 60 * 60 * 1000;
const FIRMA = "3f2a1b0c-9d8e-4f7a-8b6c-5d4e3f2a1b0c";

const sesionSimulada = vi.mocked(useSession);
const proyectosSimulados = vi.mocked(listarProyectos);
const operacionesSimuladas = vi.mocked(listarOperaciones);
const verificarSimulado = vi.mocked(verificarCadena);
const exportarSimulado = vi.mocked(exportarOperaciones);
const notificarSimulado = vi.mocked(notificarError);

const ADMINISTRADOR = 1;
const LIDER_TECNICO = 2;
const ACTOR = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b";
const PROYECTO = "0b7e1c3d-5f6a-4b8c-9d0e-1f2a3b4c5d6e";

function operacion(
  id: number,
  verb: string,
  event_timestamp = "2026-10-11T16:02:00Z",
): OperationOut {
  return {
    id,
    event_timestamp,
    actor_user_id: ACTOR,
    actor_type: "human",
    actor_ref: "ana@example.com",
    verb,
    resource_type: "secret",
    resource_id: null,
    result: "success",
    ip_address: "127.0.0.1",
    user_agent: null,
    project_id: PROYECTO,
    environment_id: null,
    details: null,
    previous_hash: null,
    current_hash: "0".repeat(64),
  };
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

const comoAdministrador = () =>
  conSesion([
    { id: "a-1", role_id: ADMINISTRADOR, role: "", project_id: null, environment_id: null },
  ]);
const comoLider = () =>
  conSesion([
    { id: "a-2", role_id: LIDER_TECNICO, role: "", project_id: PROYECTO, environment_id: null },
  ]);

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <OperationsTable />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

/** Filtros con los que se hizo la última petición de la primera página. */
function ultimosFiltros(): unknown {
  return operacionesSimuladas.mock.lastCall?.[0];
}

describe("OperationsTable", () => {
  beforeEach(() => {
    sesionSimulada.mockReset();
    proyectosSimulados.mockReset();
    operacionesSimuladas.mockReset();
    verificarSimulado.mockReset();
    exportarSimulado.mockReset();
    notificarSimulado.mockReset();
    proyectosSimulados.mockResolvedValue([
      {
        id: PROYECTO,
        name: "facturacion",
        description: null,
        created_at: "2026-10-01T10:00:00Z",
        updated_at: "2026-10-01T10:00:00Z",
      },
    ]);
    operacionesSimuladas.mockResolvedValue({ items: [operacion(1, "login")], next_cursor: null });
    comoLider();
  });

  it("la carga inicial no lleva filtros ni cursor", async () => {
    renderizar();

    await vi.waitFor(() => {
      expect(operacionesSimuladas).toHaveBeenCalledWith({}, null);
    });
  });

  it("verbo y resultado se traducen a `verb` y `result`", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");

    await usuario.selectOptions(screen.getByLabelText(/^verbo/i), "rotate_secret");
    await usuario.selectOptions(screen.getByLabelText(/^resultado/i), "failure");
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));

    await vi.waitFor(() => {
      expect(ultimosFiltros()).toEqual({ verb: "rotate_secret", result: "failure" });
    });
  });

  it.each([
    ["unlock_user", "Desbloquear usuario"],
    ["reset_password", "Restablecer contraseña"],
    ["sign_chain", "Firmar cierre"],
    ["export_operations", "Exportar bitácora"],
  ])("el filtro de verbo ofrece %s como %j", async (verbo, etiqueta) => {
    renderizar();
    await screen.findByText("login");

    const opcion = screen.getByRole("option", { name: etiqueta });
    expect(opcion).toHaveValue(verbo);
  });

  it("el actor se envía como `actor_user_id`; un campo vacío no se envía", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");
    const actor = screen.getByLabelText(/^actor/i);

    await usuario.type(actor, `  ${ACTOR}  `);
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));
    await vi.waitFor(() => {
      expect(ultimosFiltros()).toEqual({ actor_user_id: ACTOR });
    });

    await usuario.clear(actor);
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));
    await vi.waitFor(() => {
      expect(ultimosFiltros()).toEqual({});
    });
  });

  it("las fechas en hora de México viajan en ISO 8601 con zona -06:00", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");

    fireEvent.change(screen.getByLabelText(/^desde/i), { target: { value: "2026-10-01T00:00" } });
    fireEvent.change(screen.getByLabelText(/^hasta/i), { target: { value: "2026-10-11T23:59" } });
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));

    await vi.waitFor(() => {
      expect(ultimosFiltros()).toEqual({
        from: "2026-10-01T00:00:00-06:00",
        to: "2026-10-11T23:59:59-06:00",
      });
    });
  });

  it("el proyecto se elige de los proyectos visibles y se envía como `project_id`", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");
    await screen.findByRole("option", { name: "facturacion" });

    await usuario.selectOptions(screen.getByLabelText(/^proyecto/i), PROYECTO);
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));

    await vi.waitFor(() => {
      expect(ultimosFiltros()).toEqual({ project_id: PROYECTO });
    });
  });

  it("'Cargar más' pide la página siguiente con el cursor y conserva los filtros", async () => {
    operacionesSimuladas.mockReset();
    operacionesSimuladas
      .mockResolvedValueOnce({ items: [operacion(2, "login")], next_cursor: null })
      .mockResolvedValueOnce({ items: [operacion(2, "rotate_secret")], next_cursor: "c-2" })
      .mockResolvedValueOnce({ items: [operacion(1, "create_secret")], next_cursor: null });
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");
    expect(screen.queryByRole("button", { name: /cargar más/i })).not.toBeInTheDocument();

    await usuario.selectOptions(screen.getByLabelText(/^resultado/i), "success");
    await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));
    await screen.findByText("rotate_secret");
    await usuario.click(screen.getByRole("button", { name: /cargar más/i }));

    expect(await screen.findByText("create_secret")).toBeInTheDocument();
    expect(screen.getByText("rotate_secret")).toBeInTheDocument();
    expect(operacionesSimuladas).toHaveBeenLastCalledWith({ result: "success" }, "c-2");
    expect(screen.queryByRole("button", { name: /cargar más/i })).not.toBeInTheDocument();
  });

  it("muestra la fecha en hora local de México con formato legible", async () => {
    renderizar();

    // 16:02 UTC = 10:02 en la Ciudad de México (UTC-6).
    expect(await screen.findByText(/11\/10\/26, 10:02/)).toBeInTheDocument();
    expect(screen.queryByText(/2026-10-11T16:02/)).not.toBeInTheDocument();
  });

  it("el Líder Técnico no ve 'Verificar integridad'", async () => {
    renderizar();
    await screen.findByText("login");

    expect(screen.queryByRole("button", { name: /verificar integridad/i })).not.toBeInTheDocument();
  });

  it("el Administrador verifica y ve que la bitácora está íntegra", async () => {
    comoAdministrador();
    verificarSimulado.mockResolvedValueOnce(reporte());
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(await screen.findByRole("button", { name: /verificar integridad/i }));

    const resultado = await screen.findByRole("alert");
    expect(resultado).toHaveTextContent(/íntegra/i);
    expect(resultado).toHaveTextContent(/42 registros/);
    expect(verificarSimulado).toHaveBeenCalledTimes(1);
  });

  it("tras verificar vuelve a pedir la bitácora: verify_chain dejó un evento nuevo", async () => {
    comoAdministrador();
    verificarSimulado.mockResolvedValueOnce(reporte());
    const usuario = userEvent.setup();
    renderizar();
    await screen.findByText("login");
    operacionesSimuladas.mockResolvedValue({
      items: [operacion(2, "verify_chain"), operacion(1, "login")],
      next_cursor: null,
    });

    await usuario.click(screen.getByRole("button", { name: /verificar integridad/i }));

    // "verify_chain" también es una opción del selector de verbo: se busca en la tabla.
    expect(await screen.findByRole("cell", { name: "verify_chain" })).toBeInTheDocument();
    expect(operacionesSimuladas).toHaveBeenCalledTimes(2);
  });

  it("si la cadena está rota, dice qué fila fue alterada", async () => {
    comoAdministrador();
    verificarSimulado.mockResolvedValueOnce(
      reporte({ ok: false, broken: [17], last_hash: "b".repeat(64) }),
    );
    const usuario = userEvent.setup();
    renderizar();

    await usuario.click(await screen.findByRole("button", { name: /verificar integridad/i }));

    const resultado = await screen.findByRole("alert");
    expect(resultado).toHaveTextContent(/alterada/i);
    expect(resultado).toHaveTextContent(/17/);
    expect(resultado).not.toHaveTextContent(/íntegra/i);
  });

  describe("firma diaria del cierre (H-81)", () => {
    async function verificarCon(r: ChainReport) {
      comoAdministrador();
      verificarSimulado.mockResolvedValueOnce(r);
      const usuario = userEvent.setup();
      renderizar();
      await usuario.click(await screen.findByRole("button", { name: /verificar integridad/i }));
      return screen.findByRole("alert");
    }

    it("con una firma reciente dice su fecha, hasta qué registro cubre y qué queda fuera", async () => {
      const resultado = await verificarCon(
        reporte({
          signing_configured: true,
          signatures_total: 3,
          last_signed_at: new Date(Date.now() - 2 * HORA).toISOString(),
          last_signed_audit_id: 40,
        }),
      );

      expect(resultado).toHaveTextContent(/íntegra/i);
      expect(resultado).toHaveTextContent(/última firma válida/i);
      expect(resultado).toHaveTextContent(/registro #40/);
      expect(resultado).toHaveTextContent(/posteriores solo los protege la cadena/i);
      expect(resultado).not.toHaveTextContent(/no se ha ejecutado/i);
    });

    it("si la última firma tiene más de 48 h, avisa que la tarea programada no corrió", async () => {
      const resultado = await verificarCon(
        reporte({
          signing_configured: true,
          signatures_total: 1,
          last_signed_at: new Date(Date.now() - 72 * HORA).toISOString(),
          last_signed_audit_id: 30,
        }),
      );

      expect(resultado).toHaveTextContent(/la firma diaria no se ha ejecutado desde/i);
      expect(resultado).toHaveTextContent(/tarea programada/i);
    });

    it("configurada pero sin firmas, lo dice", async () => {
      const resultado = await verificarCon(reporte({ signing_configured: true }));

      expect(resultado).toHaveTextContent(/aún no hay firmas del cierre/i);
    });

    it("sin la llave pública, dice que la firma diaria no está configurada", async () => {
      const resultado = await verificarCon(reporte());

      expect(resultado).toHaveTextContent(/la firma diaria no está configurada/i);
      expect(resultado).not.toHaveTextContent(/última firma válida/i);
    });

    it("una firma inválida marca la bitácora como alterada y da su id", async () => {
      const resultado = await verificarCon(
        reporte({
          ok: false,
          signing_configured: true,
          signatures_total: 2,
          invalid_signatures: [FIRMA],
        }),
      );

      expect(resultado).toHaveTextContent(/alterada/i);
      expect(resultado).toHaveTextContent(/firmas inválidas/i);
      expect(resultado).toHaveTextContent(FIRMA);
      expect(resultado).not.toHaveTextContent(/íntegra/i);
      expect(resultado).not.toHaveTextContent(/filas? alteradas?:/i);
    });

    it("una firma borrada se reporta como faltante", async () => {
      const resultado = await verificarCon(
        reporte({ ok: false, signing_configured: true, missing_signatures: [FIRMA] }),
      );

      expect(resultado).toHaveTextContent(/firmas borradas/i);
      expect(resultado).toHaveTextContent(FIRMA);
    });
  });

  describe("Exportar (RF-021)", () => {
    const URL_BLOB = "blob:http://localhost/exportacion";
    let crearUrl: ReturnType<typeof vi.fn>;
    let revocarUrl: ReturnType<typeof vi.fn>;
    let enlaces: HTMLAnchorElement[];

    beforeEach(() => {
      crearUrl = vi.fn(() => URL_BLOB);
      revocarUrl = vi.fn();
      URL.createObjectURL = crearUrl as unknown as typeof URL.createObjectURL;
      URL.revokeObjectURL = revocarUrl as unknown as typeof URL.revokeObjectURL;
      enlaces = [];
      vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
        this: HTMLAnchorElement,
      ) {
        enlaces.push(this);
      });
      exportarSimulado.mockResolvedValue(new Blob(["id\r\n"], { type: "text/csv" }));
    });

    it.each([
      ["el Líder Técnico", comoLider],
      ["el Administrador", comoAdministrador],
    ])("%s ve los dos botones de exportación", async (_rol, como) => {
      como();
      renderizar();
      await screen.findByText("login");

      expect(screen.getByRole("button", { name: /^exportar csv$/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /^exportar json$/i })).toBeInTheDocument();
    });

    it("exporta con los filtros aplicados, no con lo que falta aplicar", async () => {
      const usuario = userEvent.setup();
      renderizar();
      await screen.findByText("login");

      await usuario.selectOptions(screen.getByLabelText(/^verbo/i), "rotate_secret");
      await usuario.click(screen.getByRole("button", { name: /^filtrar$/i }));
      await usuario.selectOptions(screen.getByLabelText(/^resultado/i), "failure"); // sin aplicar
      await usuario.click(screen.getByRole("button", { name: /^exportar csv$/i }));

      await vi.waitFor(() => {
        expect(exportarSimulado).toHaveBeenCalledWith({ verb: "rotate_secret" }, "csv");
      });
    });

    it("descarga el Blob con una URL temporal que luego revoca", async () => {
      const usuario = userEvent.setup();
      const blob = new Blob(["id\r\n"], { type: "text/csv" });
      exportarSimulado.mockResolvedValue(blob);
      renderizar();
      await screen.findByText("login");

      await usuario.click(screen.getByRole("button", { name: /^exportar csv$/i }));

      await vi.waitFor(() => {
        expect(revocarUrl).toHaveBeenCalledWith(URL_BLOB);
      });
      expect(crearUrl).toHaveBeenCalledWith(blob);
      expect(enlaces).toHaveLength(1);
      expect(enlaces[0]?.href).toBe(URL_BLOB);
      expect(enlaces[0]?.download).toMatch(/^bitacora-\d{4}-\d{2}-\d{2}\.csv$/);
      expect(enlaces[0]?.isConnected).toBe(false); // el <a> temporal no se queda en el DOM
    });

    it("JSON pide `json` y descarga un .json", async () => {
      const usuario = userEvent.setup();
      exportarSimulado.mockResolvedValue(new Blob(["[]"], { type: "application/json" }));
      renderizar();
      await screen.findByText("login");

      await usuario.click(screen.getByRole("button", { name: /^exportar json$/i }));

      await vi.waitFor(() => {
        expect(revocarUrl).toHaveBeenCalledWith(URL_BLOB);
      });
      expect(exportarSimulado).toHaveBeenCalledWith({}, "json");
      expect(enlaces[0]?.download).toMatch(/^bitacora-\d{4}-\d{2}-\d{2}\.json$/);
    });

    it("si el API falla, avisa y no crea ninguna URL", async () => {
      const usuario = userEvent.setup();
      const error = new Error("403");
      exportarSimulado.mockRejectedValue(error);
      renderizar();
      await screen.findByText("login");

      await usuario.click(screen.getByRole("button", { name: /^exportar csv$/i }));

      await vi.waitFor(() => {
        expect(notificarSimulado).toHaveBeenCalled();
      });
      expect(notificarSimulado.mock.calls[0]?.[0]).toBe(error);
      expect(crearUrl).not.toHaveBeenCalled();
      expect(enlaces).toHaveLength(0);
    });
  });
});
