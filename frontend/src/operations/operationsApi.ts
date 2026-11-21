// Llamadas al API REST Gateway para la bitácora del Servicio de Registro de Operaciones
// (CU-06, RF-016 a RF-021, RF-028; spec §4.3, §5). Solo metadatos de eventos: `details` nunca
// lleva valores (H-12), así que las consultas pueden pasar por TanStack Query (spec §8.4).
import { api } from "../api/client";
import { leerProblemaDeBlob } from "../api/problem";
import type { components, operations } from "../api/schema";

export type OperationOut = components["schemas"]["OperationOut"];
export type OperationPage = components["schemas"]["OperationPageOut"];
export type ChainReport = components["schemas"]["ChainReport"];

type ParametrosApi = NonNullable<
  operations["list_operations_api_v1_operations_get"]["parameters"]["query"]
>;

/** Filtros de GET /operations (spec §4.3); la paginación (`limit`, `cursor`) va aparte. */
export type FiltrosOperaciones = Omit<ParametrosApi, "limit" | "cursor">;

/** Registros por página (el API admite de 1 a 100). */
export const TAMANO_PAGINA_OPERACIONES = 25;

/** Formatos de GET /operations/export (RF-021). */
export type FormatoExportacion = "csv" | "json";

/** Los filtros como query params; los vacíos no se envían (el API respondería 400). */
function aParams(filtros: FiltrosOperaciones): Record<string, string | number> {
  const params: Record<string, string | number> = {};
  for (const [clave, valor] of Object.entries(filtros)) {
    if (typeof valor === "string") {
      params[clave] = valor;
    }
  }
  return params;
}

/** GET /operations: una página, del registro más reciente al más antiguo (cursor opaco). */
export async function listarOperaciones(
  filtros: FiltrosOperaciones,
  cursor: string | null,
): Promise<OperationPage> {
  const params: Record<string, string | number> = {
    ...aParams(filtros),
    limit: TAMANO_PAGINA_OPERACIONES,
  };
  if (cursor !== null) {
    params.cursor = cursor;
  }
  const { data } = await api.get<OperationPage>("/operations", { params });
  return data;
}

/**
 * POST /operations/verify-chain (RF-021): recalcula la cadena de hashes completa. Solo el
 * Administrador (audit:read de instancia, H-23b); el backend registra `verify_chain`.
 */
export async function verificarCadena(): Promise<ChainReport> {
  const { data } = await api.post<ChainReport>("/operations/verify-chain");
  return data;
}

/**
 * GET /operations/export (RF-021, H-83): la bitácora completa con los mismos filtros, como Blob
 * para descargarlo. El backend registra `export_operations`. Un error también llega como Blob:
 * se lee para que la notificación muestre el `title` y el `detail` del API.
 */
export async function exportarOperaciones(
  filtros: FiltrosOperaciones,
  formato: FormatoExportacion,
): Promise<Blob> {
  try {
    const { data } = await api.get<Blob>("/operations/export", {
      params: { ...aParams(filtros), format: formato },
      responseType: "blob",
    });
    return data;
  } catch (error) {
    await leerProblemaDeBlob(error);
    throw error;
  }
}
