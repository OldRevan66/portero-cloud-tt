// Rutas del API con los identificadores codificados (hallazgo H-62; OWASP ASVS 4.0.3 V5.3).
//
// Los identificadores llegan de la URL del Dashboard (`useParams`), que cualquiera puede
// escribir, y React Router decodifica `%2F` como "/". Si se pegan tal cual en la ruta de la
// petición, "<id>/value" convierte GET /secrets/{id} en GET /secrets/{id}/value (path traversal
// del lado del cliente). Aquí cada valor se codifica como UN segmento con `encodeURIComponent`.
//
// "." y ".." no los cambia `encodeURIComponent`, y el navegador los resuelve aunque vengan
// codificados (%2E%2E): subirían de nivel en la ruta. Por eso se rechazan, igual que un valor
// vacío (dejaría "//"). Es una segunda capa: las páginas ya validan que sean UUID.

const SEGMENTOS_PROHIBIDOS = new Set(["", ".", ".."]);

/**
 * Plantilla etiquetada para rutas del API: ruta`/secrets/${sid}/value`.
 * Lanza `Error` si un valor es "", "." o "..".
 */
export function ruta(partes: TemplateStringsArray, ...valores: string[]): string {
  const codificados = valores.map((valor) => {
    if (SEGMENTOS_PROHIBIDOS.has(valor)) {
      throw new Error("Identificador inválido en la ruta del API");
    }
    return encodeURIComponent(valor);
  });
  // String.raw intercala las partes fijas de la plantilla con los valores ya codificados.
  return String.raw({ raw: partes }, ...codificados);
}
