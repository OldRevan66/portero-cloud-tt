// Errores del API en el Dashboard (RF-029, spec §6, Cap. 6 §Manejo de errores).
//
// El backend responde problem+json (RFC 9457) con `title` y `detail` en español, ya limpios de
// datos internos. El Dashboard muestra solo esos dos campos. No usa `error.message` de Axios
// (trae la URL y está en inglés) ni nada de `error.config` (lleva el cuerpo enviado, que puede
// ser el valor de un secreto).
import { notifications } from "@mantine/notifications";
import { isAxiosError } from "axios";

export interface Problema {
  titulo: string;
  detalle: string | null;
  /** Código HTTP, o null si no hubo respuesta. */
  status: number | null;
}

function esProblemJson(data: unknown): data is { title: string; detail?: unknown } {
  return (
    typeof data === "object" &&
    data !== null &&
    "title" in data &&
    typeof (data as { title: unknown }).title === "string"
  );
}

/** Traduce cualquier error a un mensaje en español apto para mostrarse (RF-029). */
export function problemaDe(error: unknown): Problema {
  if (!isAxiosError(error)) {
    return {
      titulo: "Error inesperado",
      detalle: "Ocurrió un error inesperado. Inténtalo de nuevo.",
      status: null,
    };
  }
  const respuesta = error.response;
  if (respuesta === undefined) {
    return {
      titulo: "Sin conexión",
      detalle: "No se pudo contactar al servidor. Revisa tu conexión e inténtalo de nuevo.",
      status: null,
    };
  }
  if (esProblemJson(respuesta.data)) {
    const { title, detail } = respuesta.data;
    return {
      titulo: title,
      detalle: typeof detail === "string" ? detail : null,
      status: respuesta.status,
    };
  }
  return {
    titulo: "Error del servidor",
    detalle: `El servidor respondió con el código ${respuesta.status}.`,
    status: respuesta.status,
  };
}

/**
 * RF-021: una petición con `responseType: "blob"` (la exportación de la bitácora) recibe también
 * el cuerpo de un error como Blob. Si es problem+json, lo lee y lo deja como objeto en
 * `error.response.data`, para que `problemaDe` muestre su `title` y `detail`. Devuelve el mismo
 * error; si no hay Blob JSON, lo deja como estaba.
 */
export async function leerProblemaDeBlob(error: unknown): Promise<unknown> {
  if (!isAxiosError(error) || error.response === undefined) {
    return error;
  }
  const cuerpo: unknown = error.response.data;
  if (!(cuerpo instanceof Blob) || !cuerpo.type.includes("json")) {
    return error;
  }
  try {
    error.response.data = JSON.parse(await cuerpo.text()) as unknown;
  } catch {
    // Cuerpo ilegible: queda el mensaje genérico con el código.
  }
  return error;
}

/**
 * Muestra el error como notificación de Mantine. Un 401 no se notifica: lo resuelve el
 * interceptor del cliente (renueva la sesión o manda al login, spec §8.3).
 */
export function notificarError(error: unknown): void {
  const problema = problemaDe(error);
  if (problema.status === 401) {
    return;
  }
  notifications.show({
    color: "red",
    title: problema.titulo,
    message: problema.detalle ?? "",
  });
}

/** Notificación de error que no viene del API (p. ej., sin acceso al portapapeles). */
export function notificarFallo(titulo: string, mensaje: string): void {
  notifications.show({ color: "red", title: titulo, message: mensaje });
}

/** Notificación de éxito (crear, rotar, archivar...). */
export function notificarExito(mensaje: string): void {
  notifications.show({ color: "green", message: mensaje });
}
