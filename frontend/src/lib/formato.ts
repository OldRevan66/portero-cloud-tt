// Formatos de presentación del Dashboard (RF-029: interfaz en español).

const FORMATO_FECHA = new Intl.DateTimeFormat("es-MX", {
  dateStyle: "short",
  timeStyle: "short",
  timeZone: "America/Mexico_City",
});

/** Fecha ISO 8601 del API (UTC) → hora local de México, p. ej. "11/10/26, 10:02". */
export function formatearFecha(iso: string): string {
  return FORMATO_FECHA.format(new Date(iso));
}

/** Los UUID completos estorban en una tabla; basta con los primeros 8 caracteres. */
export function uuidCorto(uuid: string): string {
  return uuid.slice(0, 8);
}

/**
 * Desfase de la hora de México. Desde 2022 la Ciudad de México no tiene horario de verano, así
 * que es fijo.
 */
const ZONA_MEXICO = "-06:00";

/**
 * Valor de un `<input type="datetime-local">` ("2026-10-01T00:00"), capturado en hora de México,
 * → ISO 8601 con zona ("2026-10-01T00:00:00-06:00"), que es lo que exige el API (spec §4.3).
 * `segundos` permite cerrar un rango inclusivo al final del minuto ("59").
 */
export function horaMexicoAIso(valorLocal: string, segundos: "00" | "59" = "00"): string {
  return `${valorLocal}:${segundos}${ZONA_MEXICO}`;
}
