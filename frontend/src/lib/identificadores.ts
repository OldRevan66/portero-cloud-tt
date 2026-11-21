// Validación de los identificadores que llegan en la URL del Dashboard (hallazgo H-62; OWASP
// ASVS 4.0.3 V5.1.3, lista permitida). Proyectos, ambientes y secretos se identifican por UUID
// (spec Fase 5 §1); lo que no tenga esa forma no se envía al API.

const PATRON_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** ¿`valor` es un UUID en su forma canónica de 36 caracteres? */
export function esUuid(valor: string): boolean {
  return PATRON_UUID.test(valor);
}
