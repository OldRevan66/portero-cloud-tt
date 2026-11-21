// Validación en el navegador de los campos de un secreto. Replica las restricciones de
// SecretCreate y SecretRotate (backend/src/portero/api/v1/secrets.py) para avisar antes de
// enviar; la autoridad sigue siendo el backend, que responde 400 si algo no cumple.

export const PATRON_NOMBRE = /^[A-Z][A-Z0-9_]*$/;
export const MAX_NOMBRE = 255;
export const MAX_VALOR = 65_536;
export const MAX_DESCRIPCION = 1024;

/** Error del nombre en español, o null si es válido (SCREAMING_SNAKE_CASE, 1 a 255). */
export function errorDeNombre(nombre: string): string | null {
  if (nombre === "") {
    return "El nombre es obligatorio.";
  }
  if (nombre.length > MAX_NOMBRE) {
    return `El nombre admite como máximo ${MAX_NOMBRE} caracteres.`;
  }
  if (!PATRON_NOMBRE.test(nombre)) {
    return "Usa solo MAYÚSCULAS, dígitos y guion bajo, empezando con una letra (p. ej. DATABASE_URL).";
  }
  return null;
}

/** Error del valor, o null si es válido (1 a 65 536 caracteres). Nunca repite el valor. */
export function errorDeValor(valor: string): string | null {
  if (valor === "") {
    return "El valor es obligatorio.";
  }
  if (valor.length > MAX_VALOR) {
    return "El valor admite como máximo 65 536 caracteres.";
  }
  return null;
}

/** Error de la descripción (opcional, hasta 1024 caracteres). */
export function errorDeDescripcion(descripcion: string): string | null {
  if (descripcion.length > MAX_DESCRIPCION) {
    return `La descripción admite como máximo ${MAX_DESCRIPCION} caracteres.`;
  }
  return null;
}
