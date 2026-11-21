// Credenciales de los usuarios del seed para el stack E2E (H-57). Las genera
// backend/scripts/generate_e2e_env.py en cada corrida; aquí solo se leen las tres contraseñas
// (nunca la KEK ni la clave de firma) y nunca se imprimen.
//
// `credencialesNuevas` genera correo y contraseña para usuarios creados dentro de una prueba
// (flujos viii e ix), con el CSPRNG de Node. Así nunca se tocan las contraseñas del seed, que
// usan las demás pruebas. Tampoco se imprimen.
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type Rol = "admin" | "lider" | "dev";

export interface Credenciales {
  correo: string;
  contrasena: string;
}

const CORREOS: Record<Rol, string> = {
  admin: "admin@tienda.example",
  lider: "lider@tienda.example",
  dev: "dev@tienda.example",
};

const VARIABLES: Record<Rol, string> = {
  admin: "SEED_PASSWORD_ADMIN",
  lider: "SEED_PASSWORD_LIDER",
  dev: "SEED_PASSWORD_DEV",
};

const ARCHIVO = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  ".generado",
  "e2e.env",
);

let contrasenas: Map<string, string> | undefined;

function leerContrasenas(): Map<string, string> {
  if (contrasenas === undefined) {
    contrasenas = new Map();
    for (const linea of readFileSync(ARCHIVO, "utf-8").split("\n")) {
      const [nombre, ...resto] = linea.trim().split("=");
      if (nombre !== undefined && nombre.startsWith("SEED_PASSWORD_")) {
        contrasenas.set(nombre, resto.join("="));
      }
    }
  }
  return contrasenas;
}

export function credenciales(rol: Rol): Credenciales {
  const contrasena = leerContrasenas().get(VARIABLES[rol]);
  if (!contrasena) {
    throw new Error(`Falta ${VARIABLES[rol]} en e2e/.generado/e2e.env; usa npm run e2e`);
  }
  return { correo: CORREOS[rol], contrasena };
}

/** Correo único y contraseña aleatoria de 32 caracteres (cumple la política de 12 a 128). */
export function credencialesNuevas(): Credenciales {
  return {
    correo: `e2e-${randomUUID().slice(0, 8)}@tienda.example`,
    contrasena: randomBytes(24).toString("base64url"),
  };
}
