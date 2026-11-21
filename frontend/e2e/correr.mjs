// `npm run e2e`: corre las pruebas end-to-end contra un stack limpio y desechable (Cap. 6
// §Pruebas end-to-end del Dashboard; H-57). Node puro, sin bash ni PowerShell, para que funcione
// igual en Windows y en GitHub Actions.
//
// 1. Genera el entorno (contraseñas, KEK, clave Ed25519) en e2e/.generado/, ignorado por Git.
// 2. Levanta el stack portero-e2e: BD en RAM → migración y seed (servicio "preparar") → backend
//    → Dashboard en http://localhost:8180.
// 3. Corre Playwright con los argumentos extra (`npm run e2e -- e2e/sesion.spec.ts`).
// 4. Siempre, aunque fallen las pruebas o se interrumpa con Ctrl+C: baja el stack con sus
//    volúmenes y borra el entorno generado. Sale con el código de Playwright.
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const raiz = path.resolve(frontend, "..");
const generado = path.join(frontend, "e2e", ".generado");
const archivoEnv = path.join(generado, "e2e.env");

const compose = [
  "compose",
  "-p",
  "portero-e2e",
  "-f",
  path.join(raiz, "docker-compose.yml"),
  "-f",
  path.join(raiz, "docker-compose.e2e.yml"),
  // Sustituye al .env de desarrollo para la interpolación: el stack E2E nunca lo lee.
  "--env-file",
  archivoEnv,
];

/** Ejecuta un comando mostrando su salida; devuelve el código de salida (1 si no arrancó). */
function correr(comando, argumentos, cwd = frontend) {
  const resultado = spawnSync(comando, argumentos, { cwd, stdio: "inherit" });
  if (resultado.error) {
    console.error(`e2e: no se pudo ejecutar ${comando}: ${resultado.error.message}`);
    return 1;
  }
  return resultado.status ?? 1;
}

function paso(texto) {
  console.log(`\n=== e2e: ${texto}`);
}

// Ctrl+C también llega a los procesos hijos; Node no debe salir antes del `finally`.
process.on("SIGINT", () => console.log("\ne2e: interrumpido; bajando el stack..."));

const playwright = createRequire(import.meta.url).resolve("@playwright/test/cli");
let codigo = 1;
rmSync(generado, { recursive: true, force: true });
mkdirSync(generado, { recursive: true });
try {
  paso("generando el entorno desechable");
  if (
    correr(
      "uv",
      ["run", "python", "scripts/generate_e2e_env.py", archivoEnv],
      path.join(raiz, "backend"),
    ) !== 0
  ) {
    throw new Error("no se pudo generar el entorno");
  }

  paso("levantando el stack portero-e2e (migración y seed incluidos)");
  if (correr("docker", [...compose, "up", "-d", "--build", "--wait", "frontend"]) !== 0) {
    // El seed en modo no interactivo no imprime contraseñas ni el PAT (H-57).
    correr("docker", [...compose, "logs", "preparar", "backend"]);
    throw new Error("el stack no levantó");
  }

  paso("corriendo Playwright");
  codigo = correr(process.execPath, [playwright, "test", ...process.argv.slice(2)]);
} catch (error) {
  console.error(`e2e: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  paso("bajando el stack y borrando el entorno generado");
  correr("docker", [...compose, "down", "-v", "--remove-orphans"]);
  rmSync(generado, { recursive: true, force: true });
}
process.exit(codigo);
