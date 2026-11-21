// Pasos de interfaz que comparten las pruebas E2E. Cada prueba inicia sesión por la pantalla de
// login: no se comparte `storageState` entre pruebas porque el refresh rota y reusar la misma
// cookie dispararía la detección de reúso, que revoca todas las sesiones del usuario (H-43).
import { expect, type Page } from "@playwright/test";

import { credenciales, type Credenciales, type Rol } from "./credenciales";

export const PROYECTO = "Tienda en línea";

/** Llena y envía el formulario de login, sin esperar el resultado. */
export async function intentarIniciarSesion(page: Page, cuenta: Credenciales): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Correo electrónico").fill(cuenta.correo);
  await page.getByRole("textbox", { name: "Contraseña", exact: true }).fill(cuenta.contrasena);
  await page.getByRole("button", { name: "Iniciar sesión" }).click();
}

/** Inicia sesión con cualquier cuenta y espera la lista de proyectos. */
export async function iniciarSesionCon(page: Page, cuenta: Credenciales): Promise<void> {
  await intentarIniciarSesion(page, cuenta);
  await expect(page.getByRole("heading", { name: "Proyectos", level: 2 })).toBeVisible();
}

/** Inicia sesión con un usuario del seed. */
export async function iniciarSesion(page: Page, rol: Rol): Promise<void> {
  await iniciarSesionCon(page, credenciales(rol));
}

/**
 * Espera a que pase la ventana de H-37: al revocar, el backend fija `T = floor(ahora) + 1 s` y
 * rechaza todo token con `iat < T`. Un login en el mismo segundo que el evento recibiría un token
 * que ya nace revocado (falla cerrado, spec §3.5). Sin esta espera, la prueba sería intermitente.
 */
export async function esperarVentanaH37(): Promise<void> {
  await new Promise((listo) => setTimeout(listo, 1_100));
}

/** Desde la lista de proyectos, abre el árbol de "Tienda en línea" y entra al ambiente. */
export async function abrirAmbiente(page: Page, ambiente: string): Promise<void> {
  await page.goto("/proyectos");
  await page.getByRole("button", { name: PROYECTO }).click();
  await page
    .getByRole("list", { name: `Ambientes de ${PROYECTO}` })
    .getByRole("link", { name: ambiente, exact: true })
    .click();
  await expect(page.getByRole("heading", { name: `Secretos de ${ambiente}` })).toBeVisible();
}

/** Texto de `localStorage` y `sessionStorage` de la página, para buscar fugas. */
export async function almacenamiento(page: Page): Promise<string> {
  return page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
}
