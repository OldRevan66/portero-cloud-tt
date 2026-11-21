// Flujos (i) y (vi): inicio y cierre de sesión (Cap. 6 §Pruebas end-to-end) y la sesión de H-36:
// el access token solo en memoria y el refresh solo en la cookie HttpOnly (spec §8.3).
import { expect, test } from "@playwright/test";

import { almacenamiento, iniciarSesion, PROYECTO } from "./apoyo/sesion";

test("(i) iniciar y cerrar sesión; «atrás» no vuelve a mostrar datos", async ({ page }) => {
  await iniciarSesion(page, "lider");
  await expect(page.getByRole("button", { name: PROYECTO })).toBeVisible();
  // Una pantalla con datos más en el historial: /proyectos queda detrás del detalle.
  await page.getByRole("link", { name: "Detalle" }).click();
  await expect(page.getByRole("heading", { name: PROYECTO, level: 2 })).toBeVisible();

  await page.getByRole("button", { name: "Cerrar sesión" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("button", { name: "Iniciar sesión" })).toBeVisible();

  // "Atrás" regresa a /proyectos, que sin sesión redirige otra vez al login sin mostrar datos.
  await page.goBack();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("button", { name: "Iniciar sesión" })).toBeVisible();
  await expect(page.getByText(PROYECTO)).toHaveCount(0);
});

test("(vi) recargar conserva la sesión y ningún token queda al alcance de JavaScript", async ({
  page,
  context,
}) => {
  await iniciarSesion(page, "lider");

  await page.reload();
  await expect(page.getByRole("button", { name: "Cerrar sesión" })).toBeVisible();
  await expect(page.getByRole("button", { name: PROYECTO })).toBeVisible();
  await expect(page).not.toHaveURL(/\/login/);

  // El refresh viaja en una cookie HttpOnly, Secure y SameSite=Strict (H-36); Chromium la acepta
  // en http://localhost porque lo trata como contexto seguro.
  const refresh = (await context.cookies()).find((c) => c.path === "/api/v1/auth");
  expect(refresh, "cookie del refresh").toBeDefined();
  expect(refresh?.httpOnly).toBe(true);
  expect(refresh?.secure).toBe(true);
  expect(refresh?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).not.toContain(refresh?.value ?? "-");

  // Ni el access token ni el refresh (JWT, empiezan con "eyJ") en el almacenamiento web.
  expect(await almacenamiento(page)).not.toMatch(/eyJ/);
});
