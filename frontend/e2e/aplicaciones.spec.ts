// Flujo (iii): crear y revocar una Aplicación Cliente (H-21: el token se muestra una sola vez;
// la lista solo trae el prefijo).
import { expect, test } from "@playwright/test";

import { unico } from "./apoyo/api";
import { iniciarSesion, PROYECTO } from "./apoyo/sesion";

test("(iii) Líder: crear una Aplicación Cliente, ver el token una vez y revocarla", async ({
  page,
}) => {
  const nombre = unico("e2e-app");
  await iniciarSesion(page, "lider");
  await page.getByRole("link", { name: "Detalle" }).click();
  await expect(page.getByRole("heading", { name: PROYECTO, level: 2 })).toBeVisible();

  await page.getByRole("button", { name: "Nueva aplicación" }).click();
  const crear = page.getByRole("dialog", { name: "Nueva Aplicación Cliente" });
  await crear.getByRole("textbox", { name: "Nombre", exact: true }).fill(nombre);
  await crear.getByLabel("Ambiente").selectOption({ label: "development" });
  await crear.getByRole("button", { name: "Crear" }).click();

  const emitido = page.getByRole("dialog", { name: `Token de ${nombre}` });
  const bloqueToken = emitido.getByText(/^eyJ/);
  await expect(bloqueToken).toBeVisible();
  const token = (await bloqueToken.textContent())?.trim() ?? "";
  expect(token.length).toBeGreaterThan(40);
  await emitido.getByRole("button", { name: "Ya lo guardé" }).click();
  await expect(emitido).toBeHidden();

  // En la lista solo "termina en …" con los últimos 8 caracteres (H-42: `token_prefix` es el
  // final del PAT, porque el inicio de todo JWT es igual); el token completo ya no está.
  const fila = page.getByRole("row").filter({ hasText: nombre });
  await expect(fila).toContainText(`termina en ${token.slice(-8)}`);
  await expect(page.getByText(token)).toHaveCount(0);
  expect(await page.content()).not.toContain(token);

  await fila.getByRole("button", { name: "Revocar" }).click();
  const confirmar = page.getByRole("dialog", { name: "Revocar Aplicación Cliente" });
  await expect(confirmar).toContainText(nombre);
  await confirmar.getByRole("button", { name: "Revocar" }).click();
  await expect(confirmar).toBeHidden();
  await expect(fila).toContainText("Revocada");
  await expect(fila.getByRole("button", { name: "Revocar" })).toHaveCount(0);
});
