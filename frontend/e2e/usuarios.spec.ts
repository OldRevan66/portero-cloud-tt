// Flujo (viii): el Administrador gestiona usuarios y roles desde el Dashboard (CU-05; spec §8.2;
// H-22, H-37, H-73). El usuario se crea en la prueba con credenciales generadas (no se tocan las
// del seed) y entra en otro contexto del navegador, con sus propias cookies. Al quitarle el rol,
// el backend invalida sus tokens (H-37): al recargar, el refresh falla y vuelve al login.
import { expect, test } from "@playwright/test";

import { credencialesNuevas } from "./apoyo/credenciales";
import { esperarVentanaH37, iniciarSesion, iniciarSesionCon, PROYECTO } from "./apoyo/sesion";

test("(viii) Administrador: crea un usuario, le asigna Desarrollador en development y se lo quita", async ({
  page,
  browser,
}, testInfo) => {
  const cuenta = credencialesNuevas();
  await iniciarSesion(page, "admin");

  // Alta.
  await page
    .getByRole("navigation", { name: "Menú principal" })
    .getByRole("link", { name: "Usuarios" })
    .click();
  await expect(page.getByRole("heading", { name: "Usuarios", level: 2 })).toBeVisible();
  await page.getByRole("button", { name: "Nuevo usuario" }).click();
  const alta = page.getByRole("dialog", { name: "Nuevo usuario" });
  await alta.getByRole("textbox", { name: "Correo", exact: true }).fill(cuenta.correo);
  await alta.getByRole("textbox", { name: "Contraseña", exact: true }).fill(cuenta.contrasena);
  await alta.getByRole("button", { name: "Crear" }).click();
  await expect(alta).toBeHidden();

  // Asignar Desarrollador en Tienda en línea / development.
  await page.getByRole("link", { name: cuenta.correo, exact: true }).click();
  await expect(page.getByRole("heading", { name: cuenta.correo, level: 2 })).toBeVisible();
  await expect(page.getByText("Este usuario no tiene roles asignados.")).toBeVisible();
  await page.getByRole("button", { name: "Asignar rol" }).click();
  const asignar = page.getByRole("dialog", { name: "Asignar rol" });
  await asignar.getByLabel("Rol").selectOption({ label: "Desarrollador" });
  await asignar.getByLabel("Proyecto").selectOption({ label: PROYECTO });
  await asignar.getByLabel("Ambiente").selectOption({ label: "development" });
  await asignar.getByRole("button", { name: "Asignar" }).click();
  await expect(asignar).toBeHidden();
  const fila = page.getByRole("row", { name: /Desarrollador/ });
  await expect(fila).toContainText(PROYECTO);
  await expect(fila).toContainText("development");

  // El usuario entra en otro contexto (otras cookies) y solo ve development.
  await esperarVentanaH37();
  const contexto = await browser.newContext({ baseURL: testInfo.project.use.baseURL });
  try {
    const otra = await contexto.newPage();
    await iniciarSesionCon(otra, cuenta);
    await otra.getByRole("button", { name: PROYECTO }).click();
    await expect(
      otra.getByRole("list", { name: `Ambientes de ${PROYECTO}` }).getByRole("link"),
    ).toHaveText(["development"]);

    // El Administrador le quita el rol (H-37: se invalidan sus tokens).
    await fila.getByRole("button", { name: "Quitar" }).click();
    const quitar = page.getByRole("dialog", { name: "Quitar rol" });
    await quitar.getByRole("button", { name: "Quitar" }).click();
    await expect(quitar).toBeHidden();
    await expect(page.getByText("Este usuario no tiene roles asignados.")).toBeVisible();

    // Al recargar, el refresh silencioso falla y el usuario vuelve al login.
    await otra.reload();
    await expect(otra).toHaveURL(/\/login$/);
    await expect(otra.getByRole("button", { name: "Iniciar sesión" })).toBeVisible();
  } finally {
    await contexto.close();
  }
});
