// Flujo (ix): un usuario cambia su propia contraseña (spec §3.6, §3.5; H-37). El usuario se crea
// en la prueba por la API con credenciales generadas: las contraseñas del seed no cambian, porque
// las usan las demás pruebas. Tras el 204, el Dashboard vuelve al login con un aviso; la
// contraseña anterior ya no sirve y la nueva sí.
import { expect, test } from "@playwright/test";

import { ApiE2E } from "./apoyo/api";
import { credencialesNuevas } from "./apoyo/credenciales";
import {
  almacenamiento,
  esperarVentanaH37,
  iniciarSesionCon,
  intentarIniciarSesion,
} from "./apoyo/sesion";

const AVISO = "Contraseña cambiada. Inicia sesión con tu nueva contraseña.";

test("(ix) un usuario cambia su contraseña: vuelve al login, la anterior falla y la nueva entra", async ({
  page,
  request,
}) => {
  const anterior = credencialesNuevas();
  const nueva = { correo: anterior.correo, contrasena: credencialesNuevas().contrasena };
  const admin = await ApiE2E.como(request, "admin");
  await admin.crearUsuario(anterior);

  await iniciarSesionCon(page, anterior);
  await page.getByRole("banner").getByRole("button", { name: "Cambiar contraseña" }).click();
  const modal = page.getByRole("dialog", { name: "Cambiar contraseña" });
  await modal
    .getByRole("textbox", { name: "Contraseña actual", exact: true })
    .fill(anterior.contrasena);
  await modal
    .getByRole("textbox", { name: "Nueva contraseña", exact: true })
    .fill(nueva.contrasena);
  await modal
    .getByRole("textbox", { name: "Confirma la nueva contraseña", exact: true })
    .fill(nueva.contrasena);
  await modal.getByRole("button", { name: "Cambiar contraseña" }).click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText(AVISO)).toBeVisible();
  for (const contrasena of [anterior.contrasena, nueva.contrasena]) {
    expect(page.url()).not.toContain(contrasena);
    expect(await almacenamiento(page)).not.toContain(contrasena);
  }

  // H-37: un login en el mismo segundo del cambio recibiría un token ya revocado.
  await esperarVentanaH37();
  await intentarIniciarSesion(page, anterior);
  await expect(page.getByRole("alert")).toHaveText("Credenciales inválidas.");

  await iniciarSesionCon(page, nueva);
});
