// H-77: archivar un proyecto, eliminar un ambiente y editar la descripción de un secreto desde el
// Dashboard (CU-07, RF-032, spec §8.2). El backend ya tenía las tres operaciones; aquí se prueba
// la interfaz completa, incluidos los dos 409 (spec §6).
import { expect, test } from "@playwright/test";

import { ApiE2E, unico, valorDemo } from "./apoyo/api";
import { iniciarSesion } from "./apoyo/sesion";

test("H-77 Admin: eliminar ambientes (409 con secretos, H-39) y archivar con doble confirmación", async ({
  page,
  request,
}) => {
  // Proyecto propio de la prueba: el del seed no se toca.
  const admin = await ApiE2E.como(request, "admin");
  const nombre = unico("E2E Proyecto");
  const { pid, ambientes } = await admin.crearProyecto(nombre);
  await admin.crearSecreto(pid, ambientes.get("development") ?? "", unico("E2E_H77"), valorDemo());

  await iniciarSesion(page, "admin");
  await page.goto(`/proyectos/${pid}`);
  await expect(page.getByRole("heading", { name: nombre, level: 2 })).toBeVisible();

  // development tiene un secreto: 409 con el title y el detail del API.
  await page
    .getByRole("row")
    .filter({ hasText: "development" })
    .getByRole("button", { name: "Eliminar" })
    .click();
  const conSecretos = page.getByRole("dialog");
  await conSecretos.getByRole("button", { name: "Eliminar ambiente" }).click();
  await expect(conSecretos.getByRole("alert")).toContainText("Conflicto");
  await expect(conSecretos.getByRole("alert")).toContainText("el ambiente tiene secretos");
  await conSecretos.getByRole("button", { name: "Cancelar" }).click();
  await expect(page.getByRole("link", { name: "development", exact: true })).toBeVisible();

  // staging está vacío: se elimina.
  await page
    .getByRole("row")
    .filter({ hasText: "staging" })
    .getByRole("button", { name: "Eliminar" })
    .click();
  await page.getByRole("dialog").getByRole("button", { name: "Eliminar ambiente" }).click();
  await expect(page.getByRole("link", { name: "staging", exact: true })).toHaveCount(0);

  // Archivar: el proyecto tiene secretos activos → 409 → segunda confirmación con confirm=true.
  await page.getByRole("button", { name: "Archivar proyecto" }).click();
  const archivar = page.getByRole("dialog");
  await archivar.getByRole("button", { name: "Archivar", exact: true }).click();
  await expect(archivar).toContainText("el proyecto tiene secretos activos");
  await archivar.getByRole("button", { name: "Archivar proyecto y sus secretos" }).click();

  await expect(page).toHaveURL(/\/proyectos$/);
  await expect(page.getByText(nombre)).toHaveCount(0);
});

test("H-77 Líder: editar la descripción de un secreto", async ({ page, request }) => {
  const lider = await ApiE2E.como(request, "lider");
  const { pid, ambientes } = await lider.tienda();
  const eid = ambientes.get("development") ?? "";
  const sid = await lider.crearSecreto(pid, eid, unico("E2E_DESCRIPCION"), valorDemo());
  const descripcion = `Descripción editada ${unico("E2E")}`;

  await iniciarSesion(page, "lider");
  await page.goto(`/proyectos/${pid}/ambientes/${eid}/secretos/${sid}`);
  await page.getByRole("button", { name: "Editar descripción" }).click();
  const editar = page.getByRole("dialog");
  await editar.getByRole("textbox", { name: "Descripción" }).fill(descripcion);
  await editar.getByRole("button", { name: "Guardar" }).click();
  await expect(editar).toBeHidden();

  await expect(page.getByText(descripcion, { exact: true })).toBeVisible();
});
