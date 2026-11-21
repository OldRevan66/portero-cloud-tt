// Flujos (ii) y (vii): ciclo de vida de un secreto desde la interfaz (CU-02, CU-03) y el manejo
// del valor revelado (spec §8.4: nunca en la URL ni en el almacenamiento; se borra al desmontar).
import { expect, test } from "@playwright/test";

import { ApiE2E, unico, valorDemo } from "./apoyo/api";
import { abrirAmbiente, almacenamiento, iniciarSesion } from "./apoyo/sesion";

test("(ii) Líder: crear, listar, revelar y rotar un secreto en development", async ({ page }) => {
  const nombre = unico("E2E_SECRETO");
  const valor = valorDemo();
  const nuevoValor = valorDemo();
  await iniciarSesion(page, "lider");
  await abrirAmbiente(page, "development");

  await page.getByRole("button", { name: "Nuevo secreto" }).click();
  const crear = page.getByRole("dialog", { name: "Nuevo secreto" });
  await crear.getByRole("textbox", { name: "Nombre", exact: true }).fill(nombre);
  await crear.getByRole("textbox", { name: "Valor", exact: true }).fill(valor);
  await crear.getByRole("button", { name: "Crear secreto" }).click();
  await expect(crear).toBeHidden();

  const fila = page.getByRole("row").filter({ hasText: nombre });
  await expect(fila).toContainText("v1");
  await fila.getByRole("link", { name: nombre, exact: true }).click();
  await expect(page.getByRole("heading", { name: nombre })).toBeVisible();
  await expect(page.getByText(valor)).toHaveCount(0);

  await page.getByRole("button", { name: "Revelar" }).click();
  await expect(page.getByText(valor, { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Rotar" }).click();
  const rotar = page.getByRole("dialog", { name: `Rotar ${nombre}` });
  await rotar.getByRole("textbox", { name: "Nuevo valor", exact: true }).fill(nuevoValor);
  await rotar.getByRole("button", { name: "Rotar" }).click();
  await expect(rotar).toBeHidden();

  await expect(page.getByRole("cell", { name: "v2", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "v1", exact: true })).toBeVisible();
  // Al rotar, el componente del valor se desmonta: el valor anterior ya no está en pantalla.
  await expect(page.getByText(valor)).toHaveCount(0);
});

test("(vii) el valor revelado no va a la URL ni al almacenamiento y se borra al salir", async ({
  page,
  request,
}) => {
  const lider = await ApiE2E.como(request, "lider");
  const { pid, ambientes } = await lider.tienda();
  const eid = ambientes.get("development") ?? "";
  const valor = valorDemo();
  const sid = await lider.crearSecreto(pid, eid, unico("E2E_REVELADO"), valor);

  await iniciarSesion(page, "lider");
  await page.goto(`/proyectos/${pid}/ambientes/${eid}/secretos/${sid}`);
  await page.getByRole("button", { name: "Revelar" }).click();
  await expect(page.getByText(valor, { exact: true })).toBeVisible();

  expect(page.url()).not.toContain(valor);
  expect(await almacenamiento(page)).not.toContain(valor);
  expect(await page.evaluate(() => JSON.stringify(history.state))).not.toContain(valor);

  // Otra pantalla y de vuelta: el componente se desmontó y el valor ya no existe.
  await page.getByRole("link", { name: "development", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Secretos de development" })).toBeVisible();
  await expect(page.getByText(valor)).toHaveCount(0);
  await page.goBack();
  await expect(page.getByRole("button", { name: "Revelar" })).toBeVisible();
  await expect(page.getByText(valor)).toHaveCount(0);
});
