// Flujo (v): un Desarrollador no ve acciones administrativas (Cap. 6 §Pruebas end-to-end) y lo
// que está fuera de su alcance es "no encontrado", no "prohibido" (H-14). /usuarios no depende de
// un proyecto: la ruta es visible para todos, así que sin users:manage es 403, no 404.
import { expect, test } from "@playwright/test";

import { ApiE2E } from "./apoyo/api";
import { abrirAmbiente, iniciarSesion, PROYECTO } from "./apoyo/sesion";

let urlProduccion = "";
let secretoProduccion = "";

test.beforeAll(async ({ request }) => {
  const lider = await ApiE2E.como(request, "lider");
  const { pid, ambientes } = await lider.tienda();
  const eid = ambientes.get("production") ?? "";
  const smtp = (await lider.secretos(pid, eid)).find((s) => s.name === "SMTP_PASSWORD");
  if (smtp === undefined) throw new Error("El seed no creó SMTP_PASSWORD en production");
  secretoProduccion = smtp.id;
  urlProduccion = `/proyectos/${pid}/ambientes/${eid}/secretos/${smtp.id}`;
});

test("(v) Desarrollador: sin Bitácora, solo development y sin acciones de escritura", async ({
  page,
}) => {
  await iniciarSesion(page, "dev");

  const menu = page.getByRole("navigation", { name: "Menú principal" });
  await expect(menu.getByRole("link", { name: "Proyectos" })).toBeVisible();
  await expect(menu.getByRole("link", { name: "Bitácora" })).toHaveCount(0);

  await page.getByRole("button", { name: PROYECTO }).click();
  await expect(
    page.getByRole("list", { name: `Ambientes de ${PROYECTO}` }).getByRole("link"),
  ).toHaveText(["development"]);

  await abrirAmbiente(page, "development");
  await expect(page.getByRole("button", { name: "Nuevo secreto" })).toHaveCount(0);
  await page.getByRole("link", { name: "DB_PASSWORD", exact: true }).click();
  await expect(page.getByRole("button", { name: "Revelar" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Rotar" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Archivar" })).toHaveCount(0);
});

test("(v) Desarrollador: la URL de un secreto de production da «no encontrado» (404)", async ({
  page,
}) => {
  await iniciarSesion(page, "dev");

  const respuesta = page.waitForResponse((r) =>
    r.url().endsWith(`/api/v1/secrets/${secretoProduccion}`),
  );
  await page.goto(urlProduccion);
  expect((await respuesta).status()).toBe(404);
  await expect(page.getByText("No se encontró el secreto o no tienes acceso a él.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Revelar" })).toHaveCount(0);
});

test("(v) Desarrollador: sin «Usuarios» en el menú y /usuarios muestra «Acceso denegado» (403)", async ({
  page,
}) => {
  await iniciarSesion(page, "dev");

  const menu = page.getByRole("navigation", { name: "Menú principal" });
  await expect(menu.getByRole("link", { name: "Proyectos" })).toBeVisible();
  await expect(menu.getByRole("link", { name: "Usuarios" })).toHaveCount(0);

  const respuesta = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/users");
  await page.goto("/usuarios");
  expect((await respuesta).status()).toBe(403);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Acceso denegado");
  await expect(page.getByRole("button", { name: "Nuevo usuario" })).toHaveCount(0);
});
