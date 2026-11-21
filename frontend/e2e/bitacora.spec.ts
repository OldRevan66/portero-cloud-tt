// Flujo (iv): consultar y filtrar la bitácora y verificar la cadena de hashes (RF-028, H-46).
// Las operaciones a buscar las crea este archivo por la API, con nombres únicos, para no depender
// del orden de los demás archivos.
// RF-021 (H-83): "Exportar CSV" descarga de verdad en Chromium (URL temporal + <a download>) y la
// celda con fórmula que dejó un anónimo en su User-Agent llega neutralizada con '.
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { ApiE2E, unico, valorDemo } from "./apoyo/api";
import { iniciarSesion } from "./apoyo/sesion";

let secretoId = "";
let aplicacionId = "";
const correoFallido = `e2e-${randomUUID().slice(0, 8)}@no-existe.example`;
const correoFormula = `e2e-${randomUUID().slice(0, 8)}@formula.example`;
const FORMULA = '=HYPERLINK("http://atacante.example/x","clic")';

test.beforeAll(async ({ request }) => {
  const lider = await ApiE2E.como(request, "lider");
  const { pid, ambientes } = await lider.tienda();
  const eid = ambientes.get("development") ?? "";
  secretoId = await lider.crearSecreto(pid, eid, unico("E2E_BITACORA"), valorDemo());
  aplicacionId = await lider.crearAplicacion(pid, eid, unico("e2e-bitacora"));
  // Un login fallido con un correo inexistente: deja un "Fallo" sin bloquear cuentas del seed.
  const fallido = await request.post("/api/v1/auth/login", {
    data: { email: correoFallido, password: "contrasena-incorrecta-e2e" },
  });
  expect(fallido.status()).toBe(401);
  // Otro, sin autenticarse, con una fórmula en el User-Agent (el vector de CSV injection).
  const conFormula = await request.post("/api/v1/auth/login", {
    data: { email: correoFormula, password: "contrasena-incorrecta-e2e" },
    headers: { "User-Agent": FORMULA },
  });
  expect(conFormula.status()).toBe(401);
});

test("(iv) Administrador: filtrar la bitácora por verbo y resultado y verificar la cadena", async ({
  page,
}) => {
  await iniciarSesion(page, "admin");
  await page
    .getByRole("navigation", { name: "Menú principal" })
    .getByRole("link", { name: "Bitácora" })
    .click();
  await expect(page.getByRole("heading", { name: "Bitácora", level: 2 })).toBeVisible();
  const verbo = page.getByLabel("Verbo");
  const resultado = page.getByLabel("Resultado");
  const filtrar = page.getByRole("button", { name: "Filtrar" });

  await verbo.selectOption({ label: "Crear secreto" });
  await filtrar.click();
  await expect(page.getByRole("row").filter({ hasText: secretoId.slice(0, 8) })).toBeVisible();
  await expect(page.getByRole("cell", { name: "create_service_account" })).toHaveCount(0);

  await verbo.selectOption({ label: "Crear Aplicación Cliente" });
  await filtrar.click();
  await expect(page.getByRole("row").filter({ hasText: aplicacionId.slice(0, 8) })).toBeVisible();
  await expect(page.getByRole("cell", { name: "create_secret", exact: true })).toHaveCount(0);

  await verbo.selectOption({ label: "Todos" });
  await resultado.selectOption({ label: "Fallo" });
  await filtrar.click();
  const fila = page.getByRole("row").filter({ hasText: correoFallido });
  await expect(fila).toContainText("login_failed");
  await expect(fila).toContainText("Fallo");
  await expect(page.getByRole("cell", { name: "Éxito" })).toHaveCount(0);

  await page.getByRole("button", { name: "Verificar integridad" }).click();
  const veredicto = page.getByRole("alert").filter({ hasText: "Cadena verificada" });
  await expect(veredicto).toContainText("La bitácora está íntegra");
});

test("RF-021 Administrador: exportar la bitácora filtrada en CSV, con la fórmula neutralizada", async ({
  page,
}) => {
  await iniciarSesion(page, "admin");
  await page
    .getByRole("navigation", { name: "Menú principal" })
    .getByRole("link", { name: "Bitácora" })
    .click();
  await page.getByLabel("Verbo").selectOption({ label: "Inicio de sesión fallido" });
  await page.getByRole("button", { name: "Filtrar" }).click();
  await expect(page.getByRole("row").filter({ hasText: correoFormula })).toBeVisible();

  const descarga = page.waitForEvent("download");
  await page.getByRole("button", { name: "Exportar CSV" }).click();
  const archivo = await descarga;

  expect(archivo.suggestedFilename()).toMatch(/^bitacora-\d{4}-\d{2}-\d{2}\.csv$/);
  const texto = await readFile(await archivo.path(), "utf-8");
  const linea = texto.split("\r\n").find((l) => l.includes(correoFormula));
  expect(linea).toBeDefined();
  expect(linea).toContain("login_failed");
  expect(linea).toContain(`"'=HYPERLINK(""http://atacante.example/x"",""clic"")"`);
  expect(texto).not.toContain("create_secret"); // solo lo filtrado
});
