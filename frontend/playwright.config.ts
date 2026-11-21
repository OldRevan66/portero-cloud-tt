// Pruebas end-to-end del Dashboard con Playwright (Cap. 6 §Pruebas end-to-end del Dashboard;
// spec §8.6). Corren contra el stack E2E propio (docker-compose.e2e.yml, Dashboard en el 8180),
// que levanta y destruye `npm run e2e` (e2e/correr.mjs). Correrlas a mano con `npx playwright
// test` solo funciona si ese stack ya está arriba.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.spec.ts",
  // Espera a que el backend responda /health/ready antes de la primera prueba.
  globalSetup: "./e2e/apoyo/esperar-stack.ts",
  // Sin reintentos: una prueba intermitente debe verse, no ocultarse.
  retries: 0,
  // Una prueba que se queda en una página por error falla en 30 s, no se cuelga.
  timeout: 30_000,
  forbidOnly: !!process.env.CI,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: "http://localhost:8180",
    locale: "es-MX",
    timezoneId: "America/Mexico_City",
    // Evidencia solo de lo que falla: trace (DOM, red y consola paso a paso) y captura.
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
