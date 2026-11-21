import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

// Configuración de Vite (servidor de desarrollo y build) y de Vitest (pruebas).
export default defineConfig({
  plugins: [react()],
  server: {
    // Mismo origen para el Dashboard y la API (spec §3.1, §8.5): el navegador envía la cookie
    // del refresh (SameSite=Strict, Path=/api/v1/auth) sin necesidad de CORS.
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    // Las pruebas E2E (e2e/*.spec.ts) las corre Playwright, no Vitest.
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
