import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist",
      "node_modules",
      "src/api/schema.d.ts",
      "e2e/.generado",
      "playwright-report",
      "test-results",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { react, "react-hooks": reactHooks },
    settings: { react: { version: "19" } },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Spec §8.4 y RNF-006: sin HTML inyectado y sin valores en la consola.
      "react/no-danger": "error",
      "no-console": "error",
      // Convención: un parámetro que empieza con _ se deja sin usar a propósito.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  // Pruebas E2E, su orquestador y la prueba de nginx (H-79): corren en Node, no en el navegador.
  {
    files: ["e2e/**/*.{ts,mjs}", "pruebas-nginx/**/*.mjs", "playwright.config.ts"],
    languageOptions: { globals: globals.node },
  },
);
