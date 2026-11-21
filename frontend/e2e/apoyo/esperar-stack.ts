// globalSetup de Playwright: `docker compose up --wait` devuelve cuando los contenedores corren,
// pero uvicorn tarda unos segundos más en derivar la KEK y aceptar peticiones. Se espera a que
// /health/ready (a través de nginx, como el navegador) responda 200, hasta 60 s.
import type { FullConfig } from "@playwright/test";

export default async function esperarStack(config: FullConfig): Promise<void> {
  const base = config.projects[0]?.use.baseURL ?? "http://localhost:8180";
  const limite = Date.now() + 60_000;
  while (Date.now() < limite) {
    try {
      const respuesta = await fetch(`${base}/api/v1/health/ready`);
      if (respuesta.ok) return;
    } catch {
      // Todavía no escucha: se reintenta.
    }
    await new Promise((listo) => setTimeout(listo, 1_000));
  }
  throw new Error(`El stack E2E no respondió en ${base}; ¿corriste npm run e2e?`);
}
