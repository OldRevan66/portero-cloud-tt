// `npm run prueba:nginx`: prueba de la IP real del cliente detrás de un proxy de confianza
// (H-79, spec §7). Node puro, como e2e/correr.mjs, para que funcione igual en Windows y en
// GitHub Actions.
//
// 1. Levanta el stack portero-realip (docker-compose.yml de esta carpeta).
// 2. Desde "proxy" y desde "otro" pide /api/eco con un X-Forwarded-For y compara la IP que llega
//    al backend.
// 3. Siempre, aunque falle o se interrumpa: baja el stack. Sale con 1 si algún caso falla.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const carpeta = path.dirname(fileURLToPath(import.meta.url));
const compose = ["compose", "-f", path.join(carpeta, "docker-compose.yml")];

const IP_PROXY = "10.250.79.20";
const IP_OTRO = "10.250.79.30";
const CLIENTE = "203.0.113.7"; // TEST-NET-3 (RFC 5737): nunca es una IP real.
const INYECTADA = "198.51.100.1"; // TEST-NET-2

function docker(argumentos, salida = "pipe") {
  const resultado = spawnSync("docker", [...compose, ...argumentos], {
    encoding: "utf8",
    stdio: ["ignore", salida, salida],
  });
  if (resultado.error) {
    throw new Error(`no se pudo ejecutar docker: ${resultado.error.message}`);
  }
  return { codigo: resultado.status ?? 1, texto: (resultado.stdout ?? "").trim() };
}

/** IP que el backend recibe cuando `cliente` pide /api/eco a `servicio` con ese X-Forwarded-For. */
function ipQueVeElBackend(cliente, servicio, xff) {
  const { codigo, texto } = docker([
    "exec",
    "-T",
    cliente,
    "wget",
    "-qO-",
    "--header",
    `X-Forwarded-For: ${xff}`,
    `http://${servicio}:8080/api/eco`,
  ]);
  return codigo === 0 ? texto : null;
}

function esperar(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Espera a que nginx de `servicio` responda (hasta ~30 s). */
function esperarListo(servicio) {
  for (let intento = 0; intento < 30; intento++) {
    if (ipQueVeElBackend("otro", servicio, CLIENTE) !== null) return true;
    esperar(1000);
  }
  return false;
}

/** Estado del contenedor de `servicio` tras unos segundos: "running" o "exited <código>". */
function estadoTrasArrancar(servicio) {
  esperar(5000);
  const { texto: id } = docker(["ps", "-a", "-q", servicio]);
  const resultado = spawnSync(
    "docker",
    ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", id],
    { encoding: "utf8" },
  );
  return (resultado.stdout ?? "").trim();
}

const casos = [
  {
    nombre: "1. proxy declarado: el backend ve la IP del cliente",
    obtener: () => ipQueVeElBackend("proxy", "frontend", CLIENTE),
    esperado: CLIENTE,
  },
  {
    nombre: "2. otro origen (spec §7): su X-Forwarded-For se ignora",
    obtener: () => ipQueVeElBackend("otro", "frontend", CLIENTE),
    esperado: IP_OTRO,
  },
  {
    nombre: "3. proxy declarado, el cliente inyectó una IP antes: cuenta la que agregó el proxy",
    obtener: () => ipQueVeElBackend("proxy", "frontend", `${INYECTADA}, ${CLIENTE}`),
    esperado: CLIENTE,
  },
  {
    nombre: "4. sin PORTERO_TRUSTED_PROXY: nada cambia, ni siquiera desde el proxy",
    obtener: () => ipQueVeElBackend("proxy", "frontend-sin-proxy", CLIENTE),
    esperado: IP_PROXY,
  },
  {
    nombre: "5. valor inválido en PORTERO_TRUSTED_PROXY: el contenedor no arranca",
    obtener: () => {
      const estado = estadoTrasArrancar("frontend-invalido");
      return estado.startsWith("exited") && !estado.endsWith(" 0") ? "no arranca" : estado;
    },
    esperado: "no arranca",
  },
  {
    nombre: "6. valor con saltos de línea (H-85): el contenedor no arranca",
    obtener: () => {
      const estado = estadoTrasArrancar("frontend-salto");
      return estado.startsWith("exited") && !estado.endsWith(" 0") ? "no arranca" : estado;
    },
    esperado: "no arranca",
  },
];

process.on("SIGINT", () => console.log("\nprueba:nginx: interrumpido; bajando el stack..."));

let fallas = 0;
try {
  console.log("=== prueba:nginx: construyendo y levantando el stack portero-realip");
  if (docker(["up", "-d", "--build"], "inherit").codigo !== 0) {
    // `up` no espera a que nginx escuche; solo falla si no pudo crear los contenedores.
    console.error("prueba:nginx: no se pudo levantar el stack");
    fallas = 1;
  } else if (!esperarListo("frontend") || !esperarListo("frontend-sin-proxy")) {
    console.error("prueba:nginx: el Dashboard no respondió a tiempo");
    fallas = 1;
  } else {
    for (const caso of casos) {
      const obtenido = caso.obtener();
      const bien = obtenido === caso.esperado;
      if (!bien) fallas++;
      console.log(
        `${bien ? "OK   " : "FALLA"} ${caso.nombre}` +
          (bien ? "" : `\n        esperado: ${caso.esperado}\n        obtenido: ${obtenido}`),
      );
    }
  }
} finally {
  console.log("=== prueba:nginx: bajando el stack");
  docker(["down", "-v", "--remove-orphans", "--rmi", "local"], "inherit");
}
console.log(
  fallas === 0 ? "prueba:nginx: todo en verde" : `prueba:nginx: ${fallas} caso(s) en rojo`,
);
process.exit(fallas === 0 ? 0 : 1);
