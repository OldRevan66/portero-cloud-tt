// Bitácora del Servicio de Registro de Operaciones (CU-06, RF-028; spec §4.3, §8.1, §8.2).
//
// - Filtros: verbo, resultado, actor, fechas y proyecto. Se aplican al pulsar "Filtrar"; los
//   vacíos no se envían. Las fechas se capturan en hora de México y viajan en ISO 8601 con zona.
// - Paginación con el cursor opaco del API ("Cargar más"), como el historial de versiones.
// - "Verificar integridad" (RF-021) solo para el Administrador: audit:read de instancia
//   (H-23b). Es conveniencia de interfaz; el backend responde 403 a cualquier otro. La propia
//   verificación deja un evento `verify_chain` (spec §5.2): al terminar se invalida la bitácora
//   para que aparezca sin recargar la página.
// - "Exportar CSV" y "Exportar JSON" (RF-021, H-83) descargan la bitácora con los filtros
//   aplicados, como el backend la entrega (mismo alcance que la tabla). El Blob no pasa por la
//   caché: se descarga con una URL temporal que se revoca enseguida.
// Son metadatos de eventos (`details` nunca lleva valores, H-12): pueden pasar por TanStack Query.
import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Loader,
  NativeSelect,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { notificarError } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha, horaMexicoAIso, uuidCorto } from "../lib/formato";
import { useProyectos } from "../projects/queries";
import {
  exportarOperaciones,
  listarOperaciones,
  verificarCadena,
  type ChainReport,
  type FiltrosOperaciones,
  type FormatoExportacion,
} from "./operationsApi";

/** Catálogo de verbos de la spec §5.2, con su nombre en español para el selector. */
const VERBOS: readonly { value: string; label: string }[] = [
  { value: "login", label: "Inicio de sesión" },
  { value: "login_failed", label: "Inicio de sesión fallido" },
  { value: "refresh", label: "Renovación de sesión" },
  { value: "refresh_reused", label: "Reúso de token de renovación" },
  { value: "logout", label: "Cierre de sesión" },
  { value: "change_password", label: "Cambio de contraseña" },
  { value: "create_secret", label: "Crear secreto" },
  { value: "read_secret", label: "Leer valor de secreto" },
  { value: "rotate_secret", label: "Rotar secreto" },
  { value: "update_secret", label: "Editar secreto" },
  { value: "archive_secret", label: "Archivar secreto" },
  { value: "create_project", label: "Crear proyecto" },
  { value: "update_project", label: "Editar proyecto" },
  { value: "archive_project", label: "Archivar proyecto" },
  { value: "create_environment", label: "Crear ambiente" },
  { value: "update_environment", label: "Editar ambiente" },
  { value: "delete_environment", label: "Eliminar ambiente" },
  { value: "create_user", label: "Crear usuario" },
  { value: "update_user", label: "Editar usuario" },
  { value: "deactivate_user", label: "Desactivar usuario" },
  { value: "unlock_user", label: "Desbloquear usuario" },
  { value: "reset_password", label: "Restablecer contraseña" },
  { value: "assign_role", label: "Asignar rol" },
  { value: "revoke_role", label: "Retirar rol" },
  { value: "create_service_account", label: "Crear Aplicación Cliente" },
  { value: "revoke_service_account", label: "Revocar Aplicación Cliente" },
  { value: "rotate_kek", label: "Rotar KEK" },
  { value: "verify_chain", label: "Verificar integridad" },
  { value: "sign_chain", label: "Firmar cierre" },
  { value: "export_operations", label: "Exportar bitácora" },
  { value: "access_denied", label: "Acceso denegado" },
];

const RESULTADOS = [
  { value: "success", label: "Éxito" },
  { value: "failure", label: "Fallo" },
] as const;

/** Lo que el usuario tiene escrito en el formulario (aún sin aplicar). */
interface Formulario {
  verb: string;
  result: string;
  actor: string;
  desde: string; // valor de <input type="datetime-local">: "2026-10-01T00:00"
  hasta: string;
  project_id: string;
}

const FORMULARIO_VACIO: Formulario = {
  verb: "",
  result: "",
  actor: "",
  desde: "",
  hasta: "",
  project_id: "",
};

/**
 * Traduce el formulario a los query params de GET /operations. Los campos vacíos se omiten.
 * `from` y `to` son inclusivos: "Desde" empieza en el segundo :00 y "Hasta" termina en el :59
 * del minuto elegido, para que el último minuto también cuente.
 */
function aFiltros(formulario: Formulario): FiltrosOperaciones {
  const filtros: FiltrosOperaciones = {};
  if (formulario.verb !== "") {
    filtros.verb = formulario.verb;
  }
  if (formulario.result === "success" || formulario.result === "failure") {
    filtros.result = formulario.result;
  }
  const actor = formulario.actor.trim();
  if (actor !== "") {
    filtros.actor_user_id = actor;
  }
  if (formulario.desde !== "") {
    filtros.from = horaMexicoAIso(formulario.desde);
  }
  if (formulario.hasta !== "") {
    filtros.to = horaMexicoAIso(formulario.hasta, "59");
  }
  if (formulario.project_id !== "") {
    filtros.project_id = formulario.project_id;
  }
  return filtros;
}

/** Fecha de hoy en hora de México, AAAA-MM-DD, para el nombre del archivo. */
function hoyEnMexico(): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "America/Mexico_City" }).format(new Date());
}

/**
 * Descarga un Blob: URL temporal, un <a download> que se agrega, se pulsa y se quita, y la URL se
 * revoca en cuanto el navegador tomó la descarga (no queda una copia accesible en la página).
 */
function descargar(blob: Blob, nombre: string): void {
  const url = URL.createObjectURL(blob);
  const enlace = document.createElement("a");
  enlace.href = url;
  enlace.download = nombre;
  document.body.appendChild(enlace);
  try {
    enlace.click();
  } finally {
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}

export function OperationsTable() {
  const { usuario } = useSession();
  const proyectos = useProyectos();
  const [formulario, setFormulario] = useState<Formulario>(FORMULARIO_VACIO);
  const [filtros, setFiltros] = useState<FiltrosOperaciones>({});

  const operaciones = useInfiniteQuery({
    queryKey: ["operaciones", filtros],
    queryFn: ({ pageParam }) => listarOperaciones(filtros, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (pagina) => pagina.next_cursor,
  });

  const queryClient = useQueryClient();
  const verificacion = useMutation({
    mutationFn: verificarCadena,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["operaciones"] }),
    onError: notificarError,
  });

  // La mutación no devuelve el Blob: así no queda guardado en la caché de TanStack Query.
  const exportacion = useMutation({
    mutationFn: async (formato: FormatoExportacion) => {
      const blob = await exportarOperaciones(filtros, formato);
      descargar(blob, `bitacora-${hoyEnMexico()}.${formato}`);
    },
    onError: notificarError,
  });

  // Solo el Administrador verifica la cadena: audit:read con alcance de instancia (H-23b).
  const puedeVerificar = usuario !== null && permisosEn(usuario, null, null).has("audit:read");

  const nombreProyecto = new Map((proyectos.data ?? []).map((p) => [p.id, p.name]));

  function cambiar(campo: keyof Formulario, valor: string) {
    setFormulario((anterior) => ({ ...anterior, [campo]: valor }));
  }

  function aplicar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setFiltros(aFiltros(formulario));
  }

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Bitácora</Title>
        <Group gap="xs">
          <Button
            variant="default"
            loading={exportacion.isPending && exportacion.variables === "csv"}
            disabled={exportacion.isPending}
            onClick={() => exportacion.mutate("csv")}
          >
            Exportar CSV
          </Button>
          <Button
            variant="default"
            loading={exportacion.isPending && exportacion.variables === "json"}
            disabled={exportacion.isPending}
            onClick={() => exportacion.mutate("json")}
          >
            Exportar JSON
          </Button>
          {puedeVerificar && (
            <Button
              variant="light"
              loading={verificacion.isPending}
              onClick={() => verificacion.mutate()}
            >
              Verificar integridad
            </Button>
          )}
        </Group>
      </Group>

      {verificacion.data !== undefined && <ResultadoVerificacion reporte={verificacion.data} />}

      <form noValidate onSubmit={aplicar}>
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
          <NativeSelect
            label="Verbo"
            value={formulario.verb}
            onChange={(e) => cambiar("verb", e.currentTarget.value)}
            data={[{ value: "", label: "Todos" }, ...VERBOS]}
          />
          <NativeSelect
            label="Resultado"
            value={formulario.result}
            onChange={(e) => cambiar("result", e.currentTarget.value)}
            data={[{ value: "", label: "Todos" }, ...RESULTADOS]}
          />
          <NativeSelect
            label="Proyecto"
            value={formulario.project_id}
            onChange={(e) => cambiar("project_id", e.currentTarget.value)}
            data={[
              { value: "", label: "Todos" },
              ...(proyectos.data ?? []).map((p) => ({ value: p.id, label: p.name })),
            ]}
          />
          <TextInput
            label="Actor (ID de usuario)"
            placeholder="UUID del usuario"
            value={formulario.actor}
            onChange={(e) => cambiar("actor", e.currentTarget.value)}
          />
          <TextInput
            type="datetime-local"
            label="Desde (hora de México)"
            value={formulario.desde}
            onChange={(e) => cambiar("desde", e.currentTarget.value)}
          />
          <TextInput
            type="datetime-local"
            label="Hasta (hora de México)"
            value={formulario.hasta}
            onChange={(e) => cambiar("hasta", e.currentTarget.value)}
          />
        </SimpleGrid>
        <Group justify="flex-end" mt="sm">
          <Button
            variant="default"
            onClick={() => {
              setFormulario(FORMULARIO_VACIO);
              setFiltros({});
            }}
          >
            Limpiar
          </Button>
          <Button type="submit">Filtrar</Button>
        </Group>
      </form>

      {operaciones.isPending && <Loader size="sm" aria-label="Cargando bitácora" />}
      {operaciones.isError && <Text c="red">No se pudo cargar la bitácora.</Text>}
      {operaciones.data !== undefined && (
        <>
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Fecha</Table.Th>
                <Table.Th>Actor</Table.Th>
                <Table.Th>Verbo</Table.Th>
                <Table.Th>Recurso</Table.Th>
                <Table.Th>Resultado</Table.Th>
                <Table.Th>Proyecto</Table.Th>
                <Table.Th>IP</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {operaciones.data.pages
                .flatMap((pagina) => pagina.items)
                .map((op) => (
                  <Table.Tr key={op.id}>
                    <Table.Td>{formatearFecha(op.event_timestamp)}</Table.Td>
                    <Table.Td title={op.actor_user_id ?? undefined}>{op.actor_ref}</Table.Td>
                    <Table.Td>
                      <Code>{op.verb}</Code>
                    </Table.Td>
                    <Table.Td>
                      {op.resource_type ?? "—"}
                      {op.resource_id !== null && ` ${uuidCorto(op.resource_id)}`}
                    </Table.Td>
                    <Table.Td>
                      <Badge color={op.result === "success" ? "green" : "red"} variant="light">
                        {op.result === "success" ? "Éxito" : "Fallo"}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {op.project_id === null
                        ? "—"
                        : (nombreProyecto.get(op.project_id) ?? uuidCorto(op.project_id))}
                    </Table.Td>
                    <Table.Td>{op.ip_address ?? "—"}</Table.Td>
                  </Table.Tr>
                ))}
            </Table.Tbody>
          </Table>
          {operaciones.hasNextPage && (
            <Button
              variant="default"
              loading={operaciones.isFetchingNextPage}
              onClick={() => void operaciones.fetchNextPage()}
            >
              Cargar más
            </Button>
          )}
        </>
      )}
    </Stack>
  );
}

/** Una firma diaria con más de esto ya se perdió al menos una corrida de la tarea programada. */
const FIRMA_ATRASADA_MS = 48 * 60 * 60 * 1000;

function firmaAtrasada(reporte: ChainReport): boolean {
  return (
    reporte.last_signed_at !== null &&
    Date.now() - new Date(reporte.last_signed_at).getTime() > FIRMA_ATRASADA_MS
  );
}

/**
 * Estado de la firma diaria del cierre (H-81). La firma cubre la cadena hasta
 * `last_signed_audit_id`; lo posterior solo lo protege la cadena de hashes. Si la firma tiene más
 * de 48 h, quien tiene la BD pudo haber borrado las firmas recientes junto con el final de la
 * cadena: se avisa para que el Administrador revise la tarea programada.
 */
function EstadoFirma({ reporte }: { reporte: ChainReport }) {
  if (!reporte.signing_configured) {
    return (
      <Text size="sm">
        La firma diaria no está configurada: la integridad solo descansa en la cadena de hashes.
      </Text>
    );
  }
  if (reporte.last_signed_at === null) {
    return (
      <Text size="sm">
        Aún no hay firmas del cierre. Programa <Code>sign-chain</Code> una vez al día (guía de
        instalación).
      </Text>
    );
  }
  return (
    <>
      <Text size="sm">
        Última firma válida: {formatearFecha(reporte.last_signed_at)} (cubre hasta el registro #
        {reporte.last_signed_audit_id}). Los registros posteriores solo los protege la cadena de
        hashes.
      </Text>
      {firmaAtrasada(reporte) && (
        <Text size="sm" fw={600}>
          La firma diaria no se ha ejecutado desde {formatearFecha(reporte.last_signed_at)}; revisa
          la tarea programada.
        </Text>
      )}
    </>
  );
}

/** Lista de ids de firma (UUID completos: el Administrador los busca en `chain_signatures`). */
function IdsDeFirma({ titulo, ids }: { titulo: string; ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <Text size="sm">
      {titulo}:{" "}
      {ids.map((id, i) => (
        <span key={id}>
          {i > 0 && ", "}
          <Code>{id}</Code>
        </span>
      ))}
    </Text>
  );
}

/**
 * Resultado de verify-chain (spec §5.1). Muestra también `last_hash`: entre firmas, la cadena no
 * tiene ancla (H-46), así que el Administrador lo anota fuera del sistema y lo compara la próxima
 * vez. Con la firma diaria (H-81) se dice la fecha de la última firma válida y, si algo no
 * cuadra, qué firmas son inválidas o fueron borradas.
 */
function ResultadoVerificacion({ reporte }: { reporte: ChainReport }) {
  if (reporte.ok) {
    return (
      <Alert
        color={firmaAtrasada(reporte) ? "yellow" : "green"}
        title="Cadena verificada"
        role="alert"
      >
        <Stack gap={4}>
          <Text size="sm">La bitácora está íntegra ({reporte.total} registros verificados).</Text>
          <EstadoFirma reporte={reporte} />
          {reporte.last_hash !== null && (
            <Text size="xs" c="dimmed">
              Último hash (anótalo fuera del sistema): <Code>{reporte.last_hash}</Code>
            </Text>
          )}
        </Stack>
      </Alert>
    );
  }
  return (
    <Alert color="red" title="La bitácora fue alterada" role="alert">
      <Stack gap={4}>
        {reporte.broken.length > 0 && (
          <Text size="sm">
            {reporte.broken.length === 1 ? "Fila alterada" : "Filas alteradas"}:{" "}
            {reporte.broken.join(", ")} (de {reporte.total} registros).
          </Text>
        )}
        <IdsDeFirma titulo="Firmas inválidas" ids={reporte.invalid_signatures} />
        <IdsDeFirma titulo="Firmas borradas" ids={reporte.missing_signatures} />
      </Stack>
    </Alert>
  );
}
