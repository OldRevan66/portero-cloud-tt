// Detalle de un proyecto con sus ambientes (CU-07, RF-027). Editar o archivar el proyecto, crear,
// editar o eliminar ambientes y gestionar sus Aplicaciones Cliente (spec §8.2, H-23a) solo con
// projects:manage en el proyecto (Administrador, Líder Técnico del proyecto).
//
// H-77 (decisión del 29 oct): "Archivar proyecto" sigue a la API (projects:manage), igual que
// "Editar proyecto". Los dos 409 se muestran con el title y el detail del API (RF-029):
// - archivar con secretos activos: segunda confirmación que reintenta con ?confirm=true (RF-032);
// - eliminar un ambiente con secretos (H-39): solo se informa; no hay forma de forzarlo.
import {
  Alert,
  Anchor,
  Breadcrumbs,
  Button,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { notificarExito, problemaDe, type Problema } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha } from "../lib/formato";
import { esUuid } from "../lib/identificadores";
import { NotFoundPage } from "../pages/NotFoundPage";
import { ServiceAccountsSection } from "../serviceAccounts/ServiceAccountsSection";
import { NombreDescripcionForm } from "./NombreDescripcionForm";
import {
  MAX_NOMBRE_AMBIENTE,
  MAX_NOMBRE_PROYECTO,
  type EnvironmentOut,
  type ProjectOut,
} from "./projectsApi";
import {
  useActualizarAmbiente,
  useActualizarProyecto,
  useAmbientes,
  useArchivarProyecto,
  useCrearAmbiente,
  useEliminarAmbiente,
  useProyecto,
} from "./queries";

/** Sin un UUID válido en la URL no se hace ninguna petición (H-62). */
export function ProjectDetailPage() {
  const { pid = "" } = useParams();
  if (!esUuid(pid)) {
    return <NotFoundPage />;
  }
  return <DetalleProyecto pid={pid} />;
}

function DetalleProyecto({ pid }: { pid: string }) {
  const { usuario } = useSession();
  const proyecto = useProyecto(pid);
  const ambientes = useAmbientes(pid);
  const actualizarProyecto = useActualizarProyecto(pid);
  const crearAmbiente = useCrearAmbiente(pid);
  const actualizarAmbiente = useActualizarAmbiente(pid);
  const [editarAbierto, editar] = useDisclosure(false);
  const [archivarAbierto, archivar] = useDisclosure(false);
  const [nuevoAbierto, nuevo] = useDisclosure(false);
  const [ambienteEnEdicion, setAmbienteEnEdicion] = useState<EnvironmentOut | null>(null);
  const [ambienteAEliminar, setAmbienteAEliminar] = useState<EnvironmentOut | null>(null);

  const puedeGestionar = usuario !== null && permisosEn(usuario, pid, null).has("projects:manage");

  if (proyecto.isPending) {
    return <Loader size="sm" aria-label="Cargando proyecto" />;
  }
  if (proyecto.isError) {
    return <Text c="red">No se encontró el proyecto o no tienes acceso a él.</Text>;
  }

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/proyectos">
          Proyectos
        </Anchor>
        <Text>{proyecto.data.name}</Text>
      </Breadcrumbs>

      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{proyecto.data.name}</Title>
          {proyecto.data.description !== null && (
            <Text c="dimmed">{proyecto.data.description}</Text>
          )}
        </div>
        {puedeGestionar && (
          <Group gap="xs">
            <Button variant="default" onClick={editar.open}>
              Editar proyecto
            </Button>
            <Button variant="light" color="red" onClick={archivar.open}>
              Archivar proyecto
            </Button>
          </Group>
        )}
      </Group>

      <Group justify="space-between">
        <Title order={3}>Ambientes</Title>
        {puedeGestionar && <Button onClick={nuevo.open}>Nuevo ambiente</Button>}
      </Group>

      {ambientes.isPending && <Loader size="sm" aria-label="Cargando ambientes" />}
      {ambientes.isError && <Text c="red">No se pudieron cargar los ambientes.</Text>}
      {ambientes.data !== undefined && (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Nombre</Table.Th>
              <Table.Th>Descripción</Table.Th>
              <Table.Th>Creado</Table.Th>
              {puedeGestionar && <Table.Th>Acciones</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {ambientes.data.map((ambiente) => (
              <Table.Tr key={ambiente.id}>
                <Table.Td>
                  <Anchor component={Link} to={`/proyectos/${pid}/ambientes/${ambiente.id}`}>
                    {ambiente.name}
                  </Anchor>
                </Table.Td>
                <Table.Td>{ambiente.description ?? "—"}</Table.Td>
                <Table.Td>{formatearFecha(ambiente.created_at)}</Table.Td>
                {puedeGestionar && (
                  <Table.Td>
                    <Group gap="xs">
                      <Button
                        size="xs"
                        variant="default"
                        onClick={() => setAmbienteEnEdicion(ambiente)}
                      >
                        Editar
                      </Button>
                      <Button
                        size="xs"
                        variant="light"
                        color="red"
                        onClick={() => setAmbienteAEliminar(ambiente)}
                      >
                        Eliminar
                      </Button>
                    </Group>
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {puedeGestionar && <ServiceAccountsSection pid={pid} />}

      <Modal
        opened={editarAbierto}
        onClose={editar.close}
        title="Editar proyecto"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <NombreDescripcionForm
          maxNombre={MAX_NOMBRE_PROYECTO}
          inicial={proyecto.data}
          textoBoton="Guardar"
          onGuardar={async (datos) => {
            await actualizarProyecto.mutateAsync(datos);
            notificarExito("Proyecto actualizado.");
          }}
          onTerminado={editar.close}
        />
      </Modal>

      <Modal
        opened={nuevoAbierto}
        onClose={nuevo.close}
        title="Nuevo ambiente"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <NombreDescripcionForm
          maxNombre={MAX_NOMBRE_AMBIENTE}
          textoBoton="Crear ambiente"
          onGuardar={async (datos) => {
            const ambiente = await crearAmbiente.mutateAsync(datos);
            notificarExito(`Ambiente ${ambiente.name} creado.`);
          }}
          onTerminado={nuevo.close}
        />
      </Modal>

      <Modal
        opened={ambienteEnEdicion !== null}
        onClose={() => setAmbienteEnEdicion(null)}
        title="Editar ambiente"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        {ambienteEnEdicion !== null && (
          <NombreDescripcionForm
            maxNombre={MAX_NOMBRE_AMBIENTE}
            inicial={ambienteEnEdicion}
            textoBoton="Guardar"
            onGuardar={async (datos) => {
              await actualizarAmbiente.mutateAsync({ eid: ambienteEnEdicion.id, cuerpo: datos });
              notificarExito("Ambiente actualizado.");
            }}
            onTerminado={() => setAmbienteEnEdicion(null)}
          />
        )}
      </Modal>

      <Modal
        opened={archivarAbierto}
        onClose={archivar.close}
        title="Archivar proyecto"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <ConfirmarArchivarProyecto proyecto={proyecto.data} onCancelar={archivar.close} />
      </Modal>

      <Modal
        opened={ambienteAEliminar !== null}
        onClose={() => setAmbienteAEliminar(null)}
        title="Eliminar ambiente"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        {ambienteAEliminar !== null && (
          <ConfirmarEliminarAmbiente
            pid={pid}
            ambiente={ambienteAEliminar}
            onTerminado={() => setAmbienteAEliminar(null)}
          />
        )}
      </Modal>
    </Stack>
  );
}

/**
 * Archivar el proyecto (RF-032, H-77). Primero se pide sin `confirm`: si el proyecto tiene
 * secretos activos, el API responde 409 y aquí se muestra su `detail` con una segunda
 * confirmación, que reintenta con `?confirm=true`. Así nadie archiva secretos sin saberlo.
 */
function ConfirmarArchivarProyecto({
  proyecto,
  onCancelar,
}: {
  proyecto: ProjectOut;
  onCancelar: () => void;
}) {
  const navigate = useNavigate();
  const archivado = useArchivarProyecto(proyecto.id);
  const [conSecretos, setConSecretos] = useState<Problema | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);

  function archivar(confirmar: boolean) {
    setErrorApi(null);
    archivado.mutate(confirmar, {
      onSuccess: () => {
        notificarExito(`Proyecto ${proyecto.name} archivado.`);
        void navigate("/proyectos");
      },
      onError: (error) => {
        const problema = problemaDe(error);
        if (problema.status === 409 && !confirmar) {
          setConSecretos(problema);
        } else {
          setErrorApi(problema);
        }
      },
    });
  }

  return (
    <Stack gap="sm">
      {conSecretos === null ? (
        <Text size="sm">
          ¿Archivar <strong>{proyecto.name}</strong>? Dejará de verse en el Dashboard y sus
          aplicaciones ya no podrán leer sus secretos. El historial se conserva en la bitácora.
        </Text>
      ) : (
        <Alert color="yellow" title={conSecretos.titulo}>
          {conSecretos.detalle} Si continúas, sus secretos activos también se archivan.
        </Alert>
      )}
      {errorApi !== null && (
        <Alert color="red" title={errorApi.titulo} role="alert">
          {errorApi.detalle}
        </Alert>
      )}
      <Group justify="flex-end">
        <Button variant="default" onClick={onCancelar}>
          Cancelar
        </Button>
        {conSecretos === null ? (
          <Button color="red" loading={archivado.isPending} onClick={() => archivar(false)}>
            Archivar
          </Button>
        ) : (
          <Button color="red" loading={archivado.isPending} onClick={() => archivar(true)}>
            Archivar proyecto y sus secretos
          </Button>
        )}
      </Group>
    </Stack>
  );
}

/**
 * Eliminar un ambiente (H-77). El API lo borra solo si no tiene secretos, ni activos ni
 * archivados, ni Aplicaciones Cliente; si no, responde 409 (H-39) y aquí se muestra su `title` y
 * su `detail`.
 */
function ConfirmarEliminarAmbiente({
  pid,
  ambiente,
  onTerminado,
}: {
  pid: string;
  ambiente: EnvironmentOut;
  onTerminado: () => void;
}) {
  const eliminado = useEliminarAmbiente(pid);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);

  function eliminar() {
    setErrorApi(null);
    eliminado.mutate(ambiente.id, {
      onSuccess: () => {
        notificarExito(`Ambiente ${ambiente.name} eliminado.`);
        onTerminado();
      },
      onError: (error) => setErrorApi(problemaDe(error)),
    });
  }

  return (
    <Stack gap="sm">
      <Text size="sm">
        ¿Eliminar el ambiente <strong>{ambiente.name}</strong>? Solo es posible si nunca tuvo
        secretos ni Aplicaciones Cliente. No se puede deshacer.
      </Text>
      {errorApi !== null && (
        <Alert color="red" title={errorApi.titulo} role="alert">
          {errorApi.detalle}
        </Alert>
      )}
      <Group justify="flex-end">
        <Button variant="default" onClick={onTerminado}>
          Cancelar
        </Button>
        <Button color="red" loading={eliminado.isPending} onClick={eliminar}>
          Eliminar ambiente
        </Button>
      </Group>
    </Stack>
  );
}
