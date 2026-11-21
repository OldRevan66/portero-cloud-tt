// Secretos de un ambiente (RF-027, CU-02, CU-03): lista de metadatos y, con secrets:write en el
// ambiente, "Nuevo secreto". La lista nunca trae valores (spec §2).
import {
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
import { useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router";

import { notificarExito } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha } from "../lib/formato";
import { esUuid } from "../lib/identificadores";
import { NotFoundPage } from "../pages/NotFoundPage";
import { useAmbientes, useProyecto } from "../projects/queries";
import { invalidarTrasCambio, useSecretos } from "./queries";
import { SecretForm } from "./SecretForm";

/** Sin UUID válidos en la URL no se hace ninguna petición (H-62). */
export function EnvironmentSecretsPage() {
  const { pid = "", eid = "" } = useParams();
  if (![pid, eid].every(esUuid)) {
    return <NotFoundPage />;
  }
  return <SecretosDelAmbiente pid={pid} eid={eid} />;
}

function SecretosDelAmbiente({ pid, eid }: { pid: string; eid: string }) {
  const { usuario } = useSession();
  const queryClient = useQueryClient();
  const proyecto = useProyecto(pid);
  const ambientes = useAmbientes(pid);
  const secretos = useSecretos(pid, eid);
  const [nuevoAbierto, nuevo] = useDisclosure(false);

  const ambiente = ambientes.data?.find((a) => a.id === eid);
  const puedeCrear = usuario !== null && permisosEn(usuario, pid, eid).has("secrets:write");

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/proyectos">
          Proyectos
        </Anchor>
        <Anchor component={Link} to={`/proyectos/${pid}`}>
          {proyecto.data?.name ?? "Proyecto"}
        </Anchor>
        <Text>{ambiente?.name ?? "Ambiente"}</Text>
      </Breadcrumbs>

      <Group justify="space-between">
        <Title order={2}>Secretos de {ambiente?.name ?? "este ambiente"}</Title>
        {puedeCrear && <Button onClick={nuevo.open}>Nuevo secreto</Button>}
      </Group>

      {secretos.isPending && <Loader size="sm" aria-label="Cargando secretos" />}
      {secretos.isError && (
        <Text c="red">No se encontró el ambiente o no tienes acceso a sus secretos.</Text>
      )}
      {secretos.data?.length === 0 && <Text c="dimmed">Este ambiente no tiene secretos.</Text>}
      {secretos.data !== undefined && secretos.data.length > 0 && (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Nombre</Table.Th>
              <Table.Th>Versión</Table.Th>
              <Table.Th>Descripción</Table.Th>
              <Table.Th>Actualizado</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {secretos.data.map((secreto) => (
              <Table.Tr key={secreto.id}>
                <Table.Td>
                  <Anchor
                    component={Link}
                    to={`/proyectos/${pid}/ambientes/${eid}/secretos/${secreto.id}`}
                    ff="monospace"
                  >
                    {secreto.name}
                  </Anchor>
                </Table.Td>
                <Table.Td>v{secreto.version}</Table.Td>
                <Table.Td>{secreto.description ?? "—"}</Table.Td>
                <Table.Td>{formatearFecha(secreto.updated_at)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
        opened={nuevoAbierto}
        onClose={nuevo.close}
        title="Nuevo secreto"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <SecretForm
          projectId={pid}
          environmentId={eid}
          onCreado={(secreto) => {
            nuevo.close();
            notificarExito(`Secreto ${secreto.name} creado.`);
            void invalidarTrasCambio(queryClient, pid, eid);
          }}
        />
      </Modal>
    </Stack>
  );
}
