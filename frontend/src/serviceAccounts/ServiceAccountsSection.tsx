// Aplicaciones Cliente del proyecto (spec §8.2; H-21, H-23a): crear, listar y revocar.
//
// Se muestra dentro de /proyectos/:pid solo con projects:manage en el proyecto (Administrador o
// Líder Técnico del proyecto); quien la monta decide con `permisosEn`. La autoridad es el backend.
// La lista solo trae metadatos: del token se ve únicamente `token_prefix`.
import {
  Badge,
  Button,
  Code,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { useState } from "react";

import { notificarError, notificarExito } from "../api/problem";
import { formatearFecha } from "../lib/formato";
import { useAmbientes } from "../projects/queries";
import { CreateServiceAccount } from "./CreateServiceAccount";
import { useAplicaciones, useRevocarAplicacion } from "./queries";
import type { ServiceAccountOut } from "./serviceAccountsApi";

export function ServiceAccountsSection({ pid }: { pid: string }) {
  const aplicaciones = useAplicaciones(pid);
  const ambientes = useAmbientes(pid);
  const [porRevocar, setPorRevocar] = useState<ServiceAccountOut | null>(null);

  const nombreAmbiente = new Map((ambientes.data ?? []).map((a) => [a.id, a.name]));

  return (
    <Stack gap="xs">
      <Group justify="space-between">
        <Title order={3}>Aplicaciones Cliente</Title>
        <CreateServiceAccount pid={pid} />
      </Group>

      {aplicaciones.isPending && <Loader size="sm" aria-label="Cargando aplicaciones" />}
      {aplicaciones.isError && <Text c="red">No se pudieron cargar las aplicaciones.</Text>}
      {aplicaciones.data !== undefined && aplicaciones.data.length === 0 && (
        <Text c="dimmed">Este proyecto no tiene Aplicaciones Cliente.</Text>
      )}
      {aplicaciones.data !== undefined && aplicaciones.data.length > 0 && (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Nombre</Table.Th>
              <Table.Th>Alcance</Table.Th>
              <Table.Th>Token</Table.Th>
              <Table.Th>Creada</Table.Th>
              <Table.Th>Último uso</Table.Th>
              <Table.Th>Expira</Table.Th>
              <Table.Th>Estado</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {aplicaciones.data.map((sa) => (
              <Table.Tr key={sa.id}>
                <Table.Td>{sa.name}</Table.Td>
                <Table.Td>
                  {sa.environment_id === null
                    ? "Todo el proyecto"
                    : (nombreAmbiente.get(sa.environment_id) ?? "Ambiente")}
                </Table.Td>
                <Table.Td>
                  {/* H-42: token_prefix son los últimos 8 caracteres del PAT. */}
                  <Code>termina en {sa.token_prefix}</Code>
                </Table.Td>
                <Table.Td>{formatearFecha(sa.created_at)}</Table.Td>
                <Table.Td>
                  {sa.last_used_at === null ? "—" : formatearFecha(sa.last_used_at)}
                </Table.Td>
                <Table.Td>
                  {sa.expires_at === null ? "Sin vencimiento" : formatearFecha(sa.expires_at)}
                </Table.Td>
                <Table.Td>
                  {sa.revoked_at !== null ? (
                    <Badge color="gray" variant="light">
                      Revocada
                    </Badge>
                  ) : (
                    <Button size="xs" variant="light" color="red" onClick={() => setPorRevocar(sa)}>
                      Revocar
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
        opened={porRevocar !== null}
        onClose={() => setPorRevocar(null)}
        title="Revocar Aplicación Cliente"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        {porRevocar !== null && (
          <ConfirmarRevocar
            pid={pid}
            aplicacion={porRevocar}
            onTerminado={() => setPorRevocar(null)}
          />
        )}
      </Modal>
    </Stack>
  );
}

function ConfirmarRevocar({
  pid,
  aplicacion,
  onTerminado,
}: {
  pid: string;
  aplicacion: ServiceAccountOut;
  onTerminado: () => void;
}) {
  const revocada = useRevocarAplicacion(pid);

  function confirmar() {
    revocada.mutate(aplicacion.id, {
      onSuccess: () => {
        notificarExito(`${aplicacion.name} revocada.`);
        onTerminado();
      },
      onError: notificarError,
    });
  }

  return (
    <Stack gap="sm">
      <Text size="sm">
        ¿Revocar <strong>{aplicacion.name}</strong>? Su token deja de funcionar de inmediato y no se
        puede reactivar.
      </Text>
      <Group justify="flex-end">
        <Button variant="default" onClick={onTerminado}>
          Cancelar
        </Button>
        <Button color="red" loading={revocada.isPending} onClick={confirmar}>
          Revocar
        </Button>
      </Group>
    </Stack>
  );
}
