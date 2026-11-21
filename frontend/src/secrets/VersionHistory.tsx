// Historial de versiones de un secreto, paginado con el cursor opaco del API (spec §1, §2).
// Solo metadatos: versión, fecha, autor y algoritmo AEAD; nunca valores.
import { Button, Loader, Stack, Table, Text, Title } from "@mantine/core";

import { formatearFecha, uuidCorto } from "../lib/formato";
import { useVersiones } from "./queries";

export function VersionHistory({ secretId }: { secretId: string }) {
  const versiones = useVersiones(secretId);

  return (
    <Stack gap="xs">
      <Title order={3}>Historial de versiones</Title>
      {versiones.isPending && <Loader size="sm" aria-label="Cargando versiones" />}
      {versiones.isError && <Text c="red">No se pudo cargar el historial.</Text>}
      {versiones.data !== undefined && (
        <>
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Versión</Table.Th>
                <Table.Th>Fecha</Table.Th>
                <Table.Th>Autor</Table.Th>
                <Table.Th>Algoritmo</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {versiones.data.pages
                .flatMap((pagina) => pagina.items)
                .map((version) => (
                  <Table.Tr key={version.version}>
                    <Table.Td>v{version.version}</Table.Td>
                    <Table.Td>{formatearFecha(version.created_at)}</Table.Td>
                    <Table.Td title={version.created_by} ff="monospace">
                      {uuidCorto(version.created_by)}
                    </Table.Td>
                    <Table.Td>{version.aead_algorithm}</Table.Td>
                  </Table.Tr>
                ))}
            </Table.Tbody>
          </Table>
          {versiones.hasNextPage && (
            <Button
              variant="default"
              loading={versiones.isFetchingNextPage}
              onClick={() => void versiones.fetchNextPage()}
            >
              Cargar más
            </Button>
          )}
        </>
      )}
    </Stack>
  );
}
