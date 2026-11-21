// Detalle de un secreto (CU-03, CU-04): metadatos, revelar valor, rotar, archivar e historial.
import {
  Anchor,
  Badge,
  Breadcrumbs,
  Group,
  Loader,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router";

import { formatearFecha, uuidCorto } from "../lib/formato";
import { esUuid } from "../lib/identificadores";
import { NotFoundPage } from "../pages/NotFoundPage";
import { useAmbientes, useProyecto } from "../projects/queries";
import { useSecreto } from "./queries";
import { RevealValue } from "./RevealValue";
import { SecretActions } from "./SecretActions";
import { VersionHistory } from "./VersionHistory";

function Dato({ etiqueta, children }: { etiqueta: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed">
        {etiqueta}
      </Text>
      <Text size="sm">{children}</Text>
    </div>
  );
}

/**
 * Los identificadores vienen de la URL, que cualquiera puede escribir: si alguno no es UUID no
 * se hace ninguna petición (H-62). Así "<sid>%2Fvalue" no se convierte en GET /secrets/{id}/value.
 */
export function SecretDetailPage() {
  const { pid = "", eid = "", sid = "" } = useParams();
  if (![pid, eid, sid].every(esUuid)) {
    return <NotFoundPage />;
  }
  return <DetalleSecreto pid={pid} eid={eid} sid={sid} />;
}

function DetalleSecreto({ pid, eid, sid }: { pid: string; eid: string; sid: string }) {
  const proyecto = useProyecto(pid);
  const ambientes = useAmbientes(pid);
  const secreto = useSecreto(sid);
  const ambiente = ambientes.data?.find((a) => a.id === eid);

  if (secreto.isPending) {
    return <Loader size="sm" aria-label="Cargando secreto" />;
  }
  if (secreto.isError) {
    return <Text c="red">No se encontró el secreto o no tienes acceso a él.</Text>;
  }
  const datos = secreto.data;

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/proyectos">
          Proyectos
        </Anchor>
        <Anchor component={Link} to={`/proyectos/${pid}`}>
          {proyecto.data?.name ?? "Proyecto"}
        </Anchor>
        <Anchor component={Link} to={`/proyectos/${pid}/ambientes/${eid}`}>
          {ambiente?.name ?? "Ambiente"}
        </Anchor>
        <Text>{datos.name}</Text>
      </Breadcrumbs>

      <Group justify="space-between">
        <Group gap="sm">
          <Title order={2} ff="monospace">
            {datos.name}
          </Title>
          <Badge variant="light">v{datos.version}</Badge>
        </Group>
        <SecretActions secret={datos} />
      </Group>

      <Paper withBorder p="md">
        <Stack gap="sm">
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <Dato etiqueta="Descripción">{datos.description ?? "—"}</Dato>
            <Dato etiqueta="Creado por">
              <span title={datos.created_by}>{uuidCorto(datos.created_by)}</span>
            </Dato>
            <Dato etiqueta="Creado">{formatearFecha(datos.created_at)}</Dato>
            <Dato etiqueta="Actualizado">{formatearFecha(datos.updated_at)}</Dato>
          </SimpleGrid>
          <div>
            <Text size="xs" c="dimmed">
              Valor
            </Text>
            {/* La clave incluye la versión: al rotar se desmonta y el valor anterior se borra. */}
            <RevealValue key={`${datos.id}-${datos.version}`} secretId={datos.id} />
          </div>
        </Stack>
      </Paper>

      <VersionHistory secretId={datos.id} />
    </Stack>
  );
}
