// Árbol de navegación proyecto → ambiente → secretos (RF-027).
//
// Muestra exactamente lo que responde el API: GET /projects y GET /projects/{pid}/environments
// ya vienen filtrados por las asignaciones del usuario (spec §4.2, H-23c, H-23d). Los ambientes
// de un proyecto se piden solo al abrirlo.
import { Anchor, Group, List, Loader, Stack, Text, UnstyledButton } from "@mantine/core";
import { useState } from "react";
import { Link } from "react-router";

import type { ProjectOut } from "./projectsApi";
import { useAmbientes, useProyectos } from "./queries";

export function ProjectTree() {
  const proyectos = useProyectos();

  if (proyectos.isPending) {
    return <Loader size="sm" aria-label="Cargando proyectos" />;
  }
  if (proyectos.isError) {
    return <Text c="red">No se pudieron cargar los proyectos.</Text>;
  }
  if (proyectos.data.length === 0) {
    return <Text c="dimmed">No tienes proyectos asignados todavía.</Text>;
  }
  return (
    <Stack gap="xs">
      {proyectos.data.map((proyecto) => (
        <NodoProyecto key={proyecto.id} proyecto={proyecto} />
      ))}
    </Stack>
  );
}

function NodoProyecto({ proyecto }: { proyecto: ProjectOut }) {
  const [abierto, setAbierto] = useState(false);
  const ambientes = useAmbientes(proyecto.id, abierto);

  return (
    <div>
      <Group gap="sm" wrap="nowrap">
        <UnstyledButton aria-expanded={abierto} onClick={() => setAbierto((valor) => !valor)}>
          <Group gap={6} wrap="nowrap">
            <Text component="span" aria-hidden>
              {abierto ? "▾" : "▸"}
            </Text>
            <Text component="span" fw={600}>
              {proyecto.name}
            </Text>
          </Group>
        </UnstyledButton>
        {proyecto.description !== null && (
          <Text size="sm" c="dimmed" truncate>
            {proyecto.description}
          </Text>
        )}
        <Anchor component={Link} to={`/proyectos/${proyecto.id}`} size="sm">
          Detalle
        </Anchor>
      </Group>
      {abierto && (
        <div style={{ paddingLeft: 24, paddingTop: 4 }}>
          {ambientes.isPending && <Loader size="xs" aria-label="Cargando ambientes" />}
          {ambientes.isError && <Text c="red">No se pudieron cargar los ambientes.</Text>}
          {ambientes.data?.length === 0 && (
            <Text size="sm" c="dimmed">
              Sin ambientes visibles.
            </Text>
          )}
          {ambientes.data !== undefined && ambientes.data.length > 0 && (
            <List listStyleType="none" spacing={4} aria-label={`Ambientes de ${proyecto.name}`}>
              {ambientes.data.map((ambiente) => (
                <List.Item key={ambiente.id}>
                  <Anchor
                    component={Link}
                    to={`/proyectos/${proyecto.id}/ambientes/${ambiente.id}`}
                  >
                    {ambiente.name}
                  </Anchor>
                </List.Item>
              ))}
            </List>
          )}
        </div>
      )}
    </div>
  );
}
