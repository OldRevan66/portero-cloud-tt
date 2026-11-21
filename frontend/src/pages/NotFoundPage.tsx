import { Anchor, Stack, Text, Title } from "@mantine/core";
import { Link } from "react-router";

export function NotFoundPage() {
  return (
    <Stack gap="xs">
      <Title order={2}>Página no encontrada</Title>
      <Text c="dimmed">La dirección no existe o no tienes acceso a ella.</Text>
      <Anchor component={Link} to="/proyectos">
        Ir a Proyectos
      </Anchor>
    </Stack>
  );
}
