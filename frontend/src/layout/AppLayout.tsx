// Estructura de la aplicación con sesión: encabezado con el usuario, "Cambiar contraseña" (para
// cualquier usuario, spec §3.6) y "Cerrar sesión", y barra
// lateral con las entradas que permite su rol (spec §8.2, calculadas por `menuFor`).
import { AppShell, Burger, Button, Group, NavLink, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Link, Outlet, useLocation } from "react-router";

import { CambiarContrasena } from "../auth/CambiarContrasena";
import { useSession } from "../auth/SessionProvider";
import { ErrorBoundary } from "./ErrorBoundary";

export function AppLayout() {
  const sesion = useSession();
  const location = useLocation();
  const [menuAbierto, { toggle, close }] = useDisclosure();

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !menuAbierto } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger
              opened={menuAbierto}
              onClick={toggle}
              hiddenFrom="sm"
              size="sm"
              aria-label="Abrir o cerrar el menú"
            />
            <Title order={4}>Portero Cloud</Title>
          </Group>
          <Group gap="sm" wrap="nowrap">
            <Text size="sm" visibleFrom="xs" truncate>
              {sesion.usuario?.name ?? sesion.usuario?.email}
            </Text>
            <CambiarContrasena />
            <Button variant="default" size="xs" onClick={() => void sesion.cerrarSesion()}>
              Cerrar sesión
            </Button>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs" aria-label="Menú principal">
        {sesion.menu.map((entrada) => (
          <NavLink
            key={entrada.path}
            component={Link}
            to={entrada.path}
            label={entrada.label}
            active={location.pathname.startsWith(entrada.path)}
            onClick={close}
          />
        ))}
      </AppShell.Navbar>

      <AppShell.Main>
        {/* La key reinicia la frontera de errores en cada pantalla (H-62). */}
        <ErrorBoundary key={location.pathname}>
          <Outlet />
        </ErrorBoundary>
      </AppShell.Main>
    </AppShell>
  );
}
