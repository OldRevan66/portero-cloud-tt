// Ruta protegida: solo deja pasar con sesión (spec §8.3). Sin sesión manda a /login y recuerda
// a dónde se quería ir. La autoridad sigue siendo el backend; esto solo evita pantallas vacías.
import { Alert, Button, Center, Loader, Stack } from "@mantine/core";
import { Navigate, Outlet, useLocation } from "react-router";

import { useSession } from "./SessionProvider";

export function ProtectedRoute() {
  const sesion = useSession();
  const location = useLocation();

  switch (sesion.estado) {
    case "cargando":
      return (
        <Center h="100vh">
          <Loader aria-label="Cargando sesión" />
        </Center>
      );
    case "anonimo":
      return <Navigate to="/login" replace state={{ desde: location.pathname }} />;
    case "error":
      return (
        <Center h="100vh">
          <Stack maw={420}>
            <Alert color="red" title="No se pudo cargar tu sesión">
              Inténtalo de nuevo en unos minutos.
            </Alert>
            <Button variant="default" onClick={() => void sesion.cerrarSesion()}>
              Cerrar sesión
            </Button>
          </Stack>
        </Center>
      );
    case "autenticado":
      return <Outlet />;
  }
}
