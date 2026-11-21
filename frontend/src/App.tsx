// Composición del Dashboard: tema (Mantine), caché de consultas (TanStack Query), rutas (React
// Router) y sesión. Las rutas con sesión pasan por ProtectedRoute y se dibujan dentro de AppLayout.
// Los errores de las consultas se notifican en español con el problem+json (RF-029).
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";

import { notificarError } from "./api/problem";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { SessionProvider } from "./auth/SessionProvider";
import { AppLayout } from "./layout/AppLayout";
import { LoginPage } from "./pages/LoginPage";
import { OperationsTable } from "./operations/OperationsTable";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ProjectDetailPage } from "./projects/ProjectDetailPage";
import { ProjectsPage } from "./projects/ProjectsPage";
import { EnvironmentSecretsPage } from "./secrets/EnvironmentSecretsPage";
import { SecretDetailPage } from "./secrets/SecretDetailPage";
import { UserDetailPage } from "./users/UserDetailPage";
import { UsersPage } from "./users/UsersPage";

/** Reintenta una vez los errores de red o del servidor (5xx); un 4xx no cambia al repetirlo. */
function reintentar(fallos: number, error: unknown): boolean {
  if (isAxiosError(error) && error.response !== undefined && error.response.status < 500) {
    return false;
  }
  return fallos < 1;
}

const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: notificarError }),
  defaultOptions: { queries: { retry: reintentar } },
});

export function App() {
  return (
    <MantineProvider>
      <Notifications position="top-right" />
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <SessionProvider>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route element={<ProtectedRoute />}>
                <Route element={<AppLayout />}>
                  <Route index element={<Navigate to="/proyectos" replace />} />
                  <Route path="proyectos" element={<ProjectsPage />} />
                  <Route path="proyectos/:pid" element={<ProjectDetailPage />} />
                  <Route
                    path="proyectos/:pid/ambientes/:eid"
                    element={<EnvironmentSecretsPage />}
                  />
                  <Route
                    path="proyectos/:pid/ambientes/:eid/secretos/:sid"
                    element={<SecretDetailPage />}
                  />
                  <Route path="bitacora" element={<OperationsTable />} />
                  <Route path="usuarios" element={<UsersPage />} />
                  <Route path="usuarios/:uid" element={<UserDetailPage />} />
                  <Route path="*" element={<NotFoundPage />} />
                </Route>
              </Route>
            </Routes>
          </SessionProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </MantineProvider>
  );
}
