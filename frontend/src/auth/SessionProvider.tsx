// Proveedor de sesión del Dashboard (spec §8.3, H-36).
//
// - Al montar intenta POST /auth/refresh: si la cookie HttpOnly sigue vigente, se recupera la
//   sesión aunque la página se haya recargado (el access token en memoria se pierde al recargar).
// - Con token, carga GET /auth/me (spec §3.4) y calcula el menú con `menuFor` (spec §8.2).
//   /auth/me sí usa TanStack Query: son metadatos, nunca valores de secretos (spec §8.4).
// - El token se lee de `tokenStore` con useSyncExternalStore: si el interceptor lo borra porque
//   la sesión expiró, el estado pasa a "anonimo" y ProtectedRoute manda a /login.
// - Cerrar sesión: /auth/logout, borrar el token y vaciar la caché de TanStack (spec §8.3).
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";

import { api, configureSession, logout, refreshSession } from "../api/client";
import { menuFor, type Me, type MenuEntry } from "./permissions";
import { getAccessToken, subscribe } from "./tokenStore";

export type EstadoSesion = "cargando" | "anonimo" | "autenticado" | "error";

export interface Sesion {
  estado: EstadoSesion;
  usuario: Me | null;
  menu: MenuEntry[];
  cerrarSesion: () => Promise<void>;
}

const SesionContext = createContext<Sesion | null>(null);

async function obtenerUsuario(): Promise<Me> {
  const { data } = await api.get<Me>("/auth/me");
  return data;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const token = useSyncExternalStore(subscribe, getAccessToken);
  const [recuperando, setRecuperando] = useState(true);
  const queryClient = useQueryClient();

  // Si la sesión expira, nada de la caché del usuario anterior debe sobrevivir.
  useEffect(() => {
    configureSession({ onSessionExpired: () => queryClient.clear() });
  }, [queryClient]);

  // Recuperar la sesión desde la cookie. refreshSession es de vuelo único: aunque StrictMode
  // ejecute este efecto dos veces, sale un solo refresh (H-43).
  useEffect(() => {
    refreshSession()
      .catch(() => undefined) // Sin cookie válida: no hay sesión, se mostrará el login.
      .finally(() => setRecuperando(false));
  }, []);

  const me = useQuery({
    queryKey: ["auth", "me"],
    queryFn: obtenerUsuario,
    enabled: token !== null,
    staleTime: Infinity,
  });

  const cerrarSesion = useCallback(async () => {
    await logout();
    queryClient.clear();
  }, [queryClient]);

  const sesion = useMemo<Sesion>(() => {
    const base = { usuario: null, menu: [], cerrarSesion };
    if (token === null) {
      return { ...base, estado: recuperando ? "cargando" : "anonimo" };
    }
    if (me.isError) {
      return { ...base, estado: "error" };
    }
    if (me.data === undefined) {
      return { ...base, estado: "cargando" };
    }
    return { estado: "autenticado", usuario: me.data, menu: menuFor(me.data), cerrarSesion };
  }, [token, recuperando, me.isError, me.data, cerrarSesion]);

  return <SesionContext.Provider value={sesion}>{children}</SesionContext.Provider>;
}

/** Sesión actual. Solo se usa dentro de <SessionProvider>. */
export function useSession(): Sesion {
  const sesion = useContext(SesionContext);
  if (sesion === null) {
    throw new Error("useSession debe usarse dentro de <SessionProvider>");
  }
  return sesion;
}
