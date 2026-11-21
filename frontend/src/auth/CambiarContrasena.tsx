// "Cambiar contraseña" para cualquier usuario humano (spec §3.6, §8.3, §8.4; H-37, H-74).
//
// Vive en auth/ y no en users/: users/ es la gestión de otros usuarios y exige users:manage; esto
// solo pide ser humano y termina la sesión, como "Cerrar sesión".
//
// - `cambiarContrasena` se llama directo, nunca con useMutation: el cuerpo lleva contraseñas y la
//   caché de mutaciones de TanStack conservaría las variables (spec §8.4). Las contraseñas viven
//   solo en el useState del formulario, que se monta con el modal abierto: al cerrarlo se
//   descartan. Nunca van a console, a la URL (preventDefault) ni a una notificación.
// - Si la nueva y la confirmación no coinciden, el error es local y no se llama al API.
// - 401 (contraseña actual incorrecta) → mensaje fijo, sin el detail del servidor, como el login.
//   El interceptor no lo confunde con un token vencido (H-74). 422 (política) → title/detail del
//   problem+json (RF-029). La política solo se muestra: la decide el backend (auth/passwords.py).
// - 204: el backend revocó todos los tokens (H-37) y `cambiarContrasena` ya borró el token en
//   memoria. Se vacía la caché de TanStack y se va a /login con el aviso. Al borrarse el token,
//   ProtectedRoute redirige primero a /login; esta navegación posterior la reemplaza y agrega el
//   aviso.
import { Alert, Button, Group, Modal, PasswordInput, Stack } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";

import { cambiarContrasena } from "../api/client";
import { problemaDe } from "../api/problem";
import type { AvisoLogin } from "./avisos";

const AVISO: AvisoLogin = "contrasena-cambiada";

interface ErrorApi {
  titulo: string | null;
  detalle: string | null;
}

/** Mensaje en español del error del API, sin revelar más de lo necesario. */
function errorDe(error: unknown): ErrorApi {
  const status = isAxiosError(error) ? error.response?.status : undefined;
  if (status === 401) {
    return { titulo: null, detalle: "La contraseña actual no es correcta." };
  }
  if (status === 429) {
    return {
      titulo: null,
      detalle: "Demasiados intentos. Espera un momento e inténtalo de nuevo.",
    };
  }
  const problema = problemaDe(error);
  return { titulo: problema.titulo, detalle: problema.detalle };
}

export function CambiarContrasena() {
  const [abierto, setAbierto] = useState(false);

  return (
    <>
      <Button variant="default" size="xs" onClick={() => setAbierto(true)}>
        Cambiar contraseña
      </Button>
      <Modal
        opened={abierto}
        onClose={() => setAbierto(false)}
        title="Cambiar contraseña"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <FormularioCambio />
      </Modal>
    </>
  );
}

/** Se monta solo con el modal abierto: al cerrarlo, lo tecleado se descarta. */
function FormularioCambio() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [actual, setActual] = useState("");
  const [nueva, setNueva] = useState("");
  const [confirmacion, setConfirmacion] = useState("");
  const [errorActual, setErrorActual] = useState<string | null>(null);
  const [errorNueva, setErrorNueva] = useState<string | null>(null);
  const [errorConfirmacion, setErrorConfirmacion] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<ErrorApi | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const errores = {
      actual: actual === "" ? "La contraseña actual es obligatoria." : null,
      nueva: nueva === "" ? "La contraseña nueva es obligatoria." : null,
      confirmacion:
        nueva !== "" && confirmacion !== nueva ? "Las contraseñas nuevas no coinciden." : null,
    };
    setErrorActual(errores.actual);
    setErrorNueva(errores.nueva);
    setErrorConfirmacion(errores.confirmacion);
    if (Object.values(errores).some((error) => error !== null)) {
      return;
    }
    setEnviando(true);
    try {
      await cambiarContrasena({ current_password: actual, new_password: nueva });
    } catch (error) {
      setErrorApi(errorDe(error));
      setEnviando(false);
      return;
    }
    queryClient.clear();
    navigate("/login", { replace: true, state: { aviso: AVISO } });
  }

  return (
    <form noValidate onSubmit={(evento) => void enviar(evento)}>
      <Stack gap="sm">
        {errorApi !== null && (
          <Alert color="red" title={errorApi.titulo} role="alert">
            {errorApi.detalle}
          </Alert>
        )}
        <PasswordInput
          label="Contraseña actual"
          required
          autoComplete="current-password"
          value={actual}
          error={errorActual}
          onChange={(evento) => setActual(evento.currentTarget.value)}
        />
        <PasswordInput
          label="Nueva contraseña"
          required
          autoComplete="new-password"
          description="De 12 a 128 caracteres; no uses una contraseña común."
          value={nueva}
          error={errorNueva}
          onChange={(evento) => setNueva(evento.currentTarget.value)}
        />
        <PasswordInput
          label="Confirma la nueva contraseña"
          required
          autoComplete="new-password"
          value={confirmacion}
          error={errorConfirmacion}
          onChange={(evento) => setConfirmacion(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            Cambiar contraseña
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
