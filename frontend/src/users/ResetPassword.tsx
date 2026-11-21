// Restablecer la contraseña de otro usuario (H-78; spec §2 notas de Usuarios, §3.5, §8.4).
//
// - `restablecerContrasena` se llama directo, nunca con useMutation: el cuerpo lleva la contraseña
//   temporal y la caché de mutaciones de TanStack conservaría las variables (spec §8.4, regla 8).
//   Después se invalida el detalle del usuario con `invalidarUsuario` (solo metadatos).
// - La contraseña vive solo en un useState de este formulario, que se monta con el modal abierto:
//   al cerrarlo, lo tecleado se descarta. preventDefault: nunca viaja en la URL; tampoco va a
//   console ni a la notificación.
// - La política (12 a 128 caracteres, `auth/passwords.py`) la decide el backend; su 422 se ve con el
//   title/detail del problem+json (RF-029). Igual el 409 si fuera la propia cuenta.
// - El restablecimiento cierra todas las sesiones del usuario (H-37): se avisa con AvisoSesiones.
//   La pantalla no lo ofrece sobre uno mismo, así que nunca cierra la sesión propia.
import { Alert, Button, Group, PasswordInput, Stack, Text } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { notificarExito, problemaDe, type Problema } from "../api/problem";
import { AvisoSesiones } from "./AvisoSesiones";
import { invalidarUsuario } from "./queries";
import { restablecerContrasena } from "./usersApi";

/** Se monta solo con el modal abierto: al cerrarlo, la contraseña tecleada se descarta. */
export function ResetPassword({
  uid,
  email,
  onRestablecido,
}: {
  uid: string;
  email: string;
  onRestablecido: () => void;
}) {
  const queryClient = useQueryClient();
  const [contrasena, setContrasena] = useState("");
  const [errorContrasena, setErrorContrasena] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    if (contrasena === "") {
      setErrorContrasena("La contraseña es obligatoria.");
      return;
    }
    setErrorContrasena(null);
    setEnviando(true);
    try {
      await restablecerContrasena(uid, contrasena);
      setContrasena("");
      notificarExito(`Contraseña de ${email} restablecida. Se cerraron sus sesiones.`);
      void invalidarUsuario(queryClient, uid);
      onRestablecido();
    } catch (error) {
      setErrorApi(problemaDe(error));
    } finally {
      setEnviando(false);
    }
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
          label="Contraseña temporal"
          required
          autoComplete="new-password"
          description="De 12 a 128 caracteres."
          value={contrasena}
          error={errorContrasena}
          onChange={(evento) => setContrasena(evento.currentTarget.value)}
        />
        <AvisoSesiones esUnoMismo={false} />
        <Text size="sm" c="dimmed">
          Comunícala por un canal seguro y pide que la cambie con «Cambiar contraseña».
        </Text>
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            Restablecer
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
