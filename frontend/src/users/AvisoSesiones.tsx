// Aviso de H-37 (spec §3.5): desactivar a un usuario, asignarle o quitarle un rol revoca todos sus
// tokens. Es un Text y no un Alert: el `role="alert"` del diálogo queda para el error del API.
import { Text } from "@mantine/core";

export function AvisoSesiones({ esUnoMismo }: { esUnoMismo: boolean }) {
  return (
    <Text size="sm" c="orange.8">
      Se cerrarán todas las sesiones de este usuario.
      {esUnoMismo && " Eres tú: tendrás que iniciar sesión de nuevo."}
    </Text>
  );
}
