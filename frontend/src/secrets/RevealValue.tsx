// Valor en claro de un secreto (CU-03, spec §8.4).
//
// - Se pide solo al pulsar "Revelar", con una llamada directa (`revelarValor`): nunca useQuery
//   ni useMutation, cuya caché conservaría el valor.
// - El valor vive en un useState de este componente. Se oculta solo a los 30 s, al pulsar
//   "Ocultar" o al desmontarse (cambiar de pantalla): React descarta el estado al desmontar.
// - "Copiar" usa navigator.clipboard. El valor nunca va a console, a la URL ni a una
//   notificación.
import { Button, Code, Group, Stack, Text } from "@mantine/core";
import { useEffect, useState } from "react";

import { notificarError, notificarExito, notificarFallo } from "../api/problem";
import { revelarValor } from "./secretsApi";

/** Segundos que el valor permanece visible (spec §8.4). */
export const SEGUNDOS_VISIBLE = 30;

export function RevealValue({ secretId }: { secretId: string }) {
  const [valor, setValor] = useState<string | null>(null);
  const [cargando, setCargando] = useState(false);

  // Ocultado automático. El temporizador se cancela si se oculta antes o se desmonta.
  useEffect(() => {
    if (valor === null) {
      return;
    }
    const temporizador = setTimeout(() => setValor(null), SEGUNDOS_VISIBLE * 1000);
    return () => clearTimeout(temporizador);
  }, [valor]);

  async function revelar() {
    setCargando(true);
    try {
      const respuesta = await revelarValor(secretId);
      setValor(respuesta.value);
    } catch (error) {
      notificarError(error);
    } finally {
      setCargando(false);
    }
  }

  async function copiar(texto: string) {
    try {
      await navigator.clipboard.writeText(texto);
      notificarExito("Valor copiado al portapapeles.");
    } catch {
      // Sin acceso al portapapeles (contexto no seguro o permiso denegado).
      notificarFallo("No se pudo copiar", "El navegador no permitió usar el portapapeles.");
    }
  }

  if (valor === null) {
    return (
      <Group gap="sm">
        <Code>••••••••••••</Code>
        <Button size="xs" variant="light" loading={cargando} onClick={() => void revelar()}>
          Revelar
        </Button>
      </Group>
    );
  }

  return (
    <Stack gap={4}>
      <Code block style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
        {valor}
      </Code>
      <Group gap="sm">
        <Button size="xs" variant="light" onClick={() => void copiar(valor)}>
          Copiar
        </Button>
        <Button size="xs" variant="default" onClick={() => setValor(null)}>
          Ocultar
        </Button>
        <Text size="xs" c="dimmed">
          Se oculta solo en {SEGUNDOS_VISIBLE} s.
        </Text>
      </Group>
    </Stack>
  );
}
