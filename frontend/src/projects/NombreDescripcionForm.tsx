// Formulario de nombre y descripción, compartido por proyectos y ambientes (crear y editar).
// Solo metadatos. Valida longitudes como el backend (proyecto ≤ 128, ambiente ≤ 64,
// descripción ≤ 1024) y muestra el problem+json del API si falla (RF-029).
import { Alert, Button, Group, Stack, TextInput, Textarea } from "@mantine/core";
import { useState, type FormEvent } from "react";

import { problemaDe, type Problema } from "../api/problem";

export interface NombreDescripcion {
  name: string;
  description: string | null;
}

interface Props {
  maxNombre: number;
  inicial?: NombreDescripcion;
  textoBoton: string;
  onGuardar: (datos: NombreDescripcion) => Promise<unknown>;
  onTerminado: () => void;
}

const MAX_DESCRIPCION = 1024;

export function NombreDescripcionForm({
  maxNombre,
  inicial,
  textoBoton,
  onGuardar,
  onTerminado,
}: Props) {
  const [nombre, setNombre] = useState(inicial?.name ?? "");
  const [descripcion, setDescripcion] = useState(inicial?.description ?? "");
  const [errorNombre, setErrorNombre] = useState<string | null>(null);
  const [errorDescripcion, setErrorDescripcion] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const limpio = nombre.trim();
    const eNombre =
      limpio === ""
        ? "El nombre es obligatorio."
        : limpio.length > maxNombre
          ? `El nombre admite como máximo ${maxNombre} caracteres.`
          : null;
    const eDescripcion =
      descripcion.length > MAX_DESCRIPCION
        ? `La descripción admite como máximo ${MAX_DESCRIPCION} caracteres.`
        : null;
    setErrorNombre(eNombre);
    setErrorDescripcion(eDescripcion);
    if (eNombre !== null || eDescripcion !== null) {
      return;
    }
    setEnviando(true);
    try {
      await onGuardar({
        name: limpio,
        description: descripcion.trim() === "" ? null : descripcion.trim(),
      });
      onTerminado();
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
        <TextInput
          label="Nombre"
          required
          value={nombre}
          error={errorNombre}
          onChange={(evento) => setNombre(evento.currentTarget.value)}
        />
        <Textarea
          label="Descripción"
          autosize
          minRows={2}
          value={descripcion}
          error={errorDescripcion}
          onChange={(evento) => setDescripcion(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            {textoBoton}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
