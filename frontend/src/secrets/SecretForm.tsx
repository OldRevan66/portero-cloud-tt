// Formulario para crear un secreto (CU-02, spec §8.4).
//
// - Valida antes de enviar (validacion.ts); el backend vuelve a validar.
// - El valor va en un campo type="password" con botón "Mostrar valor".
// - El envío es una llamada directa a `crearSecreto`: con useMutation, el valor quedaría en
//   `variables` dentro de la caché de mutaciones. Al terminar bien, el formulario se limpia.
// - Un error del API se muestra con el `title` y `detail` del problem+json (RF-029).
import { Alert, Button, Group, PasswordInput, Stack, TextInput, Textarea } from "@mantine/core";
import { useState, type FormEvent } from "react";

import { problemaDe, type Problema } from "../api/problem";
import { crearSecreto, type SecretOut } from "./secretsApi";
import { errorDeDescripcion, errorDeNombre, errorDeValor } from "./validacion";

interface Props {
  projectId: string;
  environmentId: string;
  onCreado: (secreto: SecretOut) => void;
}

interface Errores {
  nombre: string | null;
  valor: string | null;
  descripcion: string | null;
}

const SIN_ERRORES: Errores = { nombre: null, valor: null, descripcion: null };

export function SecretForm({ projectId, environmentId, onCreado }: Props) {
  const [nombre, setNombre] = useState("");
  const [valor, setValor] = useState("");
  const [descripcion, setDescripcion] = useState("");
  const [errores, setErrores] = useState<Errores>(SIN_ERRORES);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const nuevos: Errores = {
      nombre: errorDeNombre(nombre),
      valor: errorDeValor(valor),
      descripcion: errorDeDescripcion(descripcion),
    };
    setErrores(nuevos);
    if (nuevos.nombre !== null || nuevos.valor !== null || nuevos.descripcion !== null) {
      return;
    }

    setEnviando(true);
    try {
      const creado = await crearSecreto(projectId, environmentId, {
        name: nombre,
        value: valor,
        description: descripcion.trim() === "" ? null : descripcion,
      });
      setNombre("");
      setValor("");
      setDescripcion("");
      onCreado(creado);
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
          placeholder="DATABASE_URL"
          required
          autoComplete="off"
          value={nombre}
          error={errores.nombre}
          onChange={(evento) => setNombre(evento.currentTarget.value)}
        />
        <PasswordInput
          label="Valor"
          required
          autoComplete="new-password"
          value={valor}
          error={errores.valor}
          onChange={(evento) => setValor(evento.currentTarget.value)}
          visibilityToggleButtonProps={{ "aria-label": "Mostrar valor" }}
        />
        <Textarea
          label="Descripción"
          autosize
          minRows={2}
          value={descripcion}
          error={errores.descripcion}
          onChange={(evento) => setDescripcion(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            Crear secreto
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
