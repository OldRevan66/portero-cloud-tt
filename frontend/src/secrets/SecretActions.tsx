// Acciones sobre un secreto: Editar descripción (H-77), Rotar (CU-04) y Archivar (spec §8.2).
//
// - Visibles solo con el permiso en el alcance del secreto (`permisosEn`, Algoritmo 5): un
//   Desarrollador no las ve. Es conveniencia de interfaz; el backend vuelve a autorizar.
// - Editar descripción (`secrets:write`, PATCH /secrets/{id}): solo metadatos, así que usa una
//   mutación de TanStack. El nombre no cambia y el valor solo cambia rotando.
// - Rotar: modal con el valor nuevo en un campo password y llamada directa a `rotarSecreto`
//   (spec §8.4: nada de useMutation con valores). Después se invalidan los metadatos.
// - Archivar: pide confirmación. No lleva valores, así que usa una mutación de TanStack.
import { Alert, Button, Group, Modal, PasswordInput, Stack, Text, Textarea } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";

import { notificarError, notificarExito, problemaDe, type Problema } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { invalidarTrasCambio, useActualizarSecreto, useArchivarSecreto } from "./queries";
import { rotarSecreto, type SecretOut } from "./secretsApi";
import { errorDeValor } from "./validacion";

/** Longitud máxima de la descripción (backend/src/portero/api/v1/secrets.py). */
const MAX_DESCRIPCION = 1024;

export function SecretActions({ secret }: { secret: SecretOut }) {
  const { usuario } = useSession();
  const [editarAbierto, editar] = useDisclosure(false);
  const [rotarAbierto, rotar] = useDisclosure(false);
  const [archivarAbierto, archivar] = useDisclosure(false);

  if (usuario === null) {
    return null;
  }
  const permisos = permisosEn(usuario, secret.project_id, secret.environment_id);
  const puedeEditar = permisos.has("secrets:write");
  const puedeRotar = permisos.has("secrets:rotate");
  const puedeArchivar = permisos.has("secrets:delete");
  if (!puedeEditar && !puedeRotar && !puedeArchivar) {
    return null;
  }

  return (
    <Group gap="xs">
      {puedeEditar && (
        <>
          <Button variant="default" onClick={editar.open}>
            Editar descripción
          </Button>
          <Modal
            opened={editarAbierto}
            onClose={editar.close}
            title={`Descripción de ${secret.name}`}
            closeButtonProps={{ "aria-label": "Cerrar" }}
          >
            <FormularioDescripcion secret={secret} onTerminado={editar.close} />
          </Modal>
        </>
      )}
      {puedeRotar && (
        <>
          <Button variant="light" onClick={rotar.open}>
            Rotar
          </Button>
          <Modal
            opened={rotarAbierto}
            onClose={rotar.close}
            title={`Rotar ${secret.name}`}
            closeButtonProps={{ "aria-label": "Cerrar" }}
          >
            <FormularioRotar secret={secret} onTerminado={rotar.close} />
          </Modal>
        </>
      )}
      {puedeArchivar && (
        <>
          <Button variant="light" color="red" onClick={archivar.open}>
            Archivar
          </Button>
          <Modal
            opened={archivarAbierto}
            onClose={archivar.close}
            title="Archivar secreto"
            closeButtonProps={{ "aria-label": "Cerrar" }}
          >
            <ConfirmarArchivar secret={secret} onCancelar={archivar.close} />
          </Modal>
        </>
      )}
    </Group>
  );
}

/** Descripción del secreto (H-77). Vacía se guarda como null, igual que al crearlo. */
function FormularioDescripcion({
  secret,
  onTerminado,
}: {
  secret: SecretOut;
  onTerminado: () => void;
}) {
  const actualizado = useActualizarSecreto(secret);
  const [descripcion, setDescripcion] = useState(secret.description ?? "");
  const [errorCampo, setErrorCampo] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);

  function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const error =
      descripcion.length > MAX_DESCRIPCION
        ? `La descripción admite como máximo ${MAX_DESCRIPCION} caracteres.`
        : null;
    setErrorCampo(error);
    if (error !== null) {
      return;
    }
    const limpia = descripcion.trim();
    actualizado.mutate(
      { description: limpia === "" ? null : limpia },
      {
        onSuccess: () => {
          notificarExito(`Descripción de ${secret.name} actualizada.`);
          onTerminado();
        },
        onError: (error) => setErrorApi(problemaDe(error)),
      },
    );
  }

  return (
    <form noValidate onSubmit={enviar}>
      <Stack gap="sm">
        {errorApi !== null && (
          <Alert color="red" title={errorApi.titulo} role="alert">
            {errorApi.detalle}
          </Alert>
        )}
        <Textarea
          label="Descripción"
          autosize
          minRows={2}
          value={descripcion}
          error={errorCampo}
          onChange={(evento) => setDescripcion(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={actualizado.isPending}>
            Guardar
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

/** Se monta solo con el modal abierto: al cerrarlo, el valor tecleado se descarta. */
function FormularioRotar({ secret, onTerminado }: { secret: SecretOut; onTerminado: () => void }) {
  const queryClient = useQueryClient();
  const [nuevoValor, setNuevoValor] = useState("");
  const [errorCampo, setErrorCampo] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const error = errorDeValor(nuevoValor);
    setErrorCampo(error);
    if (error !== null) {
      return;
    }
    setEnviando(true);
    try {
      const rotacion = await rotarSecreto(secret.id, nuevoValor);
      setNuevoValor("");
      notificarExito(`${secret.name} rotado a la versión ${rotacion.version}.`);
      onTerminado();
      await invalidarTrasCambio(queryClient, secret.project_id, secret.environment_id, secret.id);
    } catch (error) {
      setErrorApi(problemaDe(error));
    } finally {
      setEnviando(false);
    }
  }

  return (
    <form noValidate onSubmit={(evento) => void enviar(evento)}>
      <Stack gap="sm">
        <Text size="sm">
          Se crea la versión {secret.version + 1}. Las aplicaciones que lean el secreto obtendrán el
          valor nuevo.
        </Text>
        {errorApi !== null && (
          <Alert color="red" title={errorApi.titulo} role="alert">
            {errorApi.detalle}
          </Alert>
        )}
        <PasswordInput
          label="Nuevo valor"
          required
          autoComplete="new-password"
          value={nuevoValor}
          error={errorCampo}
          onChange={(evento) => setNuevoValor(evento.currentTarget.value)}
          visibilityToggleButtonProps={{ "aria-label": "Mostrar valor" }}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            Rotar
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

function ConfirmarArchivar({ secret, onCancelar }: { secret: SecretOut; onCancelar: () => void }) {
  const navigate = useNavigate();
  const archivado = useArchivarSecreto(secret);

  function confirmar() {
    archivado.mutate(undefined, {
      onSuccess: () => {
        notificarExito(`${secret.name} archivado.`);
        void navigate(`/proyectos/${secret.project_id}/ambientes/${secret.environment_id}`);
      },
      onError: notificarError,
    });
  }

  return (
    <Stack gap="sm">
      <Text size="sm">
        ¿Archivar <strong>{secret.name}</strong>? Dejará de estar disponible para las personas y
        aplicaciones que lo consultan. El historial se conserva en la bitácora.
      </Text>
      <Group justify="flex-end">
        <Button variant="default" onClick={onCancelar}>
          Cancelar
        </Button>
        <Button color="red" loading={archivado.isPending} onClick={confirmar}>
          Archivar
        </Button>
      </Group>
    </Stack>
  );
}
