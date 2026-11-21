// Crear una Aplicación Cliente y mostrar su token una sola vez (spec §2, §3.7, §8.4; H-21).
//
// - `crearAplicacion` se llama directo, nunca con useMutation: su respuesta trae el token en
//   claro y la caché de mutaciones de TanStack la conservaría.
// - El token vive solo en un useState de este componente. El mismo modal pasa del formulario al
//   token, que no se puede descartar por accidente (ni clic fuera ni Escape): se cierra con
//   "Ya lo guardé", que borra el token del estado y refresca la lista (que solo trae el prefijo).
// - "Copiar" usa navigator.clipboard. El token nunca va a console, a la URL ni a una notificación.
import { Alert, Button, Code, Group, Modal, NativeSelect, Stack, TextInput } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { notificarExito, notificarFallo, problemaDe, type Problema } from "../api/problem";
import { horaMexicoAIso } from "../lib/formato";
import { useAmbientes } from "../projects/queries";
import { invalidarAplicaciones } from "./queries";
import { crearAplicacion } from "./serviceAccountsApi";

/** Longitud máxima del nombre (backend/src/portero/api/v1/service_accounts.py). */
const MAX_NOMBRE_APLICACION = 128;

/** Token recién emitido y el nombre de su aplicación (solo para el título del modal). */
interface TokenEmitido {
  nombre: string;
  token: string;
}

export function CreateServiceAccount({ pid }: { pid: string }) {
  const queryClient = useQueryClient();
  const [abierto, setAbierto] = useState(false);
  const [emitido, setEmitido] = useState<TokenEmitido | null>(null);

  /** Cierra el modal y borra el token del estado; la lista se refresca sin él. */
  function cerrar() {
    setEmitido(null);
    setAbierto(false);
    void invalidarAplicaciones(queryClient, pid);
  }

  return (
    <>
      <Button onClick={() => setAbierto(true)}>Nueva aplicación</Button>
      <Modal
        opened={abierto}
        onClose={cerrar}
        title={emitido === null ? "Nueva Aplicación Cliente" : `Token de ${emitido.nombre}`}
        closeButtonProps={{ "aria-label": "Cerrar" }}
        withCloseButton={emitido === null}
        closeOnClickOutside={emitido === null}
        closeOnEscape={emitido === null}
      >
        {emitido === null ? (
          <FormularioCrear pid={pid} onCreada={setEmitido} />
        ) : (
          <MostrarToken token={emitido.token} onCerrar={cerrar} />
        )}
      </Modal>
    </>
  );
}

/** Se monta solo con el modal abierto: al cerrarlo, lo tecleado se descarta. */
function FormularioCrear({
  pid,
  onCreada,
}: {
  pid: string;
  onCreada: (emitido: TokenEmitido) => void;
}) {
  const ambientes = useAmbientes(pid);
  const [nombre, setNombre] = useState("");
  const [ambiente, setAmbiente] = useState("");
  const [expira, setExpira] = useState("");
  const [errorNombre, setErrorNombre] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const limpio = nombre.trim();
    const error =
      limpio === ""
        ? "El nombre es obligatorio."
        : limpio.length > MAX_NOMBRE_APLICACION
          ? `Máximo ${MAX_NOMBRE_APLICACION} caracteres.`
          : null;
    setErrorNombre(error);
    if (error !== null) {
      return;
    }
    setEnviando(true);
    try {
      const creada = await crearAplicacion(pid, {
        name: limpio,
        environment_id: ambiente === "" ? null : ambiente,
        expires_at: expira === "" ? null : horaMexicoAIso(expira),
      });
      onCreada({ nombre: creada.name, token: creada.token });
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
        <NativeSelect
          label="Ambiente"
          description="Sin ambiente, la aplicación lee los secretos de todo el proyecto."
          value={ambiente}
          onChange={(evento) => setAmbiente(evento.currentTarget.value)}
          data={[
            { value: "", label: "Todo el proyecto" },
            ...(ambientes.data ?? []).map((a) => ({ value: a.id, label: a.name })),
          ]}
        />
        <TextInput
          type="datetime-local"
          label="Expira (hora de México)"
          description="Opcional. Sin fecha, el token vale hasta que se revoque."
          value={expira}
          onChange={(evento) => setExpira(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={enviando}>
            Crear
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

function MostrarToken({ token, onCerrar }: { token: string; onCerrar: () => void }) {
  async function copiar() {
    try {
      await navigator.clipboard.writeText(token);
      notificarExito("Token copiado al portapapeles.");
    } catch {
      // Sin acceso al portapapeles (contexto no seguro o permiso denegado).
      notificarFallo("No se pudo copiar", "El navegador no permitió usar el portapapeles.");
    }
  }

  return (
    <Stack gap="sm">
      <Alert color="yellow" title="Guárdalo ahora">
        Este token no se volverá a mostrar. Portero solo conserva su huella y su prefijo; si se
        pierde, revoca la aplicación y crea otra.
      </Alert>
      <Code block style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
        {token}
      </Code>
      <Group justify="flex-end">
        <Button variant="light" onClick={() => void copiar()}>
          Copiar
        </Button>
        <Button onClick={onCerrar}>Ya lo guardé</Button>
      </Group>
    </Stack>
  );
}
