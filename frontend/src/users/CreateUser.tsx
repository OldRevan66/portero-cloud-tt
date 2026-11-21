// Alta de un usuario con contraseña inicial (CU-05; spec §2 notas de Usuarios, §8.2, §8.4).
//
// - `crearUsuario` se llama directo, nunca con useMutation: el cuerpo lleva la contraseña y la
//   caché de mutaciones de TanStack conservaría las variables (spec §8.4). Después se invalida la
//   lista con `invalidarUsuarios`, que solo trae metadatos.
// - La contraseña vive solo en un useState del formulario, que se monta con el modal abierto: al
//   cerrarlo, lo tecleado se descarta. El formulario nunca se envía por GET (preventDefault), así
//   que la contraseña no llega a la URL; tampoco va a console ni a una notificación.
// - La política (12 a 128 caracteres, `auth/passwords.py`) solo se muestra: la decide el backend,
//   y su 422 se ve con el title/detail del problem+json (RF-029). El 409 (correo duplicado), igual.
import { Alert, Button, Group, Modal, PasswordInput, Stack, TextInput } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { notificarExito, problemaDe, type Problema } from "../api/problem";
import { invalidarUsuarios } from "./queries";
import { crearUsuario } from "./usersApi";

/** Longitud máxima del nombre (backend/src/portero/api/v1/users.py). */
const MAX_NOMBRE_USUARIO = 255;

export function CreateUser() {
  const queryClient = useQueryClient();
  const [abierto, setAbierto] = useState(false);

  function creado() {
    setAbierto(false);
    void invalidarUsuarios(queryClient);
  }

  return (
    <>
      <Button onClick={() => setAbierto(true)}>Nuevo usuario</Button>
      <Modal
        opened={abierto}
        onClose={() => setAbierto(false)}
        title="Nuevo usuario"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <FormularioAlta onCreado={creado} />
      </Modal>
    </>
  );
}

/** Se monta solo con el modal abierto: al cerrarlo, la contraseña tecleada se descarta. */
function FormularioAlta({ onCreado }: { onCreado: () => void }) {
  const [correo, setCorreo] = useState("");
  const [nombre, setNombre] = useState("");
  const [contrasena, setContrasena] = useState("");
  const [errorCorreo, setErrorCorreo] = useState<string | null>(null);
  const [errorNombre, setErrorNombre] = useState<string | null>(null);
  const [errorContrasena, setErrorContrasena] = useState<string | null>(null);
  const [errorApi, setErrorApi] = useState<Problema | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setErrorApi(null);
    const correoLimpio = correo.trim();
    const nombreLimpio = nombre.trim();
    const errores = {
      correo: correoLimpio === "" ? "El correo es obligatorio." : null,
      nombre:
        nombreLimpio.length > MAX_NOMBRE_USUARIO
          ? `Máximo ${MAX_NOMBRE_USUARIO} caracteres.`
          : null,
      contrasena: contrasena === "" ? "La contraseña es obligatoria." : null,
    };
    setErrorCorreo(errores.correo);
    setErrorNombre(errores.nombre);
    setErrorContrasena(errores.contrasena);
    if (Object.values(errores).some((error) => error !== null)) {
      return;
    }
    setEnviando(true);
    try {
      const creado = await crearUsuario({
        email: correoLimpio,
        name: nombreLimpio === "" ? null : nombreLimpio,
        password: contrasena,
      });
      notificarExito(`Usuario ${creado.email} creado.`);
      onCreado();
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
          type="email"
          label="Correo"
          required
          autoComplete="off"
          value={correo}
          error={errorCorreo}
          onChange={(evento) => setCorreo(evento.currentTarget.value)}
        />
        <TextInput
          label="Nombre"
          description="Opcional."
          value={nombre}
          error={errorNombre}
          onChange={(evento) => setNombre(evento.currentTarget.value)}
        />
        <PasswordInput
          label="Contraseña"
          required
          autoComplete="new-password"
          description="De 12 a 128 caracteres. El usuario podrá cambiarla después."
          value={contrasena}
          error={errorContrasena}
          onChange={(evento) => setContrasena(evento.currentTarget.value)}
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
