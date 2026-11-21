// Página de usuarios (CU-05; spec Fase 5 §2 notas de Usuarios, §3.5, §8.2): lista, alta,
// desactivación y reactivación. Pantalla solo del Administrador.
//
// - El menú solo muestra "Usuarios" con users:manage, pero cualquiera puede teclear /usuarios: la
//   autoridad es el backend. Si responde 403, se muestra su problem+json tal cual (RF-029).
// - Los botones aparecen con users:manage de instancia, `permisosEn(me, null, null)`: es el
//   alcance que exige el backend (H-23a); un Administrador solo de proyecto recibiría 403.
// - Desactivar (DELETE /users/{uid}) pide confirmación y avisa que se cierran todas las sesiones
//   del usuario (H-37). El 409 por autodesactivación o por último Administrador (H-59) se muestra
//   tal cual en el diálogo. Reactivar es PATCH {is_active: true}.
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { useState } from "react";
import { Link } from "react-router";

import { notificarError, notificarExito, problemaDe } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha } from "../lib/formato";
import { AvisoSesiones } from "./AvisoSesiones";
import { CreateUser } from "./CreateUser";
import { useActualizarUsuario, useDesactivarUsuario, useUsuarios } from "./queries";
import type { UserOut } from "./usersApi";

export function UsersPage() {
  const { usuario } = useSession();
  const usuarios = useUsuarios();
  const [porDesactivar, setPorDesactivar] = useState<UserOut | null>(null);

  const puedeGestionar = usuario !== null && permisosEn(usuario, null, null).has("users:manage");

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Usuarios</Title>
        {puedeGestionar && <CreateUser />}
      </Group>

      {usuarios.isPending && <Loader size="sm" aria-label="Cargando usuarios" />}
      {usuarios.isError && <ErrorDeCarga error={usuarios.error} />}
      {usuarios.data !== undefined && (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Correo</Table.Th>
              <Table.Th>Nombre</Table.Th>
              <Table.Th>Estado</Table.Th>
              <Table.Th>Creado</Table.Th>
              {puedeGestionar && <Table.Th>Acciones</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {usuarios.data.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Anchor component={Link} to={`/usuarios/${u.id}`} size="sm">
                    {u.email}
                  </Anchor>
                </Table.Td>
                <Table.Td>{u.name ?? "—"}</Table.Td>
                <Table.Td>
                  <EstadoUsuario activo={u.is_active} />
                </Table.Td>
                <Table.Td>{formatearFecha(u.created_at)}</Table.Td>
                {puedeGestionar && (
                  <Table.Td>
                    {u.is_active ? (
                      <Button
                        size="xs"
                        variant="light"
                        color="red"
                        onClick={() => setPorDesactivar(u)}
                      >
                        Desactivar
                      </Button>
                    ) : (
                      <BotonReactivar usuario={u} />
                    )}
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
        opened={porDesactivar !== null}
        onClose={() => setPorDesactivar(null)}
        title="Desactivar usuario"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        {porDesactivar !== null && (
          <ConfirmarDesactivar
            usuario={porDesactivar}
            esUnoMismo={usuario !== null && usuario.id === porDesactivar.id}
            onTerminado={() => setPorDesactivar(null)}
          />
        )}
      </Modal>
    </Stack>
  );
}

export function EstadoUsuario({ activo }: { activo: boolean }) {
  return activo ? (
    <Badge color="green" variant="light">
      Activo
    </Badge>
  ) : (
    <Badge color="gray" variant="light">
      Inactivo
    </Badge>
  );
}

function ErrorDeCarga({ error }: { error: unknown }) {
  const problema = problemaDe(error);
  return (
    <Text c="red" role="alert">
      {problema.titulo}
      {problema.detalle !== null && `: ${problema.detalle}`}
    </Text>
  );
}

function ConfirmarDesactivar({
  usuario,
  esUnoMismo,
  onTerminado,
}: {
  usuario: UserOut;
  esUnoMismo: boolean;
  onTerminado: () => void;
}) {
  const desactivar = useDesactivarUsuario(usuario.id);

  function confirmar() {
    desactivar.mutate(undefined, {
      onSuccess: () => {
        notificarExito(`${usuario.email} desactivado.`);
        onTerminado();
      },
    });
  }

  // El 409 (autodesactivación, último Administrador; H-59) se muestra tal cual, aquí mismo.
  const problema = desactivar.isError ? problemaDe(desactivar.error) : null;

  return (
    <Stack gap="sm">
      {problema !== null && (
        <Alert color="red" title={problema.titulo} role="alert">
          {problema.detalle}
        </Alert>
      )}
      <Text size="sm">
        ¿Desactivar a <strong>{usuario.email}</strong>? No podrá iniciar sesión hasta que lo
        reactives.
      </Text>
      <AvisoSesiones esUnoMismo={esUnoMismo} />
      <Group justify="flex-end">
        <Button variant="default" onClick={onTerminado}>
          Cancelar
        </Button>
        <Button color="red" loading={desactivar.isPending} onClick={confirmar}>
          Desactivar
        </Button>
      </Group>
    </Stack>
  );
}

/** Reactivar no cierra sesiones ni es destructivo: no pide confirmación. */
function BotonReactivar({ usuario }: { usuario: UserOut }) {
  const actualizar = useActualizarUsuario(usuario.id);

  function reactivar() {
    actualizar.mutate(
      { is_active: true },
      {
        onSuccess: () => notificarExito(`${usuario.email} reactivado.`),
        onError: notificarError,
      },
    );
  }

  return (
    <Button size="xs" variant="light" loading={actualizar.isPending} onClick={reactivar}>
      Reactivar
    </Button>
  );
}
