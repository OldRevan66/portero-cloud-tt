// Detalle de un usuario con sus roles (CU-05; spec Fase 5 §2 notas de Usuarios y Asignaciones,
// §3.5, §8.2; H-22, H-37, H-59, H-62, H-73). Pantalla solo del Administrador.
//
// - Sin un UUID válido en la URL no se hace ninguna petición: NotFoundPage (H-62).
// - "Editar nombre" es PATCH /users/{uid}; el nombre es obligatorio (el backend exige 1–255).
// - Roles: GET /users/{uid}/role-assignments (H-73), en el orden estable del backend. El proyecto
//   se muestra por nombre (GET /projects) y el ambiente con `useAmbientes`; "Instancia" si ambos
//   son nulos. "Quitar" pide confirmación; el 409 del último Administrador (H-59) se ve tal cual.
// - Asignar y quitar cierran todas las sesiones del usuario (H-37). Si el Administrador se
//   modifica a sí mismo, sus propios tokens dejan de servir: tras el éxito se cierra la sesión como
//   en el logout (spec §8.3) y se va al login.
// - Los botones aparecen con users:manage de instancia (`permisosEn(me, null, null)`, H-23a); la
//   autoridad sigue siendo el backend.
// - H-78: "Bloqueada hasta" y "Desbloquear" solo si `locked_until` no es nulo (el backend lo pone
//   nulo si el bloqueo venció). "Restablecer contraseña" abre `ResetPassword`. Ninguno de los dos
//   aparece sobre uno mismo: el backend responde 409 y la propia se cambia con "Cambiar
//   contraseña", que reverifica la actual.
import {
  Alert,
  Anchor,
  Breadcrumbs,
  Button,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { notificarExito, problemaDe } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { formatearFecha, uuidCorto } from "../lib/formato";
import { esUuid } from "../lib/identificadores";
import { NotFoundPage } from "../pages/NotFoundPage";
import { useAmbientes, useProyectos } from "../projects/queries";
import { AssignRole } from "./AssignRole";
import { AvisoSesiones } from "./AvisoSesiones";
import {
  useActualizarUsuario,
  useAsignaciones,
  useDesbloquearUsuario,
  useQuitarAsignacion,
  useUsuario,
} from "./queries";
import { ResetPassword } from "./ResetPassword";
import { nombreRol } from "./roles";
import { EstadoUsuario } from "./UsersPage";
import type { AssignmentOut, UserOut } from "./usersApi";

/** Longitud máxima del nombre (backend/src/portero/api/v1/users.py). */
const MAX_NOMBRE_USUARIO = 255;

/** Sin un UUID válido en la URL no se hace ninguna petición (H-62). */
export function UserDetailPage() {
  const { uid = "" } = useParams();
  if (!esUuid(uid)) {
    return <NotFoundPage />;
  }
  return <DetalleUsuario uid={uid} />;
}

/** Asignación por quitar, con su descripción ya resuelta a nombres para el diálogo. */
interface PorQuitar {
  asignacion: AssignmentOut;
  descripcion: string;
}

function DetalleUsuario({ uid }: { uid: string }) {
  const { usuario: yo, cerrarSesion } = useSession();
  const navigate = useNavigate();
  const usuario = useUsuario(uid);
  const asignaciones = useAsignaciones(uid);
  const proyectos = useProyectos();
  const [editarAbierto, editar] = useDisclosure(false);
  const [asignarAbierto, asignar] = useDisclosure(false);
  const [desbloquearAbierto, desbloquear] = useDisclosure(false);
  const [restablecerAbierto, restablecer] = useDisclosure(false);
  const [porQuitar, setPorQuitar] = useState<PorQuitar | null>(null);

  const puedeGestionar = yo !== null && permisosEn(yo, null, null).has("users:manage");
  const esUnoMismo = yo !== null && yo.id.toLowerCase() === uid.toLowerCase();
  const gestionaOtro = puedeGestionar && !esUnoMismo;
  const nombreProyecto = new Map((proyectos.data ?? []).map((p) => [p.id, p.name]));

  /**
   * Tras asignar o quitar un rol (H-37): si fue sobre uno mismo, los tokens propios ya no sirven;
   * se cierra la sesión (/auth/logout, token en memoria, queryClient.clear()) y se va al login.
   */
  async function rolesCambiados(mensaje: string, cerrarDialogo: () => void) {
    if (esUnoMismo) {
      notificarExito(`${mensaje} Inicia sesión de nuevo.`);
      await cerrarSesion();
      void navigate("/login", { replace: true });
      return;
    }
    notificarExito(mensaje);
    cerrarDialogo();
  }

  if (usuario.isPending) {
    return <Loader size="sm" aria-label="Cargando usuario" />;
  }
  if (usuario.isError) {
    const problema = problemaDe(usuario.error);
    return (
      <Text c="red" role="alert">
        {problema.titulo}
        {problema.detalle !== null && `: ${problema.detalle}`}
      </Text>
    );
  }

  const bloqueadaHasta = usuario.data.locked_until;

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/usuarios">
          Usuarios
        </Anchor>
        <Text>{usuario.data.email}</Text>
      </Breadcrumbs>

      <Group justify="space-between">
        <Title order={2}>{usuario.data.email}</Title>
        <Group gap="xs">
          {gestionaOtro && bloqueadaHasta !== null && (
            <Button variant="light" onClick={desbloquear.open}>
              Desbloquear
            </Button>
          )}
          {gestionaOtro && (
            <Button variant="default" onClick={restablecer.open}>
              Restablecer contraseña
            </Button>
          )}
          {puedeGestionar && (
            <Button variant="default" onClick={editar.open}>
              Editar nombre
            </Button>
          )}
        </Group>
      </Group>
      <Group gap="xl">
        <Dato etiqueta="Nombre">{usuario.data.name ?? "—"}</Dato>
        <Dato etiqueta="Estado">
          <EstadoUsuario activo={usuario.data.is_active} />
        </Dato>
        <Dato etiqueta="Creado">{formatearFecha(usuario.data.created_at)}</Dato>
        {bloqueadaHasta !== null && (
          <Dato etiqueta="Bloqueo">Bloqueada hasta {formatearFecha(bloqueadaHasta)}</Dato>
        )}
      </Group>

      <Group justify="space-between">
        <Title order={3}>Roles</Title>
        {puedeGestionar && <Button onClick={asignar.open}>Asignar rol</Button>}
      </Group>
      {asignaciones.isPending && <Loader size="sm" aria-label="Cargando roles" />}
      {asignaciones.isError && <Text c="red">No se pudieron cargar los roles.</Text>}
      {asignaciones.data !== undefined && asignaciones.data.length === 0 && (
        <Text c="dimmed">Este usuario no tiene roles asignados.</Text>
      )}
      {asignaciones.data !== undefined && asignaciones.data.length > 0 && (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Rol</Table.Th>
              <Table.Th>Proyecto</Table.Th>
              <Table.Th>Ambiente</Table.Th>
              {puedeGestionar && <Table.Th>Acciones</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {asignaciones.data.map((a) => (
              <FilaRol
                key={a.id}
                asignacion={a}
                nombreProyecto={nombreProyecto}
                puedeGestionar={puedeGestionar}
                onQuitar={(descripcion) => setPorQuitar({ asignacion: a, descripcion })}
              />
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
        opened={editarAbierto}
        onClose={editar.close}
        title="Editar nombre"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <FormularioNombre usuario={usuario.data} onGuardado={editar.close} />
      </Modal>

      <Modal
        opened={asignarAbierto}
        onClose={asignar.close}
        title="Asignar rol"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <AssignRole
          uid={uid}
          esUnoMismo={esUnoMismo}
          onAsignado={() => void rolesCambiados("Rol asignado.", asignar.close)}
        />
      </Modal>

      <Modal
        opened={desbloquearAbierto}
        onClose={desbloquear.close}
        title="Desbloquear cuenta"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <ConfirmarDesbloqueo
          uid={uid}
          email={usuario.data.email}
          onCancelar={desbloquear.close}
          onDesbloqueado={desbloquear.close}
        />
      </Modal>

      <Modal
        opened={restablecerAbierto}
        onClose={restablecer.close}
        title="Restablecer contraseña"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <ResetPassword uid={uid} email={usuario.data.email} onRestablecido={restablecer.close} />
      </Modal>

      <Modal
        opened={porQuitar !== null}
        onClose={() => setPorQuitar(null)}
        title="Quitar rol"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        {porQuitar !== null && (
          <ConfirmarQuitar
            uid={uid}
            porQuitar={porQuitar}
            esUnoMismo={esUnoMismo}
            onCancelar={() => setPorQuitar(null)}
            onQuitado={() => void rolesCambiados("Rol quitado.", () => setPorQuitar(null))}
          />
        )}
      </Modal>
    </Stack>
  );
}

function Dato({ etiqueta, children }: { etiqueta: string; children: ReactNode }) {
  return (
    <Stack gap={2}>
      <Text size="xs" c="dimmed">
        {etiqueta}
      </Text>
      <Text size="sm" component="div">
        {children}
      </Text>
    </Stack>
  );
}

/** Una fila por asignación; el nombre del ambiente se pide por proyecto (la caché lo comparte). */
function FilaRol({
  asignacion,
  nombreProyecto,
  puedeGestionar,
  onQuitar,
}: {
  asignacion: AssignmentOut;
  nombreProyecto: ReadonlyMap<string, string>;
  puedeGestionar: boolean;
  onQuitar: (descripcion: string) => void;
}) {
  const { project_id: pid, environment_id: eid } = asignacion;
  const ambientes = useAmbientes(pid ?? "", pid !== null && eid !== null);

  const rol = nombreRol(asignacion.role_id);
  const proyecto = pid === null ? "Instancia" : (nombreProyecto.get(pid) ?? uuidCorto(pid));
  const ambiente =
    pid === null
      ? "—"
      : eid === null
        ? "Todo el proyecto"
        : ((ambientes.data ?? []).find((a) => a.id === eid)?.name ?? uuidCorto(eid));
  const descripcion = pid === null ? `${rol} de instancia` : `${rol} en ${proyecto} / ${ambiente}`;

  return (
    <Table.Tr>
      <Table.Td>{rol}</Table.Td>
      <Table.Td>{proyecto}</Table.Td>
      <Table.Td>{ambiente}</Table.Td>
      {puedeGestionar && (
        <Table.Td>
          <Button size="xs" variant="light" color="red" onClick={() => onQuitar(descripcion)}>
            Quitar
          </Button>
        </Table.Td>
      )}
    </Table.Tr>
  );
}

function ConfirmarQuitar({
  uid,
  porQuitar,
  esUnoMismo,
  onCancelar,
  onQuitado,
}: {
  uid: string;
  porQuitar: PorQuitar;
  esUnoMismo: boolean;
  onCancelar: () => void;
  onQuitado: () => void;
}) {
  const quitar = useQuitarAsignacion(uid);

  function confirmar() {
    quitar.mutate(porQuitar.asignacion.id, { onSuccess: onQuitado });
  }

  // El 409 del último Administrador (H-59) se muestra tal cual, aquí mismo.
  const problema = quitar.isError ? problemaDe(quitar.error) : null;

  return (
    <Stack gap="sm">
      {problema !== null && (
        <Alert color="red" title={problema.titulo} role="alert">
          {problema.detalle}
        </Alert>
      )}
      <Text size="sm">
        ¿Quitar <strong>{porQuitar.descripcion}</strong>?
      </Text>
      <AvisoSesiones esUnoMismo={esUnoMismo} />
      <Group justify="flex-end">
        <Button variant="default" onClick={onCancelar}>
          Cancelar
        </Button>
        <Button color="red" loading={quitar.isPending} onClick={confirmar}>
          Quitar
        </Button>
      </Group>
    </Stack>
  );
}

/** H-78: confirma el desbloqueo; el 409 (p. ej. la propia cuenta) se muestra aquí mismo. */
function ConfirmarDesbloqueo({
  uid,
  email,
  onCancelar,
  onDesbloqueado,
}: {
  uid: string;
  email: string;
  onCancelar: () => void;
  onDesbloqueado: () => void;
}) {
  const desbloquear = useDesbloquearUsuario(uid);

  function confirmar() {
    desbloquear.mutate(undefined, {
      onSuccess: () => {
        notificarExito(`Cuenta ${email} desbloqueada.`);
        onDesbloqueado();
      },
    });
  }

  const problema = desbloquear.isError ? problemaDe(desbloquear.error) : null;

  return (
    <Stack gap="sm">
      {problema !== null && (
        <Alert color="red" title={problema.titulo} role="alert">
          {problema.detalle}
        </Alert>
      )}
      <Text size="sm">
        ¿Desbloquear <strong>{email}</strong>? Se reinicia el contador de intentos fallidos; sus
        sesiones abiertas no cambian.
      </Text>
      <Group justify="flex-end">
        <Button variant="default" onClick={onCancelar}>
          Cancelar
        </Button>
        <Button loading={desbloquear.isPending} onClick={confirmar}>
          Desbloquear
        </Button>
      </Group>
    </Stack>
  );
}

/** Se monta solo con el modal abierto: empieza con el nombre actual. */
function FormularioNombre({ usuario, onGuardado }: { usuario: UserOut; onGuardado: () => void }) {
  const actualizar = useActualizarUsuario(usuario.id);
  const [nombre, setNombre] = useState(usuario.name ?? "");
  const [errorNombre, setErrorNombre] = useState<string | null>(null);

  function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    const limpio = nombre.trim();
    const error =
      limpio === ""
        ? "El nombre es obligatorio."
        : limpio.length > MAX_NOMBRE_USUARIO
          ? `Máximo ${MAX_NOMBRE_USUARIO} caracteres.`
          : null;
    setErrorNombre(error);
    if (error !== null) {
      return;
    }
    actualizar.mutate(
      { name: limpio },
      {
        onSuccess: () => {
          notificarExito("Nombre actualizado.");
          onGuardado();
        },
      },
    );
  }

  const problema = actualizar.isError ? problemaDe(actualizar.error) : null;

  return (
    <form noValidate onSubmit={enviar}>
      <Stack gap="sm">
        {problema !== null && (
          <Alert color="red" title={problema.titulo} role="alert">
            {problema.detalle}
          </Alert>
        )}
        <TextInput
          label="Nombre"
          required
          value={nombre}
          error={errorNombre}
          onChange={(evento) => setNombre(evento.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={actualizar.isPending}>
            Guardar
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
