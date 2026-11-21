// Asignar un rol a un usuario (CU-05; spec Fase 5 §2 notas de Asignaciones, §3.5, §8.2; H-22, H-37).
//
// - Rol, proyecto y ambiente con NativeSelect (como CreateServiceAccount). El cuerpo es
//   {role_id, project_id, environment_id}; los nulos dan el alcance (H-22, Algoritmo 5 del Cap. 6).
// - H-22: la instancia (ambos nulos) solo se ofrece con el rol Administrador, que también puede
//   tener alcance de proyecto. Para los demás roles el proyecto es obligatorio y, sin él, no se
//   llama al API. El backend sigue validando (400 de H-22, 422 si el ambiente es de otro proyecto,
//   409 si la asignación ya existe) y su problem+json se muestra en el modal.
// - El ambiente es opcional: se habilita al elegir un proyecto, se llena con sus ambientes
//   (`useAmbientes`) y se reinicia al cambiar de proyecto.
// - Asignar cierra todas las sesiones del usuario (H-37): se avisa antes de enviar.
import { Alert, Button, Group, NativeSelect, Stack } from "@mantine/core";
import { useState, type FormEvent } from "react";

import { problemaDe } from "../api/problem";
import { useAmbientes, useProyectos } from "../projects/queries";
import { AvisoSesiones } from "./AvisoSesiones";
import { useAsignarRol } from "./queries";
import { ROL_ADMINISTRADOR, ROLES } from "./roles";

/** Valor del Select de proyecto para el alcance de instancia (solo Administrador, H-22). */
const INSTANCIA = "instancia";

export function AssignRole({
  uid,
  esUnoMismo,
  onAsignado,
}: {
  uid: string;
  esUnoMismo: boolean;
  onAsignado: () => void;
}) {
  const asignar = useAsignarRol(uid);
  const proyectos = useProyectos();
  const [rol, setRol] = useState("");
  const [proyecto, setProyecto] = useState("");
  const [ambiente, setAmbiente] = useState("");
  const [errorRol, setErrorRol] = useState<string | null>(null);
  const [errorProyecto, setErrorProyecto] = useState<string | null>(null);

  const rolElegido = ROLES.find((r) => String(r.id) === rol);
  const esAdministrador = rolElegido?.id === ROL_ADMINISTRADOR;
  const conProyecto = proyecto !== "" && proyecto !== INSTANCIA;
  const ambientes = useAmbientes(proyecto, conProyecto);

  function cambiarRol(valor: string) {
    setRol(valor);
    // Al dejar de ser Administrador, la instancia ya no es una opción (H-22).
    if (valor !== String(ROL_ADMINISTRADOR) && proyecto === INSTANCIA) {
      setProyecto("");
    }
  }

  function cambiarProyecto(valor: string) {
    setProyecto(valor);
    setAmbiente(""); // Un ambiente siempre es del proyecto elegido.
  }

  function enviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    const sinRol = rolElegido === undefined ? "Elige un rol." : null;
    const sinProyecto =
      proyecto === ""
        ? esAdministrador
          ? "Elige un proyecto o la instancia."
          : "Elige un proyecto: solo el Administrador puede tener alcance de instancia."
        : null;
    setErrorRol(sinRol);
    setErrorProyecto(sinProyecto);
    if (rolElegido === undefined || sinProyecto !== null) {
      return;
    }
    asignar.mutate(
      {
        role_id: rolElegido.id,
        project_id: conProyecto ? proyecto : null,
        environment_id: conProyecto && ambiente !== "" ? ambiente : null,
      },
      { onSuccess: onAsignado },
    );
  }

  const problema = asignar.isError ? problemaDe(asignar.error) : null;

  return (
    <form noValidate onSubmit={enviar}>
      <Stack gap="sm">
        <AvisoSesiones esUnoMismo={esUnoMismo} />
        {problema !== null && (
          <Alert color="red" title={problema.titulo} role="alert">
            {problema.detalle}
          </Alert>
        )}
        <NativeSelect
          label="Rol"
          required
          value={rol}
          error={errorRol}
          onChange={(evento) => cambiarRol(evento.currentTarget.value)}
          data={[
            { value: "", label: "Selecciona un rol" },
            ...ROLES.map((r) => ({ value: String(r.id), label: r.nombre })),
          ]}
        />
        <NativeSelect
          label="Proyecto"
          required
          description="Solo el Administrador puede tener alcance de instancia."
          value={proyecto}
          error={errorProyecto}
          onChange={(evento) => cambiarProyecto(evento.currentTarget.value)}
          data={[
            { value: "", label: "Selecciona un proyecto" },
            ...(esAdministrador
              ? [{ value: INSTANCIA, label: "Instancia (todo el sistema)" }]
              : []),
            ...(proyectos.data ?? []).map((p) => ({ value: p.id, label: p.name })),
          ]}
        />
        <NativeSelect
          label="Ambiente"
          description="Opcional. Sin ambiente, el rol cubre todo el proyecto."
          disabled={!conProyecto}
          value={ambiente}
          onChange={(evento) => setAmbiente(evento.currentTarget.value)}
          data={[
            { value: "", label: "Todo el proyecto" },
            ...(conProyecto ? (ambientes.data ?? []) : []).map((a) => ({
              value: a.id,
              label: a.name,
            })),
          ]}
        />
        <Group justify="flex-end">
          <Button type="submit" loading={asignar.isPending}>
            Asignar
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
