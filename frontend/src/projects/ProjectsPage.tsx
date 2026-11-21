// Pantalla "Proyectos" (RF-026, RF-027): árbol de proyectos visibles y, solo para quien tiene
// projects:manage en la instancia (Administrador), "Nuevo proyecto". POST /projects crea también
// development, staging y production (RF-031).
import { Button, Group, Modal, Stack, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";

import { notificarExito } from "../api/problem";
import { permisosEn } from "../auth/permissions";
import { useSession } from "../auth/SessionProvider";
import { NombreDescripcionForm } from "./NombreDescripcionForm";
import { MAX_NOMBRE_PROYECTO } from "./projectsApi";
import { ProjectTree } from "./ProjectTree";
import { useCrearProyecto } from "./queries";

export function ProjectsPage() {
  const { usuario } = useSession();
  const [abierto, modal] = useDisclosure(false);
  const crear = useCrearProyecto();
  const puedeCrear = usuario !== null && permisosEn(usuario, null, null).has("projects:manage");

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Proyectos</Title>
        {puedeCrear && <Button onClick={modal.open}>Nuevo proyecto</Button>}
      </Group>
      <ProjectTree />
      <Modal
        opened={abierto}
        onClose={modal.close}
        title="Nuevo proyecto"
        closeButtonProps={{ "aria-label": "Cerrar" }}
      >
        <NombreDescripcionForm
          maxNombre={MAX_NOMBRE_PROYECTO}
          textoBoton="Crear proyecto"
          onGuardar={async (datos) => {
            const proyecto = await crear.mutateAsync(datos);
            notificarExito(
              `Proyecto ${proyecto.name} creado con development, staging y production.`,
            );
          }}
          onTerminado={modal.close}
        />
      </Modal>
    </Stack>
  );
}
