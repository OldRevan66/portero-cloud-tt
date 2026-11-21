// Frontera de errores del área principal (hallazgo H-62). Si una pantalla falla al dibujarse (p.
// ej., el API respondió algo con una forma inesperada), se muestra un mensaje en español (RF-029)
// en lugar de dejar toda la aplicación en blanco; el menú y "Cerrar sesión" siguen disponibles.
//
// No muestra ni registra el error: su mensaje podría incluir datos de la respuesta (RNF-006).
// React 19 todavía exige un componente de clase para capturar errores de render.
import { Alert } from "@mantine/core";
import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface Estado {
  fallo: boolean;
}

/**
 * Se reinicia al cambiar de pantalla porque AppLayout le da `key={location.pathname}`: un
 * componente nuevo empieza sin error.
 */
export class ErrorBoundary extends Component<Props, Estado> {
  state: Estado = { fallo: false };

  static getDerivedStateFromError(): Estado {
    return { fallo: true };
  }

  render() {
    if (this.state.fallo) {
      return (
        <Alert color="red" title="No se pudo mostrar esta pantalla" role="alert">
          Ocurrió un error inesperado. Vuelve a Proyectos desde el menú o recarga la página.
        </Alert>
      );
    }
    return this.props.children;
  }
}
