// Pantalla de inicio de sesión (spec §3.1, RF-029).
//
// El mensaje ante un 401 es fijo: "Credenciales inválidas". No depende del correo ni del
// `detail` del servidor, para no revelar si una cuenta existe (OWASP ASVS V2.2; el backend
// responde igual para correo inexistente, contraseña errónea o cuenta bloqueada).
//
// Si otra pantalla dejó un aviso en `location.state` (p. ej., tras cambiar la contraseña), se
// muestra su texto fijo de `auth/avisos.ts`; nunca un texto tomado del state. Es role=status (no
// alert, que queda para los errores) y se oculta al enviar el formulario: el state sobrevive a una
// recarga y el aviso no debe quedarse junto a un error nuevo.
import {
  Alert,
  Button,
  Center,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { isAxiosError } from "axios";
import { useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router";

import { login } from "../api/client";
import { avisoDe } from "../auth/avisos";

const CREDENCIALES_INVALIDAS = "Credenciales inválidas.";

function mensajeDeError(error: unknown): string {
  const status = isAxiosError(error) ? error.response?.status : undefined;
  if (status === 401) {
    return CREDENCIALES_INVALIDAS;
  }
  if (status === 429) {
    return "Demasiados intentos. Espera un momento e inténtalo de nuevo.";
  }
  return "No se pudo iniciar sesión. Inténtalo más tarde.";
}

/** Solo rutas internas ("/algo"); nunca "//otro-sitio" (redirección abierta). */
function destinoSeguro(estado: unknown): string {
  if (typeof estado === "object" && estado !== null && "desde" in estado) {
    const desde = estado.desde;
    if (typeof desde === "string" && desde.startsWith("/") && !desde.startsWith("//")) {
      return desde;
    }
  }
  return "/";
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [enviando, setEnviando] = useState(false);
  const [avisoOculto, setAvisoOculto] = useState(false);
  const aviso = avisoOculto ? null : avisoDe(location.state);

  async function alEnviar(evento: FormEvent<HTMLFormElement>) {
    evento.preventDefault();
    setAvisoOculto(true);
    setError(null);
    setEnviando(true);
    try {
      await login(email, password);
      navigate(destinoSeguro(location.state), { replace: true });
    } catch (e) {
      setError(mensajeDeError(e));
    } finally {
      // La contraseña no se queda en el estado del componente más de lo necesario.
      setPassword("");
      setEnviando(false);
    }
  }

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="sm" p="xl" w="100%" maw={400}>
        <form onSubmit={(e) => void alEnviar(e)} noValidate>
          <Stack>
            <div>
              <Title order={2}>Portero Cloud</Title>
              <Text c="dimmed" size="sm">
                Inicia sesión para continuar
              </Text>
            </div>
            {aviso !== null && (
              <Text role="status" c="blue" size="sm" fw={500}>
                {aviso}
              </Text>
            )}
            {error !== null && (
              <Alert color="red" role="alert">
                {error}
              </Alert>
            )}
            <TextInput
              label="Correo electrónico"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.currentTarget.value)}
            />
            <PasswordInput
              label="Contraseña"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Button type="submit" loading={enviando}>
              Iniciar sesión
            </Button>
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
