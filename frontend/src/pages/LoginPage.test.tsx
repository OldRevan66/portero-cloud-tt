// Spec §3.1 y spec núcleo §3.1: el backend responde el mismo 401 "credenciales inválidas" exista
// o no el correo (OWASP ASVS V2.2, enumeración de cuentas). La pantalla tampoco debe filtrarlo:
// muestra un mensaje fijo, sin el correo y sin frases que distingan un caso del otro.
//
// Aviso tras cambiar la contraseña (spec §3.6): CambiarContrasena navega a /login con
// `state: { aviso: "contrasena-cambiada" }`. LoginPage traduce esa clave a un texto fijo; nunca
// muestra texto tomado del `state`.
import { MantineProvider } from "@mantine/core";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { login } from "../api/client";
import { LoginPage } from "./LoginPage";

vi.mock("../api/client", () => ({ login: vi.fn() }));

const loginSimulado = vi.mocked(login);

function error401(): AxiosError {
  const config = { headers: {} } as InternalAxiosRequestConfig;
  const response = {
    status: 401,
    statusText: "Unauthorized",
    data: { title: "No autenticado", status: 401, detail: "credenciales inválidas" },
    headers: {},
    config,
  } as AxiosResponse;
  return new AxiosError("HTTP 401", AxiosError.ERR_BAD_REQUEST, config, null, response);
}

const AVISO = "Contraseña cambiada. Inicia sesión con tu nueva contraseña.";

function renderizar(state?: unknown) {
  return render(
    <MantineProvider>
      <MemoryRouter initialEntries={[{ pathname: "/login", state }]}>
        <LoginPage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

async function intentarLogin(email: string, password: string) {
  const usuario = userEvent.setup();
  await usuario.type(screen.getByLabelText(/correo electrónico/i), email);
  await usuario.type(screen.getByLabelText(/^contraseña/i), password);
  await usuario.click(screen.getByRole("button", { name: /iniciar sesión/i }));
}

describe("LoginPage", () => {
  beforeEach(() => {
    loginSimulado.mockReset();
  });

  it("el campo de contraseña es type=password", () => {
    renderizar();

    expect(screen.getByLabelText(/^contraseña/i)).toHaveAttribute("type", "password");
  });

  it("ante un 401 muestra 'Credenciales inválidas'", async () => {
    loginSimulado.mockRejectedValueOnce(error401());
    renderizar();

    await intentarLogin("ana@example.com", "incorrecta");

    expect(await screen.findByRole("alert")).toHaveTextContent(/credenciales inválidas/i);
    expect(loginSimulado).toHaveBeenCalledWith("ana@example.com", "incorrecta");
  });

  it("no indica si el correo existe: el mensaje es idéntico y no menciona el correo", async () => {
    // Correo registrado con contraseña incorrecta.
    loginSimulado.mockRejectedValueOnce(error401());
    const primero = renderizar();
    await intentarLogin("ana@example.com", "incorrecta");
    const mensajeExistente = (await screen.findByRole("alert")).textContent;
    primero.unmount();

    // Correo que no existe.
    loginSimulado.mockRejectedValueOnce(error401());
    renderizar();
    await intentarLogin("nadie@example.com", "incorrecta");
    const mensajeInexistente = (await screen.findByRole("alert")).textContent;

    expect(mensajeExistente).toBe(mensajeInexistente);
    expect(mensajeInexistente).not.toMatch(/nadie@example\.com/);
    expect(mensajeInexistente).not.toMatch(
      /no existe|no registrad|no encontrad|contraseña incorrecta/i,
    );
  });

  it("no muestra la contraseña escrita en el mensaje de error", async () => {
    loginSimulado.mockRejectedValueOnce(error401());
    renderizar();

    await intentarLogin("ana@example.com", "clave-de-prueba-123");

    expect(await screen.findByRole("alert")).not.toHaveTextContent("clave-de-prueba-123");
  });

  it("sin aviso en el state no muestra ningún aviso", () => {
    renderizar();

    expect(screen.queryByText(AVISO)).not.toBeInTheDocument();
  });

  it("con state { aviso: 'contrasena-cambiada' } muestra el aviso fijo", () => {
    renderizar({ aviso: "contrasena-cambiada" });

    expect(screen.getByText(AVISO)).toBeInTheDocument();
  });

  it("el aviso es role=status, no una alerta: role=alert queda para los errores", () => {
    renderizar({ aviso: "contrasena-cambiada" });

    expect(screen.getByRole("status")).toHaveTextContent(AVISO);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("al enviar el formulario el aviso desaparece y solo queda el error", async () => {
    loginSimulado.mockRejectedValueOnce(error401());
    renderizar({ aviso: "contrasena-cambiada" });

    await intentarLogin("ana@example.com", "incorrecta");

    expect(await screen.findByRole("alert")).toHaveTextContent(/credenciales inválidas/i);
    expect(screen.queryByText(AVISO)).not.toBeInTheDocument();
  });

  it("un aviso desconocido en el state no se muestra: el texto nunca sale del state", () => {
    renderizar({ aviso: "Tu cuenta fue suspendida, llama al 55 0000 0000" });

    expect(screen.queryByText(/suspendida/)).not.toBeInTheDocument();
    expect(screen.queryByText(AVISO)).not.toBeInTheDocument();
  });
});
