// Spec §8.4: el valor en claro de un secreto.
// - No se pide hasta que el usuario pulsa "Revelar" (GET /secrets/{id}/value es la única respuesta
//   del sistema con un valor en claro, spec §2).
// - Vive en un useState local: se oculta solo a los 30 s y se borra al desmontar (al cambiar de
//   pantalla).
// - Se pide con una llamada directa del cliente Axios, nunca con useQuery ni useMutation: la caché
//   de TanStack conservaría el valor (consultas: `data`; mutaciones: `variables` y `data`).
// - "Copiar" usa navigator.clipboard. Nunca se escribe en console.
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RevealValue } from "./RevealValue";
import { revelarValor } from "./secretsApi";

vi.mock("./secretsApi", () => ({ revelarValor: vi.fn() }));

const revelarSimulado = vi.mocked(revelarValor);

const SECRETO = "sec-1";
const VALOR = "valor-de-prueba-no-real";

function renderizar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/secreto"]}>
          <Routes>
            <Route
              path="/secreto"
              element={
                <>
                  <RevealValue secretId={SECRETO} />
                  <Link to="/otra">Ir a otra pantalla</Link>
                </>
              }
            />
            <Route path="/otra" element={<Link to="/secreto">Volver al secreto</Link>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return queryClient;
}

async function revelar(usuario: ReturnType<typeof userEvent.setup>) {
  await usuario.click(screen.getByRole("button", { name: /revelar/i }));
  expect(await screen.findByText(VALOR)).toBeInTheDocument();
}

describe("RevealValue", () => {
  beforeEach(() => {
    revelarSimulado.mockReset();
    revelarSimulado.mockResolvedValue({
      id: SECRETO,
      name: "DATABASE_URL",
      value: VALOR,
      version: 3,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("no pide el valor hasta pulsar 'Revelar'", async () => {
    const usuario = userEvent.setup();
    renderizar();

    expect(revelarSimulado).not.toHaveBeenCalled();
    expect(screen.queryByText(VALOR)).not.toBeInTheDocument();

    await revelar(usuario);

    expect(revelarSimulado).toHaveBeenCalledTimes(1);
    expect(revelarSimulado).toHaveBeenCalledWith(SECRETO);
  });

  it("se oculta solo a los 30 s", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const usuario = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) });
    renderizar();
    await revelar(usuario);

    act(() => {
      vi.advanceTimersByTime(29_000);
    });
    expect(screen.getByText(VALOR)).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(screen.queryByText(VALOR)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /revelar/i })).toBeInTheDocument();
  });

  it("'Ocultar' lo quita de inmediato", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await revelar(usuario);

    await usuario.click(screen.getByRole("button", { name: /ocultar/i }));

    expect(screen.queryByText(VALOR)).not.toBeInTheDocument();
  });

  it("al cambiar de pantalla se borra y no se vuelve a pedir al regresar", async () => {
    const usuario = userEvent.setup();
    renderizar();
    await revelar(usuario);

    await usuario.click(screen.getByRole("link", { name: /ir a otra pantalla/i }));
    expect(screen.queryByText(VALOR)).not.toBeInTheDocument();
    await usuario.click(screen.getByRole("link", { name: /volver al secreto/i }));

    expect(screen.queryByText(VALOR)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /revelar/i })).toBeInTheDocument();
    expect(revelarSimulado).toHaveBeenCalledTimes(1);
  });

  it("'Copiar' pone el valor en el portapapeles", async () => {
    const usuario = userEvent.setup(); // instala un portapapeles simulado en navigator
    const escribir = vi.spyOn(navigator.clipboard, "writeText");
    renderizar();
    await revelar(usuario);

    await usuario.click(screen.getByRole("button", { name: /copiar/i }));

    expect(escribir).toHaveBeenCalledWith(VALOR);
  });

  it("el valor no queda en la caché de TanStack Query (ni consultas ni mutaciones)", async () => {
    const usuario = userEvent.setup();
    const queryClient = renderizar();
    await revelar(usuario);

    const consultas = queryClient
      .getQueryCache()
      .getAll()
      .map((q) => ({ key: q.queryKey, data: q.state.data }));
    const mutaciones = queryClient
      .getMutationCache()
      .getAll()
      .map((m) => ({ variables: m.state.variables, data: m.state.data }));

    expect(JSON.stringify(consultas)).not.toContain(VALOR);
    expect(mutaciones).toEqual([]);
  });

  it("nunca escribe el valor en console", async () => {
    const espias = (["log", "info", "debug", "warn", "error"] as const).map((metodo) =>
      vi.spyOn(console, metodo).mockImplementation(() => {}),
    );
    const usuario = userEvent.setup();
    renderizar();
    await revelar(usuario);
    await usuario.click(screen.getByRole("button", { name: /copiar/i }));
    await usuario.click(screen.getByRole("button", { name: /ocultar/i }));

    for (const espia of espias) {
      for (const argumentos of espia.mock.calls) {
        expect(JSON.stringify(argumentos.map(String))).not.toContain(VALOR);
      }
    }
  });
});
