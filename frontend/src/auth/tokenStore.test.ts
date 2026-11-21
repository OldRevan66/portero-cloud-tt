// Spec §8.3 (H-36): el access token vive solo en memoria, nunca en Web Storage ni en cookies
// legibles por JavaScript (OWASP ASVS V3.2, almacenamiento de tokens de sesión en el cliente).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clear, getAccessToken, setAccessToken, subscribe } from "./tokenStore";

const TOKEN = "token-de-prueba.no-es-real";

describe("tokenStore", () => {
  beforeEach(() => {
    clear();
  });

  afterEach(() => {
    clear();
  });

  it("empieza sin token", () => {
    expect(getAccessToken()).toBeNull();
  });

  it("guarda el token y lo devuelve", () => {
    setAccessToken(TOKEN);
    expect(getAccessToken()).toBe(TOKEN);
  });

  it("no escribe en localStorage ni en sessionStorage", () => {
    // localStorage y sessionStorage son instancias de Storage: espiar el prototipo cubre ambos.
    const setItem = vi.spyOn(Storage.prototype, "setItem");

    setAccessToken(TOKEN);

    expect(getAccessToken()).toBe(TOKEN);
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("no escribe el token en una cookie", () => {
    setAccessToken(TOKEN);

    expect(getAccessToken()).toBe(TOKEN);
    expect(document.cookie).not.toContain(TOKEN);
  });

  it("clear() borra el token", () => {
    setAccessToken(TOKEN);
    expect(getAccessToken()).toBe(TOKEN);

    clear();

    expect(getAccessToken()).toBeNull();
  });

  it("avisa a los suscriptores al guardar y al borrar, y deja de avisar al desuscribirse", () => {
    const aviso = vi.fn();
    const desuscribir = subscribe(aviso);

    setAccessToken(TOKEN);
    clear();
    expect(aviso).toHaveBeenCalledTimes(2);

    desuscribir();
    setAccessToken(TOKEN);
    expect(aviso).toHaveBeenCalledTimes(2);
  });
});
