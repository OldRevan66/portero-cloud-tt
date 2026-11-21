// Preparación común de Vitest: matchers de DOM (toBeInTheDocument, toHaveAttribute...) y
// polyfills que jsdom no trae y que Mantine usa (matchMedia, ResizeObserver).
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

class ResizeObserverFalso {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
window.ResizeObserver = ResizeObserverFalso;

// jsdom 25 no implementa Blob.prototype.text (los navegadores sí). La exportación de la bitácora
// (RF-021) lee con ella el problem+json que llega como Blob.
if (typeof Blob.prototype.text !== "function") {
  Blob.prototype.text = function text(this: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const lector = new FileReader();
      lector.onload = () => resolve(lector.result as string);
      lector.onerror = () => reject(lector.error ?? new Error("No se pudo leer el Blob."));
      lector.readAsText(this);
    });
  };
}
