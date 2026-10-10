import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The browser only ever talks to the Vite dev server (same origin); /api is forwarded to the local backend.
// Both servers stay on the loopback interface. Host and Origin are passed through unchanged, so the backend's own
// local-only checks (loopback Host, loopback Origin) are what protect it - no CORS, no extra allowed origins.
const BACKEND = "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: BACKEND, changeOrigin: false } },
  },
  preview: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: BACKEND, changeOrigin: false } },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
    restoreMocks: true,
  },
});
