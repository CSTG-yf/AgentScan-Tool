import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    ...(process.env.TRACEBASTION_EVALUATION_PROXY
      ? {
          proxy: {
            "/api/v1/evaluations": {
              target: process.env.TRACEBASTION_EVALUATION_PROXY,
              changeOrigin: true,
              headers: {
                "X-DefenseClaw-Client": "desktop-preview",
                ...(process.env.TRACEBASTION_GATEWAY_TOKEN
                  ? {
                      Authorization: `Bearer ${process.env.TRACEBASTION_GATEWAY_TOKEN}`,
                    }
                  : {}),
              },
            },
          },
        }
      : {}),
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    target:
      process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari13",
    minify: process.env.TAURI_ENV_DEBUG ? false : "esbuild",
    sourcemap: Boolean(process.env.TAURI_ENV_DEBUG),
  },
});
