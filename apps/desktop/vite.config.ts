import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Port 1420 is the Tauri convention; strictPort so the CSP/origin allowlist stays correct.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { host: "127.0.0.1", port: 1420, strictPort: true },
  build: { target: "es2022", sourcemap: false },
  envPrefix: ["VITE_"],
});
