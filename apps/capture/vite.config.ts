import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

const config = defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2022",
    sourcemap: true
  }
});

export default config;
