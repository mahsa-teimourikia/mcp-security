import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: ".",
  base: "/mcp-security/",
  plugins: [react()],
  build: { outDir: "../out", emptyOutDir: true },
});
