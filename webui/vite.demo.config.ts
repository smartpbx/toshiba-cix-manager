import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import path from "node:path";

// Dev/QA ONLY: builds the self-contained Call Flow renderer harness
// (callflow-demo.html) to dist-demo/ for offline screenshotting + fixture
// validation. NOT the shipped UI — the committed toshiba_cix/webui.html is
// still built by the default vite.config.ts from index.html alone.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  build: {
    target: "es2020",
    outDir: "dist-demo",
    emptyOutDir: true,
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
    reportCompressedSize: false,
    rollupOptions: {
      input: path.resolve(__dirname, "callflow-demo.html"),
      output: { inlineDynamicImports: true },
    },
  },
});
