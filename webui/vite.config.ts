import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import path from "node:path";

// The Python engine (toshiba_cix/webapp.py) serves ONE self-contained
// webui.html with zero external requests (offline on a PBX voice LAN).
// vite-plugin-singlefile inlines every chunk and stylesheet into index.html;
// scripts/finalize.mjs then copies it to ../toshiba_cix/webui.html.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5173,
    // Dev-only: proxy the JSON API to the running Python daemon.
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY || "http://127.0.0.1:8765",
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "es2020",
    outDir: "dist",
    emptyOutDir: true,
    // Deterministic output so CI can prove the committed file is a fresh build.
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        // No hashed/asset file names — everything is inlined anyway.
        inlineDynamicImports: true,
      },
    },
  },
});
