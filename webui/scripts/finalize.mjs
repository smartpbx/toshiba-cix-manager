// Copy the single-file Vite build (webui/dist/index.html) to the committed
// artifact the Python engine serves: toshiba_cix/webui.html.
//
// vite-plugin-singlefile inlines all JS + CSS, so dist/index.html is the whole
// app in one file. We add a provenance banner comment (deterministic — no
// timestamps) so a committed webui.html is recognisable as a build output.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webuiRoot = path.resolve(__dirname, "..");
const distFile = path.join(webuiRoot, "dist", "index.html");
const target = path.resolve(webuiRoot, "..", "toshiba_cix", "webui.html");

if (!existsSync(distFile)) {
  console.error(`finalize: build output not found at ${distFile}. Run 'vite build' first.`);
  process.exit(1);
}

const banner =
  "<!-- Built from webui/ (React 19 + TS + Vite + shadcn/ui, vite-plugin-singlefile).\n" +
  "     DO NOT EDIT BY HAND. Regenerate with: cd webui && npm ci && npm run build -->\n";

let html = readFileSync(distFile, "utf8");
if (!html.startsWith("<!doctype") && !html.startsWith("<!DOCTYPE")) {
  // keep as-is
}
html = banner + html;

writeFileSync(target, html);
console.log(`finalize: wrote ${target} (${html.length} bytes)`);
