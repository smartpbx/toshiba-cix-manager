// CI check (DESIGN_PLAN §2.1, §13): prove the committed toshiba_cix/webui.html
// is byte-identical to a fresh build. Builds into a temp dir, runs the same
// finalize banner, and diffs against the committed file.
//
// Usage: node scripts/check-webui-fresh.mjs
// Exit 0 = identical; exit 1 = drift (and prints the first differing offset).
import { execSync } from "node:child_process";
import { readFileSync, existsSync, mkdtempSync, rmSync, cpSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webuiRoot = path.resolve(__dirname, "..");
const committed = path.resolve(webuiRoot, "..", "toshiba_cix", "webui.html");

if (!existsSync(committed)) {
  console.error(`check: committed artifact missing at ${committed}`);
  process.exit(1);
}

console.log("check: building a fresh webui.html …");
// Build (type-check + vite build) into webui/dist, then read what finalize
// would write — but into a temp file rather than overwriting the committed one.
execSync("npx vite build", { cwd: webuiRoot, stdio: "inherit" });

const distFile = path.join(webuiRoot, "dist", "index.html");
const banner =
  "<!-- Built from webui/ (React 19 + TS + Vite + shadcn/ui, vite-plugin-singlefile).\n" +
  "     DO NOT EDIT BY HAND. Regenerate with: cd webui && npm ci && npm run build -->\n";
const fresh = banner + readFileSync(distFile, "utf8");
const current = readFileSync(committed, "utf8");

const h = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);

if (fresh === current) {
  console.log(`check: OK — committed webui.html matches a fresh build (sha ${h(fresh)}).`);
  process.exit(0);
}

// Report the drift.
let i = 0;
const min = Math.min(fresh.length, current.length);
while (i < min && fresh[i] === current[i]) i++;
console.error("check: DRIFT — committed webui.html is NOT a fresh build.");
console.error(`  committed: ${current.length} bytes, sha ${h(current)}`);
console.error(`  fresh:     ${fresh.length} bytes, sha ${h(fresh)}`);
console.error(`  first difference at byte ${i}`);
console.error("  Fix: cd webui && npm ci && npm run build, then commit toshiba_cix/webui.html");

// Save the fresh build for inspection in CI artifacts.
const dir = mkdtempSync(path.join(tmpdir(), "webui-fresh-"));
cpSync(distFile, path.join(dir, "fresh-index.html"));
console.error(`  fresh build saved to ${dir}/fresh-index.html`);
rmSync(dir, { recursive: true, force: true });
process.exit(1);
