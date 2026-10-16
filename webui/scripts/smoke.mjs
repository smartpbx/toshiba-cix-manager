// Headless smoke (DESIGN_PLAN §2.1, §13 — the runtime gate the byte-identical
// check cannot give). CI's typecheck proves the source compiles and check:webui
// proves the committed webui.html is a fresh build — but neither EXECUTES the
// app, so a render-time fault (e.g. a zustand selector that returns a fresh
// object every render → React #185 "Maximum update depth exceeded") ships with
// every gate green and #root never mounts. This loads the committed, built
// artifact in a real headless Chromium and asserts the React tree actually
// mounts into #root.
//
// Usage: node scripts/smoke.mjs            (defaults to ../toshiba_cix/webui.html)
//        node scripts/smoke.mjs <path>     (smoke a specific built html)
//
// Exit 0 = #root mounted and no render-loop error; exit 1 = it did not.
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { chromium } from "playwright";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webuiRoot = path.resolve(__dirname, "..");
const target =
  process.argv[2] ??
  path.resolve(webuiRoot, "..", "toshiba_cix", "webui.html");

if (!existsSync(target)) {
  console.error(`smoke: built artifact not found at ${target}`);
  console.error("smoke: build it first — cd webui && npm run build");
  process.exit(1);
}

// Signatures of the exact regression this gate exists for: an unbounded render
// loop. In a production React build #185 is minified, so match both forms.
const LOOP_SIGNATURES = [
  "Maximum update depth exceeded",
  "Minified React error #185",
  "getSnapshot should be cached",
  "Too many re-renders",
];
const isLoopError = (text) =>
  LOOP_SIGNATURES.some((sig) => (text || "").includes(sig));

const MOUNT_TIMEOUT_MS = 15000;

// Serve the single file over loopback http so the module script runs under a
// real origin (no file:// module quirks). The API it fetches on mount is not
// up; those requests fail and the app handles them — the render path, not the
// network, is what we are smoking.
const html = readFileSync(target, "utf8");
const server = createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
});

const fatal = [];
let browser;

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}/`;

  browser = await chromium.launch({ args: ["--no-sandbox"] });
  const page = await browser.newPage();

  // Uncaught exceptions (React #185 throws one) and console errors.
  page.on("pageerror", (err) => {
    const msg = err?.message ?? String(err);
    if (isLoopError(msg)) fatal.push(`pageerror: ${msg}`);
  });
  page.on("console", (msg) => {
    if (msg.type() === "error" && isLoopError(msg.text())) {
      fatal.push(`console: ${msg.text()}`);
    }
  });

  await page.goto(url, { waitUntil: "domcontentloaded", timeout: MOUNT_TIMEOUT_MS });

  // The assertion: the React tree committed into #root. A render loop leaves it
  // empty (the throw aborts the commit), so this times out on the broken build.
  let mounted = false;
  try {
    await page.waitForFunction(
      () => {
        const root = document.getElementById("root");
        return !!root && root.childElementCount > 0;
      },
      { timeout: MOUNT_TIMEOUT_MS, polling: 100 },
    );
    mounted = true;
  } catch {
    mounted = false;
  }

  const rootHtmlLen = await page
    .evaluate(() => document.getElementById("root")?.innerHTML.length ?? 0)
    .catch(() => 0);

  if (!mounted) {
    fatal.push(
      `#root never mounted (innerHTML length ${rootHtmlLen}) within ${MOUNT_TIMEOUT_MS}ms`,
    );
  }

  if (fatal.length) {
    console.error(`smoke: FAIL — ${path.relative(webuiRoot, target) || target}`);
    for (const line of fatal) console.error(`  • ${line}`);
    console.error(
      "  The app did not mount. A fresh/typecheck-clean build can still crash at\n" +
        "  runtime — e.g. a zustand selector returning a new object each render\n" +
        "  (wrap it in useShallow). Run `npm run dev` and open the console to see it.",
    );
    process.exitCode = 1;
  } else {
    console.log(
      `smoke: OK — #root mounted (innerHTML ${rootHtmlLen} chars), no render-loop error.`,
    );
    process.exitCode = 0;
  }
} catch (err) {
  console.error(`smoke: ERROR — ${err?.stack ?? err}`);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close().catch(() => {});
  server.close();
}
