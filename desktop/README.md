# Switchroom desktop shell (Tauri v2)

A **self-contained native window** for Switchroom. Instead of launching the
tech's system browser in app-mode (the `--serve` path), this opens a real OS
window using the platform's own WebView — **WebView2** on Windows,
**WebKitGTK** on Linux — with *no bundled Chromium*.

This is **additive**. The Python engine, the committed `webui.html`, the
`--serve` / app-mode browser path and the PyInstaller `.exe` / `.AppImage`
builds are all unchanged and still the right choice for the Pi and headless
use. The desktop shell is just a nicer front door on a laptop.

```
┌─────────────────── native window (Tauri) ───────────────────┐
│  OS WebView (WebView2 / WebKitGTK) — no Chromium             │
│      loads  http://127.0.0.1:<port>/#token=<token>          │
│         │ fetch /api/*  + SSE  (same-origin cookie auth)     │
│         ▼                                                    │
│  switchroom-engine  (PyInstaller sidecar, spawned by Tauri) │
│      = the toshiba_cix engine, headless, loopback only      │
└──────────────────────────────────────────────────────────────┘
        Tauri spawns the sidecar on launch, passes it the token,
        and kills it on exit.
```

## How the sidecar is wired

1. **Token.** On launch the Rust shell mints a 32-byte loopback token and hands
   it to the engine in `$SWITCHROOM_TOKEN` (DESIGN_PLAN §2.2 — Tauri owns the
   token).
2. **Spawn.** It spawns the bundled sidecar `binaries/switchroom-engine`
   (a Tauri `externalBin`). The sidecar is `packaging/sidecar_entry.py`, frozen
   by PyInstaller; it runs the engine with `open_browser=False`,
   `autoexit=False`, `emit_endpoint=True`.
3. **Port.** The engine binds `127.0.0.1:0` — an **OS-chosen free port**, so a
   second instance never collides and there is no pick-then-bind race. (We let
   the engine pick and report the port rather than having Tauri pre-select one;
   a Tauri-chosen port would be a TOCTOU bind race.)
4. **Discovery.** The engine prints exactly one machine-readable line to
   stdout:

   ```
   @@SWITCHROOM_ENDPOINT@@ {"url": "http://127.0.0.1:53017/#token=…", "token": "…", "port": 53017}
   ```

   The Rust shell reads its stdout, ignores every other line, parses this one,
   and **navigates** the window from the local "Starting…" splash
   (`splash/index.html`) to that URL.
5. **Lifecycle.** On app exit Tauri kills the sidecar child. As a backstop the
   sidecar also watches its own stdin (piped by Tauri) and exits on EOF, so an
   abruptly-killed shell never orphans an engine holding a port.

### Why load the engine's URL, not `webui.html` as the Tauri frontend

The UI authenticates to the engine with a `SameSite=Strict`, loopback-`Origin`
cookie that the engine plants on the `/` response (`toshiba_cix/server/auth.py`).
Served **same-origin** from `http://127.0.0.1:<port>/`, that cookie and the
Origin/Host guard pass unchanged, and the desktop shell shares *one* code path
with the browser app-mode launch. If we instead made `webui.html` the Tauri
frontend, its origin would be `tauri://localhost` (non-loopback) and every
`/api` call would be refused by the Origin guard unless we weakened it. Loading
the engine URL keeps the security model identical and the diff tiny. The only
thing that changes between "browser app-mode" and "native window" is who owns
the window.

## Building

Rust + the Tauri CLI are a **dev/build-time toolchain only** — they never ship
in the Python wheel or the amalgam. PyInstaller **cannot cross-compile**, so the
sidecar must be built on the same OS as the window (a Linux sidecar for the
Linux app, a Windows sidecar for the Windows app).

### Prerequisites

- **Rust** (stable) — <https://rustup.rs>
- **Node** 18+ (only to fetch the Tauri CLI binary)
- **Python 3.12** + **PyInstaller** in a throwaway venv (build-time only)
- **Linux system libs** (Debian/Ubuntu):
  ```
  sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
      libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev pkg-config
  ```
- **Windows:** the WebView2 runtime (present on Windows 10/11; the installer
  can also bootstrap it) and the MSVC build tools.

### Linux (the first-cut target)

```bash
# 1) build the engine sidecar and stage it for Tauri
python -m venv .buildvenv && . .buildvenv/bin/activate
pip install pyinstaller
python packaging/build_sidecar.py
#   -> desktop/src-tauri/binaries/switchroom-engine-x86_64-unknown-linux-gnu

# 2) build the desktop app
cd desktop
npm install                 # fetches the @tauri-apps/cli binary
npm run tauri build         # -> src-tauri/target/release/switchroom
                            #    + bundles under target/release/bundle/{deb,appimage}
```

`npm run tauri dev` runs it unbundled for iteration.

### Icons

The icon set under `src-tauri/icons/` is generated once from the committed
`packaging/icon.svg`:

```bash
python packaging/make_icon.py                 # -> packaging/icon.png
cd desktop && npm run tauri icon ../../packaging/icon.png
```

### Windows (`.msi` / `.exe`)

Same two steps, on a Windows machine (or the `windows-latest` CI job —
see `.github/workflows/release.yml`):

```powershell
python -m venv .buildvenv; .\.buildvenv\Scripts\activate
pip install pyinstaller
python packaging\build_sidecar.py
#   -> desktop\src-tauri\binaries\switchroom-engine-x86_64-pc-windows-msvc.exe

cd desktop
npm install
npm run tauri build -- --bundles nsis,msi
#   -> src-tauri\target\release\bundle\{nsis,msi}\*
```

Cross-building the Windows app from Linux is **not** supported (PyInstaller
can't cross-compile and the MSVC/WebView2 toolchain is Windows-only), so CI
builds it on a native `windows-latest` runner.

## Layout

```
desktop/
  package.json            # @tauri-apps/cli (build-time)
  splash/index.html       # the local "Starting…" page shown until the engine is up
  src-tauri/
    Cargo.toml            # tauri + tauri-plugin-shell + getrandom
    build.rs
    tauri.conf.json       # window title/size, externalBin sidecar, bundle targets
    capabilities/default.json
    src/main.rs           # spawn sidecar, read endpoint, navigate, kill on exit
    icons/                # generated from packaging/icon.svg
    binaries/             # built sidecar (git-ignored; built per-OS)
```
