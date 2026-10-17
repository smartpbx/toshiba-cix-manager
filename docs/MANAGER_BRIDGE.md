# Manager bridge — Switchroom side (Conduit deep-link + Save to cloud)

Conduit is the system of record (storage); Switchroom (this app) is the Toshiba
Strata CIX programming tool. The **manager bridge** lets a tech open Switchroom
**pre-filled from a Conduit system** and **save a backup back into Conduit**,
without Conduit vendoring the SNMP engine.

Pairs with **conduit#manager-bridge** (the two Conduit endpoints) and the
**Frameroom** PR (the Mitel MiVoice Office 250 counterpart). Built to the shared
`CONTRACT.md`.

## Flow

```
Conduit "Open in Switchroom"
   │  switchroom://open?conduit=<urlenc base>&component=<uuid>&token=<tok>
   ▼
OS launches / focuses Switchroom
   │  (Tauri deep-link plugin → Rust side;  OR stdlib launcher arg → engine)
   ▼
engine  GET  <conduit>/api/manager-bridge/connection?component=<id>   (Bearer <tok>)
   │   → {kind, system_name, connection:{host,port,community,via}}
   ▼
UI prefills the Connect drawer and connects (snapshot-on-connect)
   ▼
tech reads / backs up, clicks "Save to cloud"
   ▼
engine  POST <conduit>/api/manager-bridge/backup?component=<id>       (Bearer <tok>)
   │   body {filename, content_b64, content_type, summary}
   ▼
Conduit attaches the .cixbak as a Document on the component → {document_id}
```

## Why the deep link arrives on the Rust side (and how it reaches the UI)

The desktop webview loads the engine over **loopback HTTP** (`withGlobalTauri:
false`), so the page has **no Tauri JS API** — a `switchroom://` link cannot be
received in page JS. It arrives in **Rust** (`desktop/src-tauri/src/main.rs`):

1. `tauri-plugin-deep-link` registers the `switchroom://` scheme and surfaces the
   URL via `on_open_url` (and `get_current()` for the cold-start launch URL).
   `tauri-plugin-single-instance` (with its `deep-link` feature) forwards a link
   to the **already-running** app on Linux/Windows instead of spawning a second
   window.
2. Rust parses the URL (`scheme`, `conduit`, `component`, `token`) and **POSTs**
   the three params to the engine's new `POST /api/deeplink` on the sidecar's
   loopback port, authenticated with the same launch token (`X-CIX-Token`). A
   tiny `std::net::TcpStream` HTTP/1.0 request — **no HTTP-client crate**, plain
   loopback, no TLS.
3. A link that lands **before** the engine's `@@SWITCHROOM_ENDPOINT@@` line
   (cold start — the app was launched *by* the link) is **buffered** and flushed
   once the port + token are known.

The engine then fetches the connection from Conduit and the UI picks it up two
ways (whichever wins): a **consume-once** poll `GET /api/deeplink/pending` on
mount, and an SSE **`deeplink`** event for links that arrive while running.

### Stdlib / browser build

The non-Tauri build (`app.py` → the browser app) has no Rust side. Its
`.desktop` declares `MimeType=x-scheme-handler/switchroom;` and `Exec=… %u`; the
launcher lifts a `switchroom://…` launch arg into `$SWITCHROOM_DEEPLINK`, and
`serve()` seeds the same bridge context from it (on a daemon thread, so a slow
Conduit never blocks startup). Same engine routes, same UI pickup.

## Engine routes (`toshiba_cix/webapp.py` + `toshiba_cix/bridge.py`)

| Route | Who calls it | What it does |
|---|---|---|
| `POST /api/deeplink` | Rust shell / stdlib launcher | Seeds the active context; best-effort fetches the Conduit connection; fires SSE `deeplink`. |
| `GET /api/deeplink/pending` | UI, on mount + on SSE | **Consume-once**: returns the link to act on (prefill form + connect) the first time only. |
| `GET /api/bridge/context` | UI, on mount | The active save target (no secrets) so the Save button survives a reload. |
| `POST /api/bridge/backup` | UI, "Save to cloud" | Exports the newest (or an explicit) `.cixbak` snapshot and POSTs it to Conduit. |

**One active context per engine** — one tech, one loopback. The Conduit base and
the bearer token are held **engine-side only**; they never appear in any
browser-facing response. Both Conduit calls are made by the engine (stdlib
`urllib`, honoring `update.py`'s CA-bundle resolver on https), so there is **no
CORS** and the token never reaches page JS. The SNMP community *is* returned to
the page (the browser-driven connect needs it) — same exposure as the tech
viewing that credential in Conduit, per the contract.

## Save to cloud

The TopBar button appears only when a bridge context is active. It saves the
**existing** `.cixbak` backup the app already produces — the newest snapshot for
the connected site (or the snapshot being browsed in file mode). **Unredacted by
default**: Conduit is the system of record and stores the Document encrypted at
rest, so a redacted copy would be useless for restore. The summary line is
**counts only** (programs / rows / swid) — never field values, which can be
passwords.

## Security notes

- The deep-link token is minted by Conduit, short-lived (~30 min), signed, and
  scoped to one component + the `manager_bridge` scope; Conduit validates it on
  both endpoints.
- `POST /api/deeplink` is a normal `/api` route behind the engine's existing
  loopback token + Origin/Host guard, so only the local Rust shell / launcher
  (which hold the launch token) can seed a context.
- The engine never persists the Conduit token; it lives in process memory for
  the life of the context.

## Files

- Engine: `toshiba_cix/bridge.py` (pure urllib client), routes in
  `toshiba_cix/webapp.py`, launch-arg handling in `toshiba_cix/launcher.py`.
- Desktop: `desktop/src-tauri/src/main.rs`, `Cargo.toml`
  (`tauri-plugin-deep-link`, `tauri-plugin-single-instance[deep-link]`, `url`),
  `tauri.conf.json` (`plugins.deep-link.desktop.schemes`).
- Packaging: `packaging/toshiba-cix-manager.desktop` (MimeType + `%u`).
- Frontend: `webui/src/lib/{api,types}.ts`, `store/useStore.ts`, `lib/sse.ts`,
  `App.tsx`, `components/shell/TopBar.tsx` (Save to cloud).
- Tests: `tests/test_bridge.py`.

## Verification status

- Engine + routes + mapping: unit + HTTP-integration tested (`tests/test_bridge.py`),
  offline.
- Frontend: `typecheck`, byte-identical `check:webui`, and the runtime `smoke`
  gate all pass.
- The full end-to-end chain (browser link → OS launches/focuses the app → Rust
  parse → engine fetch → connect → Save to cloud) **cannot be verified headless**
  and needs live testing on a real desktop once released.
