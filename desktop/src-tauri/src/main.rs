// Switchroom desktop shell.
//
// A native OS-WebView window (Tauri v2: WebView2 on Windows, WebKitGTK on
// Linux — no bundled Chromium) that hosts the existing Python engine. The
// engine runs as a Tauri *sidecar*: a PyInstaller binary we spawn on launch,
// supervise, and kill on exit. It serves the same loopback HTTP API + the
// committed single-file UI; this shell just points the WebView at it.
//
// Flow:
//   1. mint a 32-byte loopback token and hand it to the sidecar in
//      $SWITCHROOM_TOKEN (Tauri owns the token — DESIGN_PLAN §2.2);
//   2. spawn the sidecar (`switchroom-engine --emit-endpoint`, headless, no
//      browser, no auto-exit);
//   3. read its stdout for the one `@@SWITCHROOM_ENDPOINT@@ {json}` line that
//      reports the OS-chosen port + token;
//   4. navigate the window from the local "Starting…" splash to
//      `http://127.0.0.1:<port>/#token=<token>`.
//
// We load the engine's own `http://127.0.0.1:<port>/` rather than embedding
// webui.html as the Tauri frontend. Reason: the UI authenticates to the engine
// with a SameSite=Strict, loopback-Origin cookie the `/` response plants
// (toshiba_cix/server/auth.py). Served same-origin from the engine, that
// cookie + Origin check pass unchanged; a `tauri://localhost` origin would be
// non-loopback and every `/api` call would 403 unless we weakened that guard.
// So: zero changes to the security model, and one code path shared with the
// browser app-mode launch.
//
// Manager bridge (conduit#manager-bridge + the shared CONTRACT): the app
// registers the `switchroom://` URL scheme (tauri-plugin-deep-link, with
// single-instance so a link reaches a *running* app on Linux/Windows). A
// `switchroom://open?conduit&component&token` link arrives on THIS (Rust) side —
// the webview has no Tauri JS API (it loads over loopback HTTP). We parse it and
// hand the params to the engine with a plain loopback POST to its new
// `/api/deeplink` route, authenticated with the same launch token (via
// `X-CIX-Token`). A link that lands before the engine's endpoint line is
// buffered and flushed once the port + token are known. The engine then fetches
// the connection from Conduit and the UI picks it up (SSE `deeplink` + the
// pending poll). No HTTP client crate is pulled in — a tiny std TcpStream POST
// to loopback is enough (plain HTTP, no TLS).

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use tauri::{AppHandle, Manager, RunEvent};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

// The sidecar's base name. In tauri.conf.json the source lives under
// `binaries/switchroom-engine-<triple>` (tidy subdir, found at *build* time),
// but the bundler installs it flat next to the main binary as
// `switchroom-engine` (e.g. /usr/bin/switchroom-engine). The shell plugin
// resolves a sidecar name relative to the executable's own directory, so we
// must ask for it by the flat name — `binaries/switchroom-engine` would make
// it look in a non-existent `binaries/` subdir beside the installed binary.
const SIDECAR: &str = "switchroom-engine";
const ENDPOINT_MARKER: &str = "@@SWITCHROOM_ENDPOINT@@ ";

// The custom URL scheme the manager bridge launches us with.
const DEEP_LINK_SCHEME: &str = "switchroom";

// The engine exits with this code (toshiba_cix/update.py::TAURI_RELAUNCH_EXIT_CODE)
// after it applies an update. os.execv in the Python sidecar would replace the
// sidecar but leave this Rust shell running the old WebView, so the engine hands
// the restart back to us: we relaunch the whole app on seeing this exit code.
// Keep in sync with the Python constant.
const RELAUNCH_EXIT_CODE: i32 = 42;

/// The engine's loopback endpoint once it has reported one: the OS-chosen port
/// and the launch token, used to POST deep links to `/api/deeplink`.
#[derive(Clone)]
struct Endpoint {
    port: u16,
    token: String,
}

/// One parsed `switchroom://open?…` deep link.
#[derive(Clone)]
struct DeepLink {
    conduit: String,
    component: String,
    token: String,
}

/// Holds the sidecar child (to kill on exit), the engine endpoint once known,
/// and any deep links that arrived before it was known (flushed on ready).
#[derive(Default)]
struct Engine {
    child: Mutex<Option<CommandChild>>,
    endpoint: Mutex<Option<Endpoint>>,
    pending_links: Mutex<Vec<DeepLink>>,
}

/// A fresh 32-byte URL-safe-ish launch token (64 hex chars).
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Point the main window at the engine URL and reveal it.
fn open_engine(app: &AppHandle, url_str: &str) {
    let Some(window) = app.get_webview_window("main") else {
        eprintln!("[switchroom] no 'main' window to navigate");
        return;
    };
    match tauri::Url::parse(url_str) {
        Ok(url) => {
            if let Err(e) = window.navigate(url) {
                eprintln!("[switchroom] navigate failed: {e}");
            }
            let _ = window.show();
            let _ = window.set_focus();
        }
        Err(e) => eprintln!("[switchroom] bad endpoint url {url_str:?}: {e}"),
    }
}

/// Relaunch the whole app after the engine applied an update and exited with
/// `RELAUNCH_EXIT_CODE`.
fn relaunch_app(app: &AppHandle) {
    // The old sidecar has already exited — drop our (dead) handle to it so the
    // RunEvent::Exit cleanup below has nothing to kill.
    let _ = app.state::<Engine>().child.lock().unwrap().take();

    // An AppImage's `current_exe()` points inside the read-only mount, which
    // still holds the OLD bytes; the update was written to the `$APPIMAGE` file
    // on disk. Re-exec that file directly so the restart runs the NEW version —
    // Tauri's own `restart()` would re-exec `current_exe()` (the stale mount).
    if let Ok(appimage) = std::env::var("APPIMAGE") {
        if !appimage.is_empty() {
            match std::process::Command::new(&appimage).spawn() {
                Ok(_) => {
                    app.exit(0);
                    return;
                }
                Err(e) => eprintln!("[switchroom] relaunch spawn failed: {e}"),
            }
        }
    }
    // Non-AppImage packaging (or a failed spawn): let Tauri restart the process.
    app.restart();
}

/// Parse the engine's endpoint line into `(url, endpoint)`, if this is it.
fn parse_endpoint(line: &str) -> Option<(String, Endpoint)> {
    let json = line.trim().strip_prefix(ENDPOINT_MARKER)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let url = value.get("url")?.as_str()?.to_owned();
    let port = value.get("port")?.as_u64()? as u16;
    let token = value
        .get("token")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned();
    Some((url, Endpoint { port, token }))
}

/// Extract the three manager-bridge params from a `switchroom://open?…` URL.
/// `query_pairs()` percent-decodes, so the URL-encoded Conduit base comes back
/// whole. Returns `None` unless it is our scheme and all three params are set.
fn parse_switchroom_url(u: &url::Url) -> Option<DeepLink> {
    if u.scheme() != DEEP_LINK_SCHEME {
        return None;
    }
    let (mut conduit, mut component, mut token) = (None, None, None);
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "conduit" => conduit = Some(v.into_owned()),
            "component" => component = Some(v.into_owned()),
            "token" => token = Some(v.into_owned()),
            _ => {}
        }
    }
    Some(DeepLink {
        conduit: conduit?,
        component: component?,
        token: token?,
    })
}

/// Route a deep link to the engine, or buffer it until the engine is ready.
fn on_deep_link(app: &AppHandle, link: DeepLink) {
    let engine = app.state::<Engine>();
    let endpoint = engine.endpoint.lock().unwrap().clone();
    match endpoint {
        Some(ep) => deliver_deep_link(&ep, &link),
        None => engine.pending_links.lock().unwrap().push(link),
    }
    // Bring the window forward so the tech sees the connect happen.
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_focus();
    }
}

/// POST a parsed deep link to the engine's `/api/deeplink` route.
fn deliver_deep_link(ep: &Endpoint, link: &DeepLink) {
    let body = serde_json::json!({
        "conduit": link.conduit,
        "component": link.component,
        "token": link.token,
    })
    .to_string();
    if let Err(e) = post_loopback(ep.port, &ep.token, "/api/deeplink", &body) {
        eprintln!("[switchroom] deep-link delivery failed: {e}");
    }
}

/// Minimal loopback HTTP/1.0 POST — no TLS, no HTTP-client crate. The engine's
/// `/api/deeplink` route is loopback-only and gated on the launch token, which
/// we send as `X-CIX-Token` (toshiba_cix/server/auth.py accepts header or
/// cookie). The response is drained and ignored.
fn post_loopback(port: u16, token: &str, path: &str, body: &str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    let req = format!(
        "POST {path} HTTP/1.0\r\n\
         Host: 127.0.0.1\r\n\
         Content-Type: application/json\r\n\
         X-CIX-Token: {token}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        path = path,
        token = token,
        len = body.len(),
        body = body
    );
    stream.write_all(req.as_bytes())?;
    let _ = stream.flush();
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp); // drain; we don't act on the reply
    Ok(())
}

fn spawn_engine(app: &AppHandle) {
    let token = mint_token();
    let command = match app.shell().sidecar(SIDECAR) {
        Ok(cmd) => cmd.env("SWITCHROOM_TOKEN", token),
        Err(e) => {
            eprintln!("[switchroom] sidecar '{SIDECAR}' not bundled: {e}");
            return;
        }
    };

    let (mut rx, child) = match command.spawn() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[switchroom] failed to spawn engine: {e}");
            return;
        }
    };
    app.state::<Engine>().child.lock().unwrap().replace(child);

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // The shell plugin emits one Stdout event per line (newline stripped).
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    if let Some((url, endpoint)) = parse_endpoint(&line) {
                        open_engine(&handle, &url);
                        // Record the endpoint and flush any deep links that
                        // arrived before the engine was ready (cold start: the
                        // app was launched BY the link).
                        let engine = handle.state::<Engine>();
                        engine.endpoint.lock().unwrap().replace(endpoint.clone());
                        let pending: Vec<DeepLink> =
                            engine.pending_links.lock().unwrap().drain(..).collect();
                        for link in &pending {
                            deliver_deep_link(&endpoint, link);
                        }
                    }
                }
                CommandEvent::Stderr(bytes) => {
                    eprint!("[engine] {}", String::from_utf8_lossy(&bytes));
                }
                CommandEvent::Terminated(payload) => {
                    eprintln!("[switchroom] engine exited: {payload:?}");
                    // The engine asks for a full-app restart (after applying an
                    // update) by exiting with RELAUNCH_EXIT_CODE; any other exit
                    // is a normal shutdown we just stop watching.
                    if payload.code == Some(RELAUNCH_EXIT_CODE) {
                        relaunch_app(&handle);
                    }
                    break;
                }
                CommandEvent::Error(err) => {
                    eprintln!("[switchroom] engine error: {err}");
                    break;
                }
                _ => {}
            }
        }
    });
}

fn main() {
    tauri::Builder::default()
        // single-instance MUST be registered before deep-link: with its
        // `deep-link` feature, a second launch carrying a `switchroom://` link
        // (how Linux/Windows deliver one to a running app) is forwarded into the
        // deep-link plugin's `on_open_url` instead of spawning a new window.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_shell::init())
        .manage(Engine::default())
        .setup(|app| {
            let handle = app.handle().clone();
            // A link that arrives while we are running (or, on macOS, the one we
            // were launched with) is delivered here.
            app.deep_link().on_open_url(move |event| {
                for u in event.urls() {
                    if let Some(link) = parse_switchroom_url(&u) {
                        on_deep_link(&handle, link);
                    }
                }
            });
            // Cold start on Linux/Windows: the launching URL is passed as a
            // process argument, surfaced here. It buffers until the engine is up.
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                let h = app.handle().clone();
                for u in urls {
                    if let Some(link) = parse_switchroom_url(&u) {
                        on_deep_link(&h, link);
                    }
                }
            }
            // Best-effort runtime registration (chiefly for `tauri dev`). Packaged
            // builds get the association from the bundler via the scheme declared
            // in tauri.conf.json (plugins.deep-link) and the .desktop MimeType.
            #[cfg(desktop)]
            {
                let _ = app.deep_link().register(DEEP_LINK_SCHEME);
            }
            spawn_engine(&app.handle().clone());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Switchroom")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                // Kill the sidecar so no engine is left holding a loopback port.
                if let Some(child) = app.state::<Engine>().child.lock().unwrap().take() {
                    let _ = child.kill();
                }
            }
        });
}
