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

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;

use tauri::{AppHandle, Manager, RunEvent};
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

/// Holds the sidecar child so we can kill it when the app exits.
#[derive(Default)]
struct Engine {
    child: Mutex<Option<CommandChild>>,
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

/// Parse the engine's endpoint line into the URL to load, if this is it.
fn endpoint_url(line: &str) -> Option<String> {
    let json = line.trim().strip_prefix(ENDPOINT_MARKER)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get("url")?.as_str().map(str::to_owned)
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
                    if let Some(url) = endpoint_url(&line) {
                        open_engine(&handle, &url);
                    }
                }
                CommandEvent::Stderr(bytes) => {
                    eprint!("[engine] {}", String::from_utf8_lossy(&bytes));
                }
                CommandEvent::Terminated(payload) => {
                    eprintln!("[switchroom] engine exited: {payload:?}");
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
        .plugin(tauri_plugin_shell::init())
        .manage(Engine::default())
        .setup(|app| {
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
