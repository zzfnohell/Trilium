#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Trilium Notes — Tauri POC shell
//
// Purpose: verify that a Tauri (Rust) webview can load and run the Trilium
// client served over HTTP by the existing Node server. This is the minimal
// feasibility check for the "sidecar" migration path — the real server (and
// its electronApi equivalent) will be added in a later step.
//
// The window URL is declared in tauri.conf.json (`app.windows[].url`), which
// points at the locally running Trilium server (http://localhost:8080).

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}