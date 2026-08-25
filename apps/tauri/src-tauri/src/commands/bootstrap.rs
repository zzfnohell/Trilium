//! The `bootstrap` command — first IPC contact between the client and backend.
//!
//! The former client bootstrap fetched global config, login state, a CSRF token
//! and device info from `/bootstrap`. This command replaces that request. Until
//! the options/glob and auth tables are read for real, the value is a mock that
//! reproduces the shape the client expects; `db_available` reports whether the
//! existing database could be opened.

use serde::Serialize;
use tauri::{AppHandle, State};

use crate::messages;
use crate::AppState;

/// Response of the `bootstrap` command, mirroring the client's bootstrap shape.
#[derive(Serialize)]
pub struct BootstrapData {
    /// Version constant duplicated from the frontend ("app.version" option).
    pub app_version: String,
    /// Short device identifier ("app.device" option).
    pub device: String,
    /// Authentication status: `"not-initialized"`, `"no-password"`, `"not-logged-in"` or `"logged-in"`.
    pub status: String,
    /// Id of the currently open note ("activeNoteId").
    pub active_note_id: String,
    /// Whether a password has been set ("userHasPassword").
    pub user_has_password: bool,
    /// Whether the browser is authenticated with the server ("loggedIn").
    pub logged_in: bool,
    /// Whether the existing Trilium database could be opened by the backend.
    pub db_available: bool,
    /// CSRF token the client sends back on mutating requests.
    pub csrf: String,
}

/// Naive mock token. Replaced by proper CSRF handling once auth is implemented.
fn mock_csrf() -> String {
    "mock-csrf".to_string()
}

/// Handles the client's first request. Stands in for `GET /bootstrap`.
#[tauri::command]
pub fn bootstrap(state: State<'_, AppState>) -> BootstrapData {
    let db_available = state.db.lock().expect("db lock").is_some();

    BootstrapData {
        // Mirrors the real bootstrap defaults so the client recognises the shape.
        app_version: "0.104.1".to_string(),
        device: "tauri".to_string(),
        status: "not-logged-in".to_string(),
        active_note_id: "root".to_string(),
        user_has_password: true,
        logged_in: false,
        db_available,
        csrf: mock_csrf(),
    }
}

/// Smoke-test command: emits a message over the frontend-update channel and
/// returns a trivial string so the round trip can be verified end to end.
#[tauri::command]
pub fn ping_test(app: AppHandle) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = messages::emit_to_frontend(&app, serde_json::json!({ "type": "pong", "at": now }));
    "pong".to_string()
}