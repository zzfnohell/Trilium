//! The outgoing sync channel — the client→backend half of the WebSocket bridge.
//!
//! In `ws.ts` the client sends messages over `window.electronApi.ws.send(...)`
//! (e.g. `ping`, `log-error`, `entity-change` acks). In the Electron desktop these
//! arrive over the IPC messaging provider; here they arrive as `ws_send` invokes.
//!
//! The sync/change-push half (backend→frontend) has no write support yet, so this
//! command accepts and acknowledges the client's messages without acting on them.
//! It exists so the client's ping loop and error reporting never block on a
//! missing transport.

use serde_json::Value;
use tauri::State;

use crate::AppState;

/// Receive an outgoing WebSocket-style message from the frontend. Current slice is
/// read-only, so the message is logged and acknowledged; `ping`/`log-*` need no
/// backend work to let the app boot and render.
#[tauri::command]
pub fn ws_send(_state: State<'_, AppState>, message: Value) {
    let typ = message.get("type").and_then(Value::as_str).unwrap_or("?");
    // Keep pings from being noisy in the dev console; surface everything else.
    if typ != "ping" {
        eprintln!("[trilium-tauri] ws_send {typ}: {message}");
    }
}