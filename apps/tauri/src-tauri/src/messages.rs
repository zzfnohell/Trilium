//! Renderer messaging channel that replaces the renderer<->server WebSocket.
//!
//! In the Electron desktop the server pushes changes over an IPC path instead
//! of a TCP socket (see `CompositeMessagingProvider` in apps/desktop). Under
//! Tauri the same role is played by a Tauri event that every frontend window
//! subscribes to: the Rust side broadcasts every WebSocket-style message over
//! `trilium-ws-message` (the equivalent of a frame on the old WS channel) and
//! the client's injected `electronApi.ws.onMessage` hands it to the dispatcher.

use serde_json::Value;
use tauri::{AppHandle, Emitter};

/// Tauri event that carries a full WebSocket-style message from the backend to
/// the frontend. The injected bridge listens here and hands every payload to
/// `window.electronApi.ws.onMessage`, which the client forwards to
/// `dispatchMessage`. The payload is a complete `WebSocketMessage` (e.g.
/// `{"type":"frontend-update","data":{...}}`), so the client's existing
/// message-type dispatch keeps working unchanged.
pub const WS_MESSAGE_EVENT: &str = "trilium-ws-message";

/// Broadcast a WebSocket-style message to every frontend window.
pub fn emit_to_frontend(app: &AppHandle, message: Value) {
    let _ = app.emit(WS_MESSAGE_EVENT, message);
}