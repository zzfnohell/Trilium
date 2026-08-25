//! Renderer messaging channel that replaces the renderer<->server WebSocket.
//!
//! In the Electron desktop the server pushes changes over an IPC path instead
//! of a TCP socket (see `CompositeMessagingProvider` in apps/desktop). Under
//! Tauri the same role is played by a Tauri event that every frontend window
//! subscribes to: the Rust side broadcasts `frontend-update` (the equivalent of
//! the old `frontend-update` WebSocket message) and the client `listen`s to it.

use serde_json::Value;
use tauri::{AppHandle, Emitter};

/// Event name the client subscribes to for note/branch/attribute updates.
pub const FRONTEND_UPDATE_EVENT: &str = "frontend-update";

/// Broadcast a message to every frontend window.
pub fn emit_to_frontend(app: &AppHandle, message: Value) {
    let _ = app.emit(FRONTEND_UPDATE_EVENT, message);
}