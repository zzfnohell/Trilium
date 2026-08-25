//! Tauri command handlers — the IPC replacement for the internal REST + WS
//! data path the client used against the Node server. The rename is deliberate:
//! what the client fetched over HTTP (`/bootstrap`, `/api/notes/...`) becomes
//! an `invoke()` call here.

pub mod api;
pub mod bootstrap;
pub mod ws;