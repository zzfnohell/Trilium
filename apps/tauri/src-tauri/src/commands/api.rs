//! Generic API dispatcher — the IPC replacement for the internal REST data path.
//!
//! The real client sends every request through `server.ts`, which in the Tauri
//! shell funnels them here as `(method, url, data)` instead of HTTP. The URL is
//! the client-relative path (e.g. `tree`, `notes/abc/blob`, `options`) with an
//! optional `?query` appended. This module matches the known read routes against
//! the existing Trilium database and returns the JSON the real HTTP route would.
//!
//! Anything not yet translated is answered with a structured 404, which the
//! client's normal error handling already tolerates (silent-not-found callers
//! swallow it; everything else gets a standard error toast but keeps running).

use serde::Serialize;
use serde_json::{json, Value};
use tauri::State;

use crate::db::{self, tree};
use crate::AppState;

/// A structured HTTP-style error that the client bridge turns back into a
/// rejected request with a real status code.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[tauri::command]
pub fn api(state: State<'_, AppState>, method: String, url: String, data: Option<Value>) -> Value {
    let db_guard = state.db.lock().expect("db lock");
    let db: &Option<rusqlite::Connection> = &db_guard;

    let result = match db.as_ref() {
        None => Err(not_found("database unavailable")),
        Some(conn) => {
            // `tree` is the only route that needs the method+query; the rest are
            // simple reads. Dispatch by path + a tiny bit of query parsing.
            dispatch(conn, &method, &url, &data)
        }
    };

    // Always resolve successfully with an HTTP-style `{ status, body }` wrapper. Rejecting the
    // Tauri invoke for every non-2xx (404 on an untranslated route, 405 on a write) would ship the
    // error as an opaque JSON string to the client bridge; wrapping keeps the status code intact so
    // `server.ts` can apply its normal silent-not-found / error-toast logic unchanged.
    match result {
        Ok(body) => json!({ "status": 200, "body": body }),
        Err(err) => {
            let message = err.message;
            json!({ "status": err.status, "body": { "message": message } })
        }
    }
}

fn dispatch(conn: &rusqlite::Connection, method: &str, url: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    // Strip the optional query string and split the path into segments.
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    };
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // The write path so far is a single route: editing a note's data.
    if method == "PUT" {
        return match segments.as_slice() {
            ["notes", note_id, "data"] => put_note_data(conn, note_id, data),
            _ => Err(not_found(&format!("No route for PUT {url}"))),
        };
    }

    // All other methods are unhandled — refuse them explicitly rather than pretending a write happened.
    if method != "GET" {
        return Err(not_found("non-GET routes not implemented yet"));
    }

    match segments.as_slice() {
        ["tree"] => {
            let sub_tree_note_id = parse_param(query, "subTreeNoteId").unwrap_or("root");
            tree::get_tree(conn, sub_tree_note_id).ok_or_else(|| not_found("tree not found"))
        }
        ["notes", note_id, "blob"] => get_blob(conn, note_id),
        ["notes", note_id, "content"] => {
            // The text-focused content widget also reaches content through the
            // blob route; keep this as an alias for robustness.
            get_blob(conn, note_id)
        }
        ["notes", note_id] => get_note(conn, note_id),
        ["notes", "download", note_id] => get_download(conn, note_id),
        ["options"] => Ok(get_options(conn)),
        ["options", name] => get_single_option(conn, name),
        ["app-info"] => Ok(json!({
            "subVersion": "",
            "buildRevision": "tauri",
            "buildDate": "",
            "buildTime": ""
        })),
        _ => Err(not_found(&format!("No route for GET {url}"))),
    }
}

fn get_blob(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    let blob = db::get_note_blob(conn, note_id).ok_or_else(|| not_found(&format!("Note '{}' not found", note_id)))?;
    Ok(json!({
        "blobId": blob.blob_id,
        "content": blob.content,
        "contentLength": blob.content_length,
        "dateModified": blob.date_modified,
        "utcDateModified": blob.utc_date_modified,
        "isStubbed": false
    }))
}

/// Minimal note entity for the `notes/{id}` route. Most consumers only need the
/// blob (via `notes/{id}/blob`); this is a safe metadata shape.
fn get_note(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    let note = db::get_note(conn, note_id).ok_or_else(|| not_found(&format!("Note '{}' not found", note_id)))?;
    Ok(json!({
        "noteId": note.note_id,
        "title": note.title,
        "isProtected": note.is_protected,
        "type": note.note_type,
        "mime": note.mime,
        "blobId": note.blob_id
    }))
}

/// Download route used for note-served CSS/fonts (themes, app CSS). Returns the
/// blob content verbatim, which the client injects as a stylesheet or font.
fn get_download(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    let blob = db::get_note_blob(conn, note_id).ok_or_else(|| not_found(&format!("Note '{}' not found", note_id)))?;
    Ok(json!(blob.content))
}

/// The options endpoint returns a flat `Record<string, OptionValue>` map.
fn get_options(conn: &rusqlite::Connection) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in db::get_all_options(conn) {
        map.insert(name, Value::String(value));
    }
    Value::Object(map)
}

fn get_single_option(conn: &rusqlite::Connection, name: &str) -> Result<Value, ApiError> {
    db::get_option(conn, name)
        .map(Value::String)
        .ok_or_else(|| not_found(&format!("Option '{}' not found", name)))
}

/// Parse a URL-decoded query parameter's value. Values in these URLs are simple
/// note ids (no percent-encoding needed), so decode is left as a no-op.
fn parse_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

/// `PUT /notes/{id}/data` — the edit-save write path. Routes to the faithful sync
/// write and returns the (empty) body the real route produces.
fn put_note_data(conn: &rusqlite::Connection, note_id: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let content = data
        .as_ref()
        .and_then(|v| v.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("Missing or invalid 'content' in payload"))?;

    db::write::update_note_data(conn, note_id, content).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;

    Ok(json!({}))
}

fn not_found(message: &str) -> ApiError {
    ApiError {
        status: 404,
        message: message.to_string(),
    }
}

fn bad_request(message: &str) -> ApiError {
    ApiError {
        status: 400,
        message: message.to_string(),
    }
}