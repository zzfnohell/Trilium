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

use chrono::{Duration, Utc};
use rand::Rng;

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

    if method == "POST" {
        return match segments.as_slice() {
            // froca.reloadNotes preloads an explicit set of notes before restoring
            // tabs; answering it is what lets an opened note actually render.
            ["tree", "load"] => load_note_subtree(conn, data),
            // Recording a note visit. The real route also opportunistically trims
            // rows older than 24h; keep that on a small probability to avoid a write
            // on every keystroke when a note is opened once.
            ["recent-notes"] => add_recent_note(conn, data),
            _ => Err(not_found(&format!("No route for POST {url}"))),
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
        ["notes", note_id, "attachments"] => get_attachments(conn, note_id),
        ["notes", note_id, "metadata"] => get_note_metadata(conn, note_id),
        ["note-map", note_id, "backlink-count"] => get_backlink_count(conn, note_id),
        ["notes", note_id] => get_note(conn, note_id),
        ["notes", "download", note_id] => get_download(conn, note_id),
        ["options"] => Ok(get_options(conn)),
        ["options", name] => get_single_option(conn, name),
        ["autocomplete"] => get_autocomplete(conn, query),
        ["search", search] => search_notes(conn, search),
        ["app-info"] => Ok(json!({
            "subVersion": "",
            "buildRevision": "tauri",
            "buildDate": "",
            "buildTime": ""
        })),
        // The number of (non-deleted) notes. `note_autocomplete` awaits this at
        // module scope during boot — the client builds no layout until boot
        // finishes, so this route has to answer or the whole app stays blank.
        ["autocomplete", "notesCount"] => get_notes_count(conn),
        // Key bindings are decorative here (shortcuts are silent no-ops in the
        // shell), but `keyboard_actions` expects a non-null array.
        ["keyboard-actions"] => Ok(json!([])),
        // Keys bound to specific notes (`#keyboardShortcut` labels on non-launcher
        // notes). The shell binds none, so an empty list is the faithful answer.
        ["keyboard-shortcuts-for-notes"] => Ok(json!([])),
        // Startup script bundles and the widget catalog. No scripting is wired up
        // yet, so empty lists clear the "failed to fetch widgets" toast.
        ["script", "startup"] => Ok(json!([])),
        ["script", "widgets"] => Ok(json!([])),
        // Post-boot self-checks; nothing here can mismatch.
        ["system-checks"] => Ok(json!({ "isCpuArchMismatch": false })),
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

/// The total number of non-deleted notes, matching the real `getNotesCount`.
fn get_notes_count(conn: &rusqlite::Connection) -> Result<Value, ApiError> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notes WHERE isDeleted = 0;", [], |row| row.get(0))
        .map_err(|err| ApiError {
            status: 500,
            message: format!("failed to count notes: {err}"),
        })?;
    Ok(json!(count))
}

/// `POST /tree/load` — build the `{ notes, branches, attributes }` subtree for
/// the requested note ids so froca can preload them before opening a tab.
fn load_note_subtree(conn: &rusqlite::Connection, data: &Option<Value>) -> Result<Value, ApiError> {
    let note_ids: Vec<String> = data
        .as_ref()
        .and_then(|v| v.get("noteIds"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    tree::load_notes(conn, note_ids).ok_or_else(|| not_found("tree/load failed"))
}

/// `POST /recent-notes` — record that a note was visited so the autocomplete lists it.
/// Mirrors `recent_notes.ts`: upsert by `noteId` (primary key) with a fresh path and
/// timestamp; occasionally prune rows older than 24 hours.
fn add_recent_note(conn: &rusqlite::Connection, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some(payload) = data else {
        return Err(bad_request("Missing payload for recent-notes"));
    };
    let note_id = payload.get("noteId").and_then(Value::as_str).unwrap_or_default();
    let note_path = payload.get("notePath").and_then(Value::as_str).unwrap_or_default();
    if note_id.is_empty() {
        return Err(bad_request("Missing 'noteId' in recent-notes payload"));
    }

    let utc = Utc::now().format("%Y-%m-%d %H:%M:%S%.3fZ").to_string();
    db::add_recent_note(conn, note_id, note_path, &utc).map_err(|err| ApiError {
        status: 500,
        message: format!("failed to record recent note: {err}"),
    })?;

    // The real route runs this ~5% of the time; keep the same probability.
    if rand::thread_rng().gen_bool(0.05) {
        let cut_off = (Utc::now() - Duration::hours(24)).format("%Y-%m-%d %H:%M:%S%.3fZ").to_string();
        let _ = db::delete_old_recent_notes(conn, &cut_off);
    }

    Ok(json!({}))
}

/// `GET /notes/{id}/attachments` — the note's non-deleted attachments as the
/// client's `FAttachmentRow` array. Mirrors `attachments.ts` `getAttachments`.
fn get_attachments(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    let attachments = db::get_note_attachments(conn, note_id).map_err(|err| ApiError {
        status: 500,
        message: format!("failed to load attachments: {err}"),
    })?;

    let rows: Vec<Value> = attachments
        .into_iter()
        .map(|a| {
            json!({
                "attachmentId": a.attachment_id,
                "ownerId": a.owner_id,
                "role": a.role,
                "mime": a.mime,
                "title": a.title,
                "position": a.position,
                "blobId": a.blob_id,
                "isProtected": a.is_protected,
                "isDeleted": false,
                "contentLength": a.content_length,
                "dateModified": a.date_modified,
                "utcDateModified": a.utc_date_modified,
                "utcDateScheduledForErasureSince": a.utc_date_scheduled_for_erasure_since,
            })
        })
        .collect();

    Ok(Value::Array(rows))
}

/// `GET /autocomplete` — with an empty `query` this lists recent notes (the
/// "show recent notes" branch of the real `autocomplete.ts` `getAutocomplete`).
/// Each entry is shaped as the frontend's autocomplete result expects.
fn get_autocomplete(conn: &rusqlite::Connection, query: &str) -> Result<Value, ApiError> {
    let active_note_id = parse_param(query, "activeNoteId").unwrap_or("none");

    let notes = db::get_recent_notes(conn, active_note_id);
    let mut results = Vec::with_capacity(notes.len());
    for (note_id, note_path) in notes {
        let note_ids_in_path: Vec<&str> = note_path.split('/').collect();
        let note_path_title = title_path(conn, &note_ids_in_path);
        let note_title = db::get_note_title(conn, &note_id).unwrap_or_else(|| note_path_title.clone());
        let icon = db::get_note_icon(conn, &note_id).unwrap_or_else(|| "bx bx-note".to_string());
        results.push(json!({
            "notePath": note_path,
            "noteTitle": note_title,
            "notePathTitle": note_path_title,
            "highlightedNotePathTitle": note_path_title,
            "icon": icon
        }));
    }

    Ok(Value::Array(results))
}

/// Join the note titles along a path with " › ", mirroring `getNoteTitleForPath`.
fn title_path(conn: &rusqlite::Connection, note_ids: &[&str]) -> String {
    let titles: Vec<String> = note_ids
        .iter()
        .map(|id| db::get_note_title(conn, id).unwrap_or_else(|| format!("[{id}]")))
        .collect();
    titles.join(" \u{203A} ")
}

/// `GET /search/{string}` — a minimal stand-in for the full search route. Most
/// queries end up here from the workspace switcher (`#workspace #!template`) or
/// a note-type template needle; label queries resolve, everything else returns
/// an empty list so the caller degrades gracefully instead of erroring.
fn search_notes(conn: &rusqlite::Connection, encoded: &str) -> Result<Value, ApiError> {
    let search_string = percent_decode(encoded);
    let note_ids = db::search_notes_by_label_query(conn, &search_string);
    Ok(Value::Array(
        note_ids.into_iter().map(Value::String).collect(),
    ))
}

/// `GET /notes/{id}/metadata` — the note's timestamps (mirrors `getNoteMetadata`).
fn get_note_metadata(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    let meta = db::get_note_metadata(conn, note_id).ok_or_else(|| not_found(&format!("Note '{}' not found", note_id)))?;
    Ok(json!({
        "dateCreated": meta.date_created,
        "utcDateCreated": meta.utc_date_created,
        "dateModified": meta.date_modified,
        "utcDateModified": meta.utc_date_modified,
    }))
}

/// `GET /note-map/{id}/backlink-count` — count the relations pointing at a note
/// from non-search sources.
fn get_backlink_count(conn: &rusqlite::Connection, note_id: &str) -> Result<Value, ApiError> {
    Ok(json!({ "count": db::get_backlink_count(conn, note_id) }))
}

/// Decode a simple percent-encoded path segment (`%XX`, `+` -> space). The note
/// ids and short label queries routed here only ever use these ASCII escapes.
fn percent_decode(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) =>
            {
                out.push(hi * 16 + lo);
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of a single ASCII hex digit, or `None` if it is not one.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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