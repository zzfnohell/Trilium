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
use tauri::{AppHandle, State};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{Duration, Utc};
use rand::Rng;

use crate::db::{self, tree};
use crate::messages;
use crate::services::protected_session as session;
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
pub fn api(state: State<'_, AppState>, app: AppHandle, method: String, url: String, data: Option<Value>) -> Value {
    let db_guard = state.db.lock().expect("db lock");
    let db: &Option<rusqlite::Connection> = &db_guard;

    let result = match db.as_ref() {
        None => Err(not_found("database unavailable")),
        Some(conn) => {
            // `tree` is the only route that needs the method+query; the rest are
            // simple reads. Dispatch by path + a tiny bit of query parsing.
            dispatch(conn, &app, &method, &url, &data)
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

fn dispatch(conn: &rusqlite::Connection, app: &AppHandle, method: &str, url: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    // Strip the optional query string and split the path into segments.
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    };
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // The write path so far is a single route: editing a note's data.
    if method == "PUT" {
        return match segments.as_slice() {
            ["notes", note_id, "protect", protect] => protect_note(conn, app, note_id, protect, query),
            ["notes", note_id, "data"] => put_note_data(conn, note_id, data),
            ["notes", note_id, "file"] => update_file_route(conn, note_id, query, data),
            ["attachments", attachment_id, "rename"] => rename_attachment_route(conn, attachment_id, data),
            ["attachments", attachment_id, "file"] => update_attachment_file_route(conn, attachment_id, data),
            ["images", note_id] => update_image_route(conn, note_id, data),
            _ => Err(not_found(&format!("No route for PUT {url}"))),
        };
    }

    if method == "DELETE" {
        return match segments.as_slice() {
            ["attachments", attachment_id] => {
                db::write::delete_attachment(conn, attachment_id).map_err(|err| ApiError {
                    status: err.status,
                    message: err.message,
                })?;
                Ok(json!({}))
            }
            _ => Err(not_found(&format!("No route for DELETE {url}"))),
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
            ["notes", note_id, "attachments"] => save_note_attachment(conn, note_id, data, query),
            ["notes", note_id, "attachments", "upload"] => upload_attachments_route(conn, note_id, data),
            ["attachments", attachment_id, "convert-to-note"] => convert_attachment_to_note_route(conn, attachment_id),
            ["login", "protected"] => login_protected(conn, app, data),
            ["login", "protected", "touch"] => touch_protected(),
            ["logout", "protected"] => logout_protected(app),
            ["password", "change"] => change_password(conn, data),
            ["password", "reset"] => reset_password(conn, query),
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
        ["attachments", attachment_id, "all"] => get_all_attachments(conn, attachment_id),
        ["attachments", attachment_id, "blob"] => get_attachment_blob_route(conn, attachment_id),
        ["attachments", attachment_id, "image-info"] => get_attachment_image_info(conn, attachment_id),
        ["attachments", attachment_id] => get_attachment_route(conn, attachment_id),
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
    // Protected content is decrypt-and-serve when the session is active and
    // blanked otherwise (`blob.ts` `processContent`); an open blob URL answers
    // with nothing rather than the ciphertext.
    let note = db::get_note(conn, note_id);
    let content = session::process_content(note.map_or(false, |n| n.is_protected), blob.content);
    Ok(json!({
        "blobId": blob.blob_id,
        "content": content,
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
        "title": session::title_or_mask(note.is_protected, note.title),
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

/// Resource-request handler backing the `api_get_resource` IPC command. This is
/// the Tauri-side twin of the `GET /api/{path}` static-asset server that the real
/// client fetches (fonts CSS, downloaded notes) but the shell has no HTTP layer
/// for. Returns the raw content string, which the frontend bridge turns into a
/// blob URL. `auto`-themed CSS resolves purely on the client; font CSS is built
/// from the stored options like the original route did.
#[tauri::command]
pub fn get_api_resource(
    state: State<'_, AppState>,
    path: String,
) -> Result<String, String> {
    let guard = state.db.lock().expect("db lock");
    let conn = guard
        .as_ref()
        .ok_or_else(|| "database unavailable".to_string())?;

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["fonts"] => Ok(build_font_css(conn)),
        ["notes", "download", note_id] => db::get_note_blob(conn, note_id)
            .map(|blob| blob.content)
            .ok_or_else(|| format!("Note '{}' not found", note_id)),
        ["notes", note_id, "blob"] => db::get_note_blob(conn, note_id)
            .map(|blob| blob.content)
            .ok_or_else(|| format!("Note '{}' not found", note_id)),
        _ => Err(format!("Resource not found: {path}")),
    }
}

/// Build the `api/fonts` CSS from the font-family/size options, mirroring the
/// original `/api/fonts` route: only emitted when `overrideThemeFonts` is on,
/// mapping each family option (`theme`/`system`/a concrete stack) onto the
/// matching CSS custom property.
fn build_font_css(conn: &rusqlite::Connection) -> String {
    let override_theme_fonts = db::get_option(conn, "overrideThemeFonts")
        .map(|v| v == "true")
        .unwrap_or(false);
    if !override_theme_fonts {
        return String::new();
    }

    const SANS_SERIF: &str = "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Cantarell, Ubuntu, Noto Sans, Helvetica, Arial, sans-serif, Apple Color Emoji, Segoe UI Emoji";
    const MONOSPACE: &str = "ui-monospace, SFMono-Regular, SF Mono, Consolas, Source Code Pro, Ubuntu Mono, Menlo, Liberation Mono, monospace";

    let mut css = String::from("body {");

    let main = resolve_font(db::get_option(conn, "mainFontFamily").as_deref(), SANS_SERIF);
    if let Some(family) = main {
        css.push_str(&format!(" --main-font-family: {family};"));
    }
    let tree = resolve_font(db::get_option(conn, "treeFontFamily").as_deref(), SANS_SERIF);
    if let Some(family) = tree {
        css.push_str(&format!(" --tree-font-family: {family};"));
    }
    let detail = resolve_font(db::get_option(conn, "detailFontFamily").as_deref(), SANS_SERIF);
    if let Some(family) = detail {
        css.push_str(&format!(" --detail-font-family: {family};"));
    }
    let mono = resolve_font(db::get_option(conn, "monospaceFontFamily").as_deref(), MONOSPACE);
    if let Some(family) = mono {
        css.push_str(&format!(" --monospace-font-family: {family};"));
    }

    css.push_str(&format!(
        " --main-font-size: {}%; --tree-font-size: {}%; --detail-font-size: {}%; --monospace-font-size: {}%;",
        db::get_option(conn, "mainFontSize").unwrap_or_else(|| "100".into()),
        db::get_option(conn, "treeFontSize").unwrap_or_else(|| "100".into()),
        db::get_option(conn, "detailFontSize").unwrap_or_else(|| "100".into()),
        db::get_option(conn, "monospaceFontSize").unwrap_or_else(|| "100".into()),
    ));

    css.push('}');
    css
}

/// Map a font-family option to a CSS value: `theme` uses the theme's own value
/// (no override emitted), `system` expands to the platform stack, anything else
/// is used verbatim. Returns `None` when the theme should decide.
fn resolve_font(value: Option<&str>, system_stack: &str) -> Option<String> {
    match value.unwrap_or("theme") {
        "theme" => None,
        "system" => Some(system_stack.to_string()),
        other if other.is_empty() => None,
        other => Some(other.to_string()),
    }
}

/// The options endpoint returns a flat `Record<string, OptionValue>` map. Password
/// and LLM API-key values are never sent back — their "is set" presence flags are
/// exposed instead, mirroring the readable/write-only split in `options.ts`.
fn get_options(conn: &rusqlite::Connection) -> Value {
    const HIDDEN: [&str; 6] = [
        "passwordVerificationHash",
        "passwordVerificationSalt",
        "passwordDerivedKeySalt",
        "encryptedDataKey",
        "openaiApiKey",
        "anthropicApiKey",
    ];

    let mut map = serde_json::Map::new();
    for (name, value) in db::get_all_options(conn) {
        if HIDDEN.contains(&name.as_str()) {
            continue;
        }
        map.insert(name, Value::String(value));
    }

    map.insert(
        "isPasswordSet".to_string(),
        if session::is_password_set(conn) { json!("true") } else { json!("false") },
    );
    for (secret, flag) in [
        ("openaiApiKey", "isOpenaiApiKeySet"),
        ("anthropicApiKey", "isAnthropicApiKeySet"),
    ] {
        let is_set = db::get_option(conn, secret).is_some_and(|v| !v.is_empty());
        map.insert(flag.to_string(), if is_set { json!("true") } else { json!("false") });
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

    let rows: Vec<Value> = attachments.into_iter().map(|a| attachment_row_value(&a)).collect();
    Ok(Value::Array(rows))
}

/// `GET /attachments/{id}` — one attachment as `FAttachmentRow`.
fn get_attachment_route(conn: &rusqlite::Connection, attachment_id: &str) -> Result<Value, ApiError> {
    let attachment = db::get_attachment(conn, attachment_id)
        .map_err(|err| ApiError { status: 500, message: format!("failed to load attachment: {err}") })?
        .ok_or_else(|| not_found(&format!("Attachment '{}' not found", attachment_id)))?;
    Ok(attachment_row_value(&attachment))
}

/// `GET /attachments/{id}/all` — every attachment of the note that owns the
/// requested one (the attachments panel loads them in one go).
fn get_all_attachments(conn: &rusqlite::Connection, attachment_id: &str) -> Result<Value, ApiError> {
    let attachment = db::get_attachment(conn, attachment_id)
        .map_err(|err| ApiError { status: 500, message: format!("failed to load attachment: {err}") })?
        .ok_or_else(|| not_found(&format!("Attachment '{}' not found", attachment_id)))?;

    let attachments = db::get_note_attachments(conn, &attachment.owner_id).map_err(|err| ApiError {
        status: 500,
        message: format!("failed to load attachments: {err}"),
    })?;
    let rows: Vec<Value> = attachments.into_iter().map(|a| attachment_row_value(&a)).collect();
    Ok(Value::Array(rows))
}

/// One attachment serialized as the client's `FAttachmentRow` (titles decrypted
/// or masked according to the protected-session state).
fn attachment_row_value(a: &db::AttachmentInfo) -> Value {
    json!({
        "attachmentId": a.attachment_id,
        "ownerId": a.owner_id,
        "role": a.role,
        "mime": a.mime,
        "title": session::title_or_mask(a.is_protected, a.title.clone()),
        "position": a.position,
        "blobId": a.blob_id,
        "isProtected": a.is_protected,
        "isDeleted": false,
        "contentLength": a.content_length,
        "dateModified": a.date_modified,
        "utcDateModified": a.utc_date_modified,
        "utcDateScheduledForErasureSince": a.utc_date_scheduled_for_erasure_since,
    })
}

/// `GET /attachments/{id}/blob` — the blob pojo. Attachments hold binary
/// content, so `content` is `null` and only the length/timestamps travel,
/// mirroring `getBlobPojo` for non-string entities.
fn get_attachment_blob_route(conn: &rusqlite::Connection, attachment_id: &str) -> Result<Value, ApiError> {
    let blob = db::get_attachment_blob(conn, attachment_id)
        .map_err(|err| ApiError { status: 500, message: format!("failed to load attachment blob: {err}") })?
        .ok_or_else(|| not_found(&format!("Attachment '{}' not found", attachment_id)))?;
    Ok(json!({
        "blobId": blob.blob_id,
        "content": null,
        "contentLength": blob.content_length,
        "dateModified": blob.date_modified,
        "utcDateModified": blob.utc_date_modified,
        "isStubbed": false,
        "textRepresentation": null,
    }))
}

/// `POST /notes/{id}/attachments` — `note.saveAttachment({attachmentId, role,
/// mime, title, content}, matchBy)`. Binary content travels base64-encoded
/// (JSON cannot carry Uint8Array); an absent `content` force-writes an empty
/// blob like the real service.
fn save_note_attachment(
    conn: &rusqlite::Connection,
    note_id: &str,
    data: &Option<Value>,
    query: &str,
) -> Result<Value, ApiError> {
    let Some(payload) = data else {
        return Err(bad_request("Missing payload for notes/{id}/attachments"));
    };
    let attachment_id = payload.get("attachmentId").and_then(Value::as_str);
    let role = payload.get("role").and_then(Value::as_str).unwrap_or("file");
    let mime = payload.get("mime").and_then(Value::as_str).unwrap_or("application/octet-stream");
    let title = payload.get("title").and_then(Value::as_str).unwrap_or("attachment");
    let content: Vec<u8> = payload
        .get("content")
        .and_then(Value::as_str)
        .and_then(|b64| BASE64.decode(b64).ok())
        .unwrap_or_default();
    let match_by = match parse_param(query, "matchBy") {
        Some("title") => Some("title"),
        Some("attachmentId") | None => None, // attachmentId matching is the default
        _ => None,
    };

    db::write::save_attachment_route(conn, note_id, attachment_id, role, mime, title, Some(content), match_by)
        .map_err(|err| ApiError {
            status: err.status,
            message: err.message,
        })?;
    Ok(json!({}))
}

/// `PUT /attachments/{id}/rename` — `renameAttachment`, non-empty title.
fn rename_attachment_route(conn: &rusqlite::Connection, attachment_id: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let title = data
        .as_ref()
        .and_then(|v| v.get("title"))
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("Missing 'title' in payload"))?;

    db::write::rename_attachment(conn, attachment_id, title).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;
    Ok(json!({}))
}

// ---------------------------------------------------------------------------
// Multipart uploads — the `server.upload` routes (`POST notes/{id}/attachments/upload`,
// `PUT notes/{id}/file`, `PUT attachments/{id}/file`, `PUT images/{id}`). The client's
// desktop-shell `upload()` base64-encodes the file into this payload instead of sending
// multipart/form-data, so the "uploaded" response shape below matches what the FormData
// branch of the HTTP builds and the real routes answer with.
// ---------------------------------------------------------------------------

/// Parse the `server.upload` IPC payload (`{ fileName, mimeType, content: base64 }`) into
/// the file fields the upload routes consume. `None` when the payload carries no content —
/// the uploaded-file routes answer `{ uploaded: false, message }` for that, exactly like the
/// real multipart middleware seeing no file.
fn parse_upload_payload(data: &Option<Value>) -> Option<(String, String, Vec<u8>)> {
    let payload = data.as_ref()?;
    let content = payload.get("content").and_then(Value::as_str)?;
    let bytes = BASE64.decode(content.as_bytes()).ok()?;
    let original_name = payload.get("fileName").and_then(Value::as_str).unwrap_or("file").to_string();
    let mime = payload.get("mimeType").and_then(Value::as_str).unwrap_or("application/octet-stream").to_string();
    Some((original_name, mime, bytes))
}

/// `POST /notes/{noteId}/attachments/upload` — image attachments answer with their serving
/// URL, everything else with an attachments-panel reference, mirroring `uploadAttachment`.
fn upload_attachments_route(conn: &rusqlite::Connection, note_id: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some((original_name, mime, content)) = parse_upload_payload(data) else {
        return Ok(json!({ "uploaded": false, "message": "Missing attachment data." }));
    };

    let uploaded = db::write::save_uploaded_attachment(conn, note_id, &original_name, &mime, &content)
        .map_err(|err| ApiError { status: err.status, message: err.message })?;
    let url = match uploaded {
        db::write::UploadedAttachment::Image { attachment_id, title } => {
            format!("api/attachments/{attachment_id}/image/{}", db::write::encode_uri_component(&title))
        }
        db::write::UploadedAttachment::File { attachment_id } => {
            format!("#root/{note_id}?viewMode=attachments&attachmentId={attachment_id}")
        }
    };
    Ok(json!({ "uploaded": true, "url": url }))
}

/// `PUT /notes/{noteId}/file` — `replace=1` skips the revision snapshot; the response is
/// the `{ uploaded: true }` the client's update-file callers expect.
fn update_file_route(conn: &rusqlite::Connection, note_id: &str, query: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some((original_name, mime, content)) = parse_upload_payload(data) else {
        return Ok(json!({ "uploaded": false, "message": "Missing file." }));
    };
    let replace = parse_param(query, "replace").map(|v| v == "1").unwrap_or(false);

    db::write::update_file_note(conn, note_id, &original_name, &mime, &content, replace).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;
    Ok(json!({ "uploaded": true }))
}

/// `PUT /attachments/{attachmentId}/file` — upload a new revision of an attachment's file.
fn update_attachment_file_route(conn: &rusqlite::Connection, attachment_id: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some((_original_name, mime, content)) = parse_upload_payload(data) else {
        return Ok(json!({ "uploaded": false, "message": "Missing file." }));
    };

    db::write::update_file_attachment(conn, attachment_id, &mime, &content).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;
    Ok(json!({ "uploaded": true }))
}

/// `PUT /images/{noteId}` — replace an image note's content.
fn update_image_route(conn: &rusqlite::Connection, note_id: &str, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some((original_name, _mime, content)) = parse_upload_payload(data) else {
        return Ok(json!({ "uploaded": false, "message": "Missing file." }));
    };

    db::write::update_image_note(conn, note_id, &original_name, &content).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;
    Ok(json!({ "uploaded": true }))
}

/// `POST /attachments/{attachmentId}/convert-to-note` — the new note's place in the tree,
/// as the `ConvertAttachmentToNoteResponse` the attachment panel opens.
fn convert_attachment_to_note_route(conn: &rusqlite::Connection, attachment_id: &str) -> Result<Value, ApiError> {
    let created = db::write::convert_attachment_to_note(conn, attachment_id).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;

    let note = db::get_note(conn, &created.note_id).ok_or_else(|| not_found(&format!("Note '{}' not found", created.note_id)))?;
    Ok(json!({
        "note": {
            "noteId": note.note_id,
            "title": session::title_or_mask(note.is_protected, note.title),
            "isProtected": note.is_protected,
            "type": note.note_type,
            "mime": note.mime,
            "blobId": note.blob_id,
        },
        "branch": {
            "branchId": created.branch_id,
            "noteId": created.note_id,
            "parentNoteId": created.parent_note_id,
            "notePosition": created.note_position,
            "prefix": "",
            "isExpanded": false,
        }
    }))
}

/// `GET /attachments/{id}/image-info` — the shape the image-compression dialog
/// opens with. Only the format and dimensions are inspected here; the bit-depth
/// / channel / quality metrics the real `inspectImage` derives are reported as
/// unknown.
fn get_attachment_image_info(conn: &rusqlite::Connection, attachment_id: &str) -> Result<Value, ApiError> {
    let attachment = db::get_attachment(conn, attachment_id)
        .map_err(|err| ApiError { status: 500, message: format!("failed to load attachment: {err}") })?
        .ok_or_else(|| not_found(&format!("Attachment '{}' not found", attachment_id)))?;
    if attachment.role != "image" {
        return Err(ApiError {
            status: 400,
            message: format!(
                "Attachment '{}' has role '{}', but 'image' was expected",
                attachment_id, attachment.role
            ),
        });
    }

    let Some((raw, is_protected)) = db::get_attachment_content(conn, attachment_id).map_err(|err| ApiError {
        status: 500,
        message: format!("failed to load attachment content: {err}"),
    })?
    else {
        return Err(not_found(&format!("Attachment '{}' not found", attachment_id)));
    };
    if is_protected && !session::is_available() {
        return Err(ApiError {
            status: 403,
            message: format!("Content of '{attachment_id}' is protected and no protected session is open."),
        });
    }
    let bytes = if is_protected {
        session::decrypt_bytes(&String::from_utf8_lossy(&raw)).unwrap_or_default()
    } else {
        raw
    };

    let (format, width, height) = inspect_image_geometry(&bytes);
    let detected_mime = match format {
        "png" => "image/png",
        "jpg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        _ => "unknown",
    };

    Ok(json!({
        "entityType": "attachment",
        "entityId": attachment_id,
        "title": session::title_or_mask(attachment.is_protected, attachment.title),
        "mime": attachment.mime,
        "format": format,
        "detectedMime": detected_mime,
        "size": bytes.len(),
        "width": width,
        "height": height,
        "bitDepth": null,
        "channels": null,
        "hasAlpha": null,
        "indexed": null,
        "quality": null,
        "compressible": matches!(format, "png" | "jpg" | "webp"),
    }))
}

/// The format and pixel dimensions of an image, read off its header — a light
/// stand-in for `inspectImage` (PNG IHDR, GIF logical screen, JPEG SOF scan,
/// WebP/BMP headers supported; the JPEG quality / PNG color-type depth are not).
fn inspect_image_geometry(bytes: &[u8]) -> (&'static str, Option<u32>, Option<u32>) {
    if bytes.len() >= 24 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" && &bytes[12..16] == b"IHDR" {
        let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        return ("png", Some(w), Some(h));
    }
    if bytes.len() >= 10 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        let w = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as u32;
        let h = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as u32;
        return ("gif", Some(w), Some(h));
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        if let Some((w, h)) = jpeg_sof_dimensions(bytes) {
            return ("jpg", Some(w), Some(h));
        }
        return ("jpg", None, None);
    }
    if bytes.len() >= 30 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return ("webp", None, None);
    }
    if bytes.len() >= 26 && &bytes[..2] == b"BM" {
        let w = u32::from_le_bytes(bytes[18..22].try_into().unwrap());
        let h = u32::from_le_bytes(bytes[22..26].try_into().unwrap());
        return ("bmp", Some(w), Some(h));
    }
    ("unknown", None, None)
}

/// Walk the JPEG segment table for a SOF marker, which carries the height and
/// width just after the 2-byte length field.
fn jpeg_sof_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let mut i = 2usize;
    while i + 4 <= bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        // Standalone markers (RST/DHT/SOS/etc.) carry no length; a stuffed 0xFF
        // after a marker byte is part of the data.
        if marker == 0xFF || marker == 0x00 || (0xD0..=0xD9).contains(&marker) {
            i += 1;
            continue;
        }
        let seg_len = u16::from_be_bytes(bytes[i + 2..i + 4].try_into().unwrap()) as usize;
        if seg_len < 2 || i + 2 + seg_len > bytes.len() {
            return None;
        }
        if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) && seg_len >= 8 {
            if i + 9 > bytes.len() {
                return None;
            }
            let h = u16::from_be_bytes(bytes[i + 5..i + 7].try_into().unwrap()) as u32;
            let w = u16::from_be_bytes(bytes[i + 7..i + 9].try_into().unwrap()) as u32;
            return Some((w, h));
        }
        i += 2 + seg_len;
    }
    None
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
        let note_title = note_display_title(conn, &note_id, note_path_title.clone());
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

/// Display title of a note: decrypted while the protected session is open,
/// `[protected]` when a protected note is locked — `getTitleOrProtected`.
fn note_display_title(conn: &rusqlite::Connection, note_id: &str, fallback: String) -> String {
    match db::get_note(conn, note_id) {
        Some(note) => session::title_or_mask(note.is_protected, note.title),
        None => fallback,
    }
}

/// Join the note titles along a path with " › ", mirroring `getNoteTitleForPath`.
fn title_path(conn: &rusqlite::Connection, note_ids: &[&str]) -> String {
    let titles: Vec<String> = note_ids
        .iter()
        .map(|id| note_display_title(conn, id, format!("[{id}]")))
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

/// Log in to the protected session: verify the password, decrypt the data key,
/// emit the `protectedSessionLogin` websocket message to cause the client to
/// reload all notes (they get decrypted).
fn login_protected(
    conn: &rusqlite::Connection,
    app: &AppHandle,
    data: &Option<Value>,
) -> Result<Value, ApiError> {
    let Some(payload) = data else {
        return Err(bad_request("Missing payload for login/protected"));
    };
    let password = payload.get("password").and_then(Value::as_str).unwrap_or_default();

    if !session::verify_password(conn, password) {
        return Ok(json!({ "success": false, "message": "Given current password doesn't match hash" }));
    }
    let Some(key) = session::get_data_key(conn, password) else {
        return Ok(json!({ "success": false, "message": "Unable to obtain data key." }));
    };
    session::set_data_key(key);

    messages::emit_to_frontend(app, json!({ "type": "protectedSessionLogin" }));

    Ok(json!({ "success": true }))
}

/// Touch the protected session (keep the timeout countdown ticking); the client does
/// this periodically, so accept it and do nothing.
fn touch_protected() -> Result<Value, ApiError> {
    // The session already touches on the write path; this is a no-op.
    Ok(json!({}))
}

/// Log out of the protected session: reset the global data key, emit the
/// `protectedSessionLogout` message which the client handles by reloading the
/// frontend to clear all the decrypted content in memory.
fn logout_protected(app: &AppHandle) -> Result<Value, ApiError> {
    session::reset();
    messages::emit_to_frontend(app, json!({ "type": "protectedSessionLogout" }));
    Ok(json!({}))
}

/// Change the current password from `current_password` to `new_password`. Fails if the
/// current password does not pass verification. Re-salts everything: fresh salts,
/// fresh verification hash, and the existing data key re-wrapped under the new key.
fn change_password(conn: &rusqlite::Connection, data: &Option<Value>) -> Result<Value, ApiError> {
    let Some(payload) = data else {
        return Err(bad_request("Missing payload for password/change"));
    };
    let current_password = payload.get("current_password").and_then(Value::as_str).unwrap_or_default();
    let new_password = payload.get("new_password").and_then(Value::as_str).unwrap_or_default();

    match session::change_password(conn, current_password, new_password)
        .map_err(|err| ApiError { status: 500, message: err })?
    {
        session::PasswordChange::Ok => Ok(json!({ "success": true })),
        session::PasswordChange::WrongPassword => {
            Ok(json!({ "success": false, "message": "Given current password doesn't match hash" }))
        }
    }
}

/// Reset the password: clear all password options, which permanently locks any
/// protected notes the user already has protected. Guarded by the same
/// `really=...` query confirmation as the real route.
fn reset_password(conn: &rusqlite::Connection, query: &str) -> Result<Value, ApiError> {
    if parse_param(query, "really") != Some("yesIReallyWantToResetPasswordAndLoseAccessToMyProtectedNotes") {
        return Err(ApiError {
            status: 400,
            message: "Incorrect password reset confirmation".to_string(),
        });
    }
    session::reset_password(conn).map_err(|err| ApiError {
        status: 500,
        message: err,
    })?;
    Ok(json!({ "success": true }))
}

/// `PUT /notes/{id}/protect/{0|1}` — (un)protect a note, and its whole subtree
/// when `?subtree=1`. The entity flipping (content/titles/revisions/attachments)
/// happens in `write::protect_note`; this handler then emits the `taskSucceeded`
/// progress message the client's protect dialog listens for.
fn protect_note(
    conn: &rusqlite::Connection,
    app: &AppHandle,
    note_id: &str,
    protect_raw: &str,
    query: &str,
) -> Result<Value, ApiError> {
    let protect = protect_raw == "1";
    let subtree = parse_param(query, "subtree").map(|v| v == "1").unwrap_or(false);

    db::write::protect_note(conn, note_id, protect, subtree).map_err(|err| ApiError {
        status: err.status,
        message: err.message,
    })?;

    messages::emit_to_frontend(
        app,
        json!({
            "type": "taskSucceeded",
            "taskId": db::write::random_string(10),
            "taskType": "protectNotes",
            "data": { "protect": protect },
            "result": null
        }),
    );

    Ok(json!({}))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_geometry_reads_png_gif_jpeg_headers() {
        // Minimal PNG: signature + IHDR with 127x80.
        let mut png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x50]);
        assert_eq!(inspect_image_geometry(&png), ("png", Some(127), Some(80)));

        // GIF89a logical screen 320x200, little-endian.
        let gif = [b'G', b'I', b'F', b'8', b'9', b'a', 0x40, 0x01, 0xC8, 0x00];
        assert_eq!(inspect_image_geometry(&gif), ("gif", Some(320), Some(200)));

        // JPEG: SOI followed directly by a full SOF0 (length 10) carrying 250x100.
        let jpeg = [
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0A, 0x08, 0x00, 0x64, 0x00, 0xFA, 0x01, 0x11, 0x22,
        ];
        assert_eq!(inspect_image_geometry(&jpeg), ("jpg", Some(250), Some(100)));

        // Anything else stays unclassified.
        assert_eq!(inspect_image_geometry(b"not an image"), ("unknown", None, None));
    }
}