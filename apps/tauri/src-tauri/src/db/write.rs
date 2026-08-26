//! Fidelity-faithful write path for `PUT /notes/{id}/data` (edit-save).
//!
//! This reproduces the canonical sync write against the existing Trilium database,
//! exactly as `packages/trilium-core` does it:
//!
//! - `notes.updateNoteData` orchestrates: save a revision snapshot first, then scan
//!   the content for internal/image links (kept as `relations` on the note), then
//!   `BNote.setContent` (blob dedup, note row update, entity changes).
//! - Blob identity is `hashedBlobId` (base64-sha512, first 20 chars); a blob row is
//!   inserted once and, if it becomes unreferenced, purged (with its `entity_changes`).
//! - Every mutation records a `entity_changes` row so sync sees it. The hash scheme
//!   matches `AbstractBeccaEntity.generateHash`: base64-sha1 over the `|`-joined
//!   hashed properties, truncated to 10 chars (`+deleted` suffix for soft deletes).
//!
//! Deferred in this vertical slice (separate subsystems): OCR `textRepresentation`, and content
//! encryption for protected notes (protected notes are refused here). Remote image download and
//! image-attachment orphan cleanup are implemented; image recompression/shrinking is not.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{Duration, Local, Utc};
use rand::Rng;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;

/// A database error in the write path, surfaced to the caller as an HTTP-style error.
#[derive(Debug)]
pub struct WriteError {
    pub status: u16,
    pub message: String,
}

impl WriteError {
    fn not_found(note_id: &str) -> Self {
        WriteError {
            status: 404,
            message: format!("Note '{}' not found", note_id),
        }
    }
    fn unavailable(note_id: &str) -> Self {
        WriteError {
            status: 400,
            message: format!("Note '{}' is not available for change!", note_id),
        }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<rusqlite::Error> for WriteError {
    fn from(err: rusqlite::Error) -> Self {
        WriteError {
            status: 500,
            message: format!("database error: {err}"),
        }
    }
}

const BLOB_POOL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generate a random id of `[A-Za-z0-9]` of the given length, matching `randtoken` in
/// the real server (note ids, attribute ids, change ids are all this shape).
fn random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| BLOB_POOL[rng.gen_range(0..BLOB_POOL.len())] as char)
        .collect()
}

/// A process-wide instance id, mirroring the memoized `getInstanceId()`.
fn instance_id() -> &'static str {
    static INSTANCE_ID: OnceLock<String> = OnceLock::new();
    INSTANCE_ID.get_or_init(|| random_string(12))
}

/// base64-encode raw bytes exactly like Node's `Buffer.toString("base64")`.
fn base64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

fn sha1_nfc(input: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(input.nfc().collect::<String>());
    hasher.finalize().to_vec()
}

/// `hash()` in the util: base64-sha1 over the string. Used for entity-change hashes,
/// truncated to 10 chars for entities (matching `generateHash`).
fn hash10(input: &str) -> String {
    base64(&sha1_nfc(input))[..10].to_string()
}

/// `hashedBlobId`: base64-sha512 of the bytes, `+`/`/` swapped out, 20 chars.
fn hashed_blob_id_bytes(content: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(content);
    let digest = hasher.finalize();
    let b64 = base64(&digest).replace('+', "X").replace('/', "Y");
    b64[..20].to_string()
}

/// `hashedBlobId` for UTF-8 string content.
fn hashed_blob_id(content: &str) -> String {
    hashed_blob_id_bytes(content.as_bytes())
}

/// The blob content as stored in the `blobs.content` column: string notes go in as
/// TEXT (so the client reads them back as strings), attachment bytes as BLOB.
enum BlobContent<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
}

fn utc_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S%.3fZ").to_string()
}

fn local_now() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f%z").to_string()
}

/// The note's editable fields plus the timestamps the write path needs.
struct WriteNote {
    note_id: String,
    title: String,
    note_type: String,
    mime: String,
    is_protected: bool,
    blob_id: Option<String>,
    date_modified: String,
    utc_date_created: String,
    utc_date_modified: String,
}

fn load_note(conn: &Connection, note_id: &str) -> rusqlite::Result<Option<WriteNote>> {
    let mut stmt = conn.prepare(
        "SELECT noteId, title, type, mime, isProtected, blobId, dateModified, utcDateCreated, utcDateModified \
         FROM notes WHERE noteId = ?1 AND isDeleted = 0",
    )?;
    let mut rows = stmt.query(params![note_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(WriteNote {
            note_id: row.get(0)?,
            title: row.get(1)?,
            note_type: row.get(2)?,
            mime: row.get(3)?,
            is_protected: row.get(4)?,
            blob_id: row.get(5)?,
            date_modified: row.get(6)?,
            utc_date_created: row.get(7)?,
            utc_date_modified: row.get(8)?,
        }))
    } else {
        Ok(None)
    }
}

/// Record one entity change, mirroring `entity_changes.putEntityChange`: a fresh
/// change id, the process instance id, `isSynced = 1` (these entities are always
/// synced), and an upsert so an existing `(entityName, entityId)` row is replaced.
fn put_entity_change(
    conn: &Connection,
    entity_name: &str,
    entity_id: &str,
    hash: &str,
    utc_date_changed: &str,
) -> rusqlite::Result<()> {
    let change_id = random_string(12);
    conn.execute(
        "INSERT OR REPLACE INTO entity_changes \
         (entityName, entityId, hash, isErased, changeId, componentId, instanceId, isSynced, utcDateChanged) \
         VALUES (?1, ?2, ?3, 0, ?4, 'NA', ?5, 1, ?6)",
        params![entity_name, entity_id, hash, change_id, instance_id(), utc_date_changed],
    )?;
    Ok(())
}

/// Insert a blob row (deduplicated by id) and its entity change, exactly like
/// `saveBlob`. `hash_str` is the `content` fed to `calculateContentHash`
/// (`${blobId}|${content}`): the UTF-8 string for string blobs, or the bytes
/// comma-joined as `Uint8Array.toString()` does for binary ones. Returns whether
/// the blob row was actually newly inserted.
fn insert_blob(
    conn: &Connection,
    blob_id: &str,
    content: BlobContent,
    hash_str: &str,
    local: &str,
    utc: &str,
) -> rusqlite::Result<bool> {
    let existing: i64 = conn
        .query_row(
            "SELECT 1 FROM blobs WHERE blobId = ?1",
            params![blob_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);

    if existing == 1 {
        return Ok(false);
    }

    match content {
        BlobContent::Text(text) => conn.execute(
            "INSERT INTO blobs (blobId, content, dateModified, utcDateModified) VALUES (?1, ?2, ?3, ?4)",
            params![blob_id, text, local, utc],
        )?,
        BlobContent::Bytes(bytes) => conn.execute(
            "INSERT INTO blobs (blobId, content, dateModified, utcDateModified) VALUES (?1, ?2, ?3, ?4)",
            params![blob_id, bytes, local, utc],
        )?,
    };

    // Blob hash is the full base64-sha1 (not truncated); `calculateContentHash`
    // concatenates blobId|content (no textRepresentation here).
    let hash = base64(&sha1_nfc(&format!("{blob_id}|{hash_str}")));
    put_entity_change(conn, "blobs", blob_id, &hash, utc)?;
    Ok(true)
}

/// `deleteBlobIfNotUsed`: only purge a blob once no note/attachment/revision
/// references it any more.
fn delete_blob_if_not_used(conn: &Connection, blob_id: &str) -> rusqlite::Result<()> {
    for (table, column) in [("notes", "blobId"), ("attachments", "blobId"), ("revisions", "blobId")] {
        let used: i64 = conn
            .query_row(&format!("SELECT 1 FROM {table} WHERE {column} = ?1 LIMIT 1"), params![blob_id], |row| row.get(0))
            .optional()?
            .unwrap_or(0);
        if used == 1 {
            return Ok(());
        }
    }
    conn.execute("DELETE FROM blobs WHERE blobId = ?1", params![blob_id])?;
    conn.execute(
        "DELETE FROM entity_changes WHERE entityName = 'blobs' AND entityId = ?1",
        params![blob_id],
    )?;
    Ok(())
}

/// The `notes`-entity hash over its hashed properties `noteId|title|isProtected|type|mime|blobId`.
fn note_hash(note: &WriteNote, is_deleted: bool) -> String {
    let protected = if note.is_protected { "true" } else { "false" };
    let mut input = format!(
        "{}|{}|{}|{}|{}|{}",
        note.note_id,
        note.title,
        protected,
        note.note_type,
        note.mime,
        note.blob_id.as_deref().unwrap_or("")
    );
    if is_deleted {
        input.push_str("|deleted");
    }
    hash10(&input)
}

/// `BNote.save()`: stamp fresh timestamps and persist the note row + entity change.
fn save_note(conn: &Connection, note: &WriteNote) -> rusqlite::Result<()> {
    let local = local_now();
    let utc = utc_now();
    conn.execute(
        "UPDATE notes SET blobId = ?1, dateModified = ?2, utcDateModified = ?3 WHERE noteId = ?4",
        params![note.blob_id, local, utc, note.note_id],
    )?;
    put_entity_change(conn, "notes", &note.note_id, &note_hash(note, false), &utc)
}

fn is_label_truthy(conn: &Connection, note_id: &str, name: &str) -> rusqlite::Result<bool> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM attributes WHERE noteId = ?1 AND type = 'label' AND name = ?2 AND isDeleted = 0",
            params![note_id, name],
            |row| row.get(0),
        )
        .ok();
    Ok(value.map_or(false, |v| v != "false"))
}

/// `saveRevisionIfNeeded`: snapshot the note before this edit if the last revision is
/// older than `revisionSnapshotTimeInterval` and the note itself predates the cutoff.
fn save_revision_if_needed(conn: &Connection, note: &WriteNote) -> rusqlite::Result<()> {
    if note.note_type == "file" || note.note_type == "image" || is_label_truthy(conn, &note.note_id, "disableVersioning")? {
        return Ok(());
    }

    let interval: i64 = crate::db::get_option(conn, "revisionSnapshotTimeInterval")
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);

    let cutoff = (Utc::now() - Duration::seconds(interval))
        .format("%Y-%m-%d %H:%M:%S%.3fZ")
        .to_string();

    // utc dates are `YYYY-MM-DD HH:MM:SS.sssZ`: lexicographic compare is chronological.
    // No prior snapshot means the note needs one (absent = 0, not "no rows").
    let existing: i64 = conn
        .query_row(
            "SELECT 1 FROM revisions WHERE noteId = ?1 AND utcDateCreated >= ?2 LIMIT 1",
            params![note.note_id, cutoff],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let note_older_than_cutoff = note.utc_date_created.as_str() <= cutoff.as_str();

    if existing == 0 && note_older_than_cutoff {
        create_revision(conn, note)?;
    }
    Ok(())
}

/// `BNote.saveRevision` for the common case (no attachments): write a revisions row
/// pointing at the note's current (unchanged) blob, plus its entity change, then trim
/// excess snapshots. Content is byte-identical to the note's current blob, so the same
/// blobId is reused and no new blob/entity-change is created.
fn create_revision(conn: &Connection, note: &WriteNote) -> rusqlite::Result<()> {
    let revision_id = random_string(12);
    let utc = utc_now();
    let local = local_now();
    let blob_id = note.blob_id.as_deref().unwrap_or("");

    conn.execute(
        "INSERT INTO revisions \
         (revisionId, noteId, type, mime, title, description, source, isProtected, blobId, \
          utcDateLastEdited, utcDateCreated, utcDateModified, dateLastEdited, dateCreated) \
         VALUES (?1, ?2, ?3, ?4, ?5, '', 'auto', ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            revision_id,
            note.note_id,
            note.note_type,
            note.mime,
            note.title,
            note.is_protected,
            blob_id,
            note.utc_date_modified,
            utc,
            utc,
            note.date_modified,
            local,
        ],
    )?;

    // Revision hashed properties, in order: revisionId, noteId, title, description,
    // source, isProtected, dateLastEdited, dateCreated, utcDateLastEdited,
    // utcDateCreated, utcDateModified, blobId.
    let protected = if note.is_protected { "true" } else { "false" };
    let hash_input = format!(
        "{revision_id}|{}|{}||auto|{protected}|{}|{local}|{}|{utc}|{utc}|{blob_id}",
        note.note_id, note.title, note.date_modified, note.utc_date_modified
    );
    put_entity_change(conn, "revisions", &revision_id, &hash10(&hash_input), &utc)?;

    erase_excess_revision_snapshots(conn, &note.note_id)
}

/// `eraseExcessRevisionSnapshots`: keep the newest `revisionSnapshotNumberLimit`
/// snapshots, erasing the older ones (and any blob only they referenced).
fn erase_excess_revision_snapshots(conn: &Connection, note_id: &str) -> rusqlite::Result<()> {
    let limit: i64 = crate::db::get_option(conn, "revisionSnapshotNumberLimit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    if limit < 0 {
        return Ok(());
    }

    let count: i64 = conn.query_row(
        "SELECT COUNT(1) FROM revisions WHERE noteId = ?1",
        params![note_id],
        |row| row.get(0),
    )?;
    let to_erase = count - limit;
    if to_erase <= 0 {
        return Ok(());
    }

    let mut stmt = conn.prepare(
        "SELECT revisionId, blobId FROM revisions WHERE noteId = ?1 ORDER BY utcDateCreated ASC LIMIT ?2",
    )?;
    let victims: Vec<(String, Option<String>)> = stmt
        .query_map(params![note_id, to_erase], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (revision_id, blob_id) in victims {
        conn.execute("DELETE FROM revisions WHERE revisionId = ?1", params![revision_id])?;
        conn.execute(
            "DELETE FROM entity_changes WHERE entityName = 'revisions' AND entityId = ?1",
            params![revision_id],
        )?;
        if let Some(blob_id) = blob_id {
            delete_blob_if_not_used(conn, &blob_id)?;
        }
    }
    Ok(())
}

/// A found reference of a given kind in the note content.
#[derive(Clone, PartialEq)]
struct FoundLink {
    name: &'static str,
    value: String,
}

/// Decode the common HTML character references, named and numeric (decimal or hex).
fn decode_html(input: &str) -> String {
    let re = Regex::new(r"&(amp|lt|gt|quot|apos|nbsp|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        let code = &caps[1];
        match code.as_ref() {
            "amp" => "&".to_string(),
            "lt" => "<".to_string(),
            "gt" => ">".to_string(),
            "quot" => "\"".to_string(),
            "apos" => "'".to_string(),
            "nbsp" => "\u{00a0}".to_string(),
            _ => {
                let cp = code
                    .get(1..)
                    .and_then(|digits| {
                        if code.starts_with("#x") || code.starts_with("#X") {
                            u32::from_str_radix(digits, 16).ok()
                        } else {
                            digits.parse::<u32>().ok()
                        }
                    })
                    .and_then(char::from_u32);
                if let Some(ch) = cp {
                    ch.to_string()
                } else {
                    format!("&{code};")
                }
            }
        }
    })
    .into_owned()
}

/// `prepareTitle`: derive a plain attachment title from the inline attachment's link
/// label by stripping tags and decoding entities, then collapsing whitespace
/// (`parseHtml(html).text.replace(/\s+/g, " ").trim()`).
fn prepare_title(html: &str) -> String {
    let strip_tags = Regex::new(r"<[^>]*>").unwrap();
    let text = strip_tags.replace_all(html, "");
    let decoded = decode_html(&text);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `stripStaleSrcset`: an imaged pasted from the web keeps its external `srcset`/`sizes`;
/// once the `src` is localized to a Trilium attachment (and the external URLs are gone) the
/// browsers prefer `srcset` over `src`, so drop them from any attachment-backed `<img>`.
fn strip_stale_srcset(content: &str) -> String {
    let img = Regex::new(r"(?i)<img\b[^>]*>").unwrap();
    let has_attachment_src =
        Regex::new(r#"(?i)\ssrc\s*=\s*(?:"api/attachments/[^"]+"|'api/attachments/[^']+')"#).unwrap();
    let drop = Regex::new(r#"(?i)\s(?:srcset|sizes)\s*=\s*(?:"[^"]*"|'[^']*')"#).unwrap();
    img.replace_all(content, |caps: &regex::Captures| {
        let tag = &caps[0];
        if !has_attachment_src.is_match(tag) {
            return tag.to_string();
        }
        drop.replace_all(tag, "").into_owned()
    })
    .into_owned()
}

/// Save one attachment of a note: a content blob (binary) plus an `attachments` row and its
/// entity change. `role` describes what created the attachment ("file" for a plain inline
/// attachment, "image" for a stored picture); see `AttachmentRoleTraits` in the real server.
fn save_attachment(
    conn: &Connection,
    owner_id: &str,
    role: &str,
    title: &str,
    mime: &str,
    is_protected: bool,
    content: &[u8],
    local: &str,
    utc: &str,
) -> rusqlite::Result<String> {
    let attachment_id = random_string(12);
    let blob_id = hashed_blob_id_bytes(content);
    // `Uint8Array.toString()` joins the bytes with commas; `calculateContentHash` uses it.
    let hash_str = content.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
    insert_blob(conn, &blob_id, BlobContent::Bytes(content), &hash_str, local, utc)?;

    let max_position: i64 = conn.query_row(
        "SELECT COALESCE(MAX(position), 0) FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
        params![owner_id],
        |row| row.get(0),
    )?;
    let protected: i64 = i64::from(is_protected);
    conn.execute(
        "INSERT INTO attachments \
         (attachmentId, ownerId, role, mime, title, isProtected, position, blobId, dateModified, \
          utcDateModified, utcDateScheduledForErasureSince, isDeleted, deleteId) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, 0, NULL)",
        params![attachment_id, owner_id, role, mime, title, protected, max_position + 10, blob_id, local, utc],
    )?;

    // Attachment hashed properties, in order: attachmentId, ownerId, role, mime, title,
    // blobId, utcDateScheduledForErasureSince. A fresh attachment has the last one unset,
    // which serializes as the literal `undefined`.
    let hash_input = format!("|{attachment_id}|{owner_id}|{role}|{mime}|{title}|{blob_id}|undefined");
    put_entity_change(conn, "attachments", &attachment_id, &hash10(&hash_input), utc)?;
    Ok(attachment_id)
}

/// `saveAttachments`: pull inline base64 attachments (`<a href="data:...">`) out of a text
/// note's content into real attachments, rewrite the anchor to a reference-link, relativize
/// absolute attachment URLs, and drop stale srcset. Returns the rewritten content.
fn save_attachments(conn: &Connection, note: &WriteNote, content: &str) -> rusqlite::Result<String> {
    let inline = Regex::new(r#"(?i)<a[^>]*?\shref=['"]data:([^;'">]+);base64,([^'">]+)['"][^>]*>(.*?)</a>"#).unwrap();
    let local = local_now();
    let utc = utc_now();

    let mut out = String::with_capacity(content.len());
    let mut last = 0;
    for cap in inline.captures_iter(content) {
        let whole = cap.get(0).unwrap();
        out.push_str(&content[last..whole.start()]);

        let mime = cap[1].to_lowercase();
        let title = prepare_title(&cap[3]);
        let bytes = match BASE64.decode(cap[2].as_bytes()) {
            Ok(bytes) => bytes,
            // A malformed inline attachment leaves the original tag in place rather than
            // failing the whole save.
            Err(_) => {
                out.push_str(whole.as_str());
                last = whole.end();
                continue;
            }
        };

        let attachment_id = save_attachment(conn, &note.note_id, "file", &title, &mime, note.is_protected, &bytes, &local, &utc)?;
        out.push_str(&format!(
            r##"<a class="reference-link" href="#root/{0}?viewMode=attachments&attachmentId={1}">{2}</a>"##,
            note.note_id, attachment_id, title
        ));
        last = whole.end();
    }
    out.push_str(&content[last..]);

    // Remove absolute references to the server to keep the paths relative and portable.
    let abs_re = Regex::new(r#"src="[^"]*/api/attachments/"#).unwrap();
    let out = abs_re.replace_all(&out, "src=\"api/attachments/").into_owned();
    Ok(strip_stale_srcset(&out))
}

/// A picture's format, detected from magic bytes (mirrors `inspectImage`). Recompression/shrinking
/// is not done in this shell, so the bytes are stored as fetched; the detected mime is still kept.
struct DetectedImage {
    mime: &'static str,
    ext: &'static str,
}

fn inspect_image(bytes: &[u8]) -> Option<DetectedImage> {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() >= 8 && &bytes[..8] == PNG {
        return Some(DetectedImage { mime: "image/png", ext: "png" });
    }
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return Some(DetectedImage { mime: "image/jpeg", ext: "jpg" });
    }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        return Some(DetectedImage { mime: "image/gif", ext: "gif" });
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some(DetectedImage { mime: "image/webp", ext: "webp" });
    }
    if bytes.len() >= 2 && &bytes[..2] == b"BM" {
        return Some(DetectedImage { mime: "image/bmp", ext: "bmp" });
    }
    None
}

/// `encodeURIComponent`: percent-encode everything outside the RFC 3986 "unreserved" set, leaving
/// ASCII letters, digits and `-_.!~*'()` bare. Multi-byte UTF-8 is encoded byte by byte, as JS does.
fn encode_uri_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `sanitize-filename`: strip path separators, the Windows-invalid characters, and control codes
/// (kept Unicode letters and spaces), then trim trailing dots/spaces. Empty collapses to `"image"`.
fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    let trimmed = out.trim_end_matches(|c: char| c == '.' || c == ' ').to_string();
    if trimmed.is_empty() {
        "image".to_string()
    } else {
        trimmed
    }
}

/// The trailing path segment of a URL without its query/fragment, used as an image's title (so
/// `https://x/img/photo.jpg?w=1` names the attachment `photo.jpg`).
fn url_basename(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or("");
    let no_query = no_frag.split('?').next().unwrap_or("");
    let base = no_query.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        "image".to_string()
    } else {
        base.to_string()
    }
}

/// SSRF guard shared by download paths: only `http:`/`https:` are reachable.
fn is_http_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// The `downloadImagesAutomatically` switch: fetching a remote picture is the note reaching out on
/// the reader's behalf, so it is the user's call, not ours.
fn download_images_automatically(conn: &Connection) -> bool {
    crate::db::get_option(conn, "downloadImagesAutomatically").map_or(false, |v| v == "true" || v == "1")
}

/// An `<img>` `src` names a Trilium image already when it points at `api/images` (an image note),
/// at `api/attachments/.../image`, or at a bare clipper id — none of those need fetching.
fn is_local_image_url(url: &str, local_attachment: &Regex) -> bool {
    url.contains("api/images/")
        || local_attachment.is_match(url)
        || (url.len() == 20 && !url.to_lowercase().starts_with("http"))
}

fn collect_external_image_urls(content: &str) -> Vec<String> {
    let img_re = Regex::new(r#"(?i)<img[^>]{0,4096}?\ssrc=(["'])([^'" >]+)"#).unwrap();
    let inline_prefix = Regex::new(r"(?i)^data:image/[a-z]+;base64,").unwrap();
    let local_attachment = Regex::new(r"api/attachments/[^/]+/image").unwrap();

    let mut urls: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for cap in img_re.captures_iter(content) {
        let url = cap[2].to_string();
        if inline_prefix.is_match(&url) || is_local_image_url(&url, &local_attachment) || !is_http_url(&url) {
            continue;
        }
        if seen.insert(url.clone()) {
            urls.push(url);
        }
    }
    urls
}

/// Cap on a single downloaded picture; a server that answers with more is refused rather than held
/// in memory (and, previously, written into the attached document).
const MAX_IMAGE_BYTES: u64 = 50 * 1024 * 1024;

fn fetch_image(url: &str) -> Option<Vec<u8>> {
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(30)).build();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(err) => {
            eprintln!("Could not download image '{url}': {err}");
            return None;
        }
    };
    let mut bytes = Vec::new();
    if response.into_reader().take(MAX_IMAGE_BYTES).read_to_end(&mut bytes).is_err() {
        eprintln!("Could not read image '{url}'");
        return None;
    }
    Some(bytes)
}

/// Download the external `<img>` URLs a text note's content names, before the write transaction
/// opens so the DB lock is not held across the network. Gated by `downloadImagesAutomatically`.
fn collect_and_fetch_external_images(conn: &Connection, content: &str) -> rusqlite::Result<HashMap<String, Vec<u8>>> {
    let mut fetched: HashMap<String, Vec<u8>> = HashMap::new();
    if !download_images_automatically(conn) {
        return Ok(fetched);
    }
    for url in collect_external_image_urls(content) {
        if let Some(bytes) = fetch_image(&url) {
            fetched.insert(url, bytes);
        }
    }
    Ok(fetched)
}

/// `saveImageToAttachment` mirror (minus compression): store picture `bytes` as an `image`-role
/// attachment of the note, detecting its format and appending an extension when the title has none.
/// Returns the attachment id and its final title.
fn save_image_attachment(
    conn: &Connection,
    note: &WriteNote,
    title: &str,
    bytes: &[u8],
    local: &str,
    utc: &str,
) -> rusqlite::Result<(String, String)> {
    let detected = inspect_image(bytes);
    let mime = detected.as_ref().map_or("unknown", |d| d.mime).to_string();
    let mut title = sanitize_filename(title);
    if let Some(detected) = &detected {
        if !title.contains('.') {
            title = sanitize_filename(&format!("{title}.{}", detected.ext));
        }
    }
    let attachment_id = save_attachment(conn, &note.note_id, "image", &title, &mime, note.is_protected, bytes, local, utc)?;
    Ok((attachment_id, title))
}

/// `downloadImages` + `saveAttachments` on `<img>` elements: base64 `data:` pictures and *fetched*
/// remote pictures are pulled out of the content into `image` attachments and the `src` rewritten to
/// `api/attachments/{id}/image/{title}`. A URL that was not fetched (option off, or the fetch failed)
/// is left pointing at its origin, exactly as the real server leaves a pending download.
fn rewrite_linked_images(
    conn: &Connection,
    note: &WriteNote,
    content: &str,
    downloaded: &HashMap<String, Vec<u8>>,
) -> rusqlite::Result<String> {
    let img_re = Regex::new(r#"(?i)<img[^>]{0,4096}?\ssrc=(["'])([^'" >]+)"#).unwrap();
    let inline_prefix = Regex::new(r"(?i)^data:image/[a-z]+;base64,").unwrap();
    let local_attachment = Regex::new(r"api/attachments/[^/]+/image").unwrap();
    let local = local_now();
    let utc = utc_now();

    let mut out = String::with_capacity(content.len());
    let mut last = 0;
    for cap in img_re.captures_iter(content) {
        let whole = cap.get(0).unwrap();
        out.push_str(&content[last..whole.start()]);

        let quote = &cap[1];
        let url = &cap[2];
        let src_token = format!("src={quote}{url}{quote}");

        let title = if let Some(m) = inline_prefix.find(url) {
            // base64 data: picture carried inline; stored as an attachment, the *same* title the
            // real server gives any inline image.
            match BASE64.decode(&url[m.end()..]) {
                Ok(bytes) => {
                    let (id, title) = save_image_attachment(conn, note, "inline image", &bytes, &local, &utc)?;
                    Some(format!("src=\"api/attachments/{id}/image/{}\"", encode_uri_component(&title)))
                }
                Err(_) => None, // a malformed payload leaves the tag as it came in
            }
        } else if is_local_image_url(url, &local_attachment) {
            None
        } else if let Some(bytes) = downloaded.get(url) {
            let (id, title) = save_image_attachment(conn, note, &url_basename(url), bytes, &local, &utc)?;
            Some(format!("src=\"api/attachments/{id}/image/{}\"", encode_uri_component(&title)))
        } else {
            // Not fetched — option off, invalid URL, or the download failed. Kept as-is.
            None
        };

        match title {
            Some(new_src) => out.push_str(&whole.as_str().replace(&src_token, &new_src)),
            None => out.push_str(whole.as_str()),
        }
        last = whole.end();
    }
    out.push_str(&content[last..]);
    Ok(out)
}

/// Whether the given attachment role is managed by the content and so is auto-scheduled for erasure
/// when nothing refers to it: `isEmbeddedAttachmentRole` over `AttachmentRoleTraits`.
fn is_embedded_role(role: &str) -> bool {
    matches!(role, "image" | "file" | "favicon" | "coverImage")
}

/// `AttachmentRoleTraits.copiedAs`: what a hand-copied attachment of this role becomes. A role the
/// app does not know is kept as it was.
fn copied_as(role: &str) -> String {
    match role {
        "image" | "favicon" | "coverImage" => "image".to_string(),
        "file" => "file".to_string(),
        _ => role.to_string(),
    }
}

/// Set (or clear) the scheduled-erasure marker on an attachment, recording the changed entity hash.
/// The last hashed property (`utcDateScheduledForErasureSince`) serialises as `undefined` when unset.
fn set_attachment_erasure(
    conn: &Connection,
    attachment_id: &str,
    owner_id: &str,
    role: &str,
    mime: &str,
    title: &str,
    blob_id: &str,
    scheduled: Option<&str>,
) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE attachments SET utcDateScheduledForErasureSince = ?1, utcDateModified = ?2 WHERE attachmentId = ?3",
        params![scheduled, utc, attachment_id],
    )?;
    let scheduled_hash = scheduled.map(str::to_string).unwrap_or_else(|| "undefined".to_string());
    let hash_input = format!("|{attachment_id}|{owner_id}|{role}|{mime}|{title}|{blob_id}|{scheduled_hash}");
    put_entity_change(conn, "attachments", attachment_id, &hash10(&hash_input), &utc)
}

/// Copy a foreign attachment (referenced from this note's content but owned by another) into this
/// note under `role`, pointing at the same blob. Mirrors `BAttachment.copy()`.
fn copy_attachment(conn: &Connection, note_id: &str, role: &str, mime: &str, title: &str, blob_id: &str) -> rusqlite::Result<String> {
    let attachment_id = random_string(12);
    let local = local_now();
    let utc = utc_now();
    let max_position: i64 = conn.query_row(
        "SELECT COALESCE(MAX(position), 0) FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
        params![note_id],
        |row| row.get(0),
    )?;
    let is_protected: i64 = conn.query_row(
        "SELECT isProtected FROM notes WHERE noteId = ?1",
        params![note_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO attachments \
         (attachmentId, ownerId, role, mime, title, isProtected, position, blobId, dateModified, \
          utcDateModified, utcDateScheduledForErasureSince, isDeleted, deleteId) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, 0, NULL)",
        params![attachment_id, note_id, role, mime, title, is_protected, max_position + 10, blob_id, local, utc],
    )?;
    let hash_input = format!("|{attachment_id}|{note_id}|{role}|{mime}|{title}|{blob_id}|undefined");
    put_entity_change(conn, "attachments", &attachment_id, &hash10(&hash_input), &utc)?;
    Ok(attachment_id)
}

/// `checkImageAttachments` for text/markdown: schedule for erasure any embedded-role attachment the
/// content no longer refers to (and clear that the moment it is referenced again), and copy foreign
/// attachments the content references so this note owns them. Returns the (possibly rewritten)
/// content, mirroring the force-reload paths the real server returns.
fn check_image_attachments(conn: &Connection, note_id: &str, is_markdown: bool, content: &str) -> rusqlite::Result<String> {
    // Attachment ids referenced from the content; the preview pictures among them keep their role
    // when copied (a whole pasted preview stays a preview's).
    let mut found_ids: HashSet<String> = HashSet::new();
    let mut preview_ids: HashSet<String> = HashSet::new();

    if is_markdown {
        let md_url = Regex::new(r"api/attachments/([a-zA-Z0-9_]+)/image").unwrap();
        for m in md_url.captures_iter(content) {
            found_ids.insert(m[1].to_string());
        }
        let md_ref = Regex::new(r"attachmentId=([a-zA-Z0-9_]+)").unwrap();
        for m in md_ref.captures_iter(content) {
            found_ids.insert(m[1].to_string());
        }
    } else {
        let text_src = Regex::new(r#"(?i)src="[^"]*api/attachments/([a-zA-Z0-9_]+)/image"#).unwrap();
        for m in text_src.captures_iter(content) {
            found_ids.insert(m[1].to_string());
        }
        let text_preview = Regex::new(r#"(?i)data-(?:image|favicon)="[^"]*api/attachments/([a-zA-Z0-9_]+)/image"#).unwrap();
        for m in text_preview.captures_iter(content) {
            found_ids.insert(m[1].to_string());
            preview_ids.insert(m[1].to_string());
        }
        let text_ref = Regex::new(r#"(?i)href="[^"]+attachmentId=([a-zA-Z0-9_]+)"#).unwrap();
        for m in text_ref.captures_iter(content) {
            found_ids.insert(m[1].to_string());
        }
    }

    // This note's attachments, with the fields the erasure-schedule hash needs.
    let mut stmt = conn.prepare(
        "SELECT attachmentId, role, mime, title, blobId, utcDateScheduledForErasureSince \
         FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
    )?;
    let attachments: Vec<(String, String, String, String, Option<String>, Option<String>)> = stmt
        .query_map(params![note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (attachment_id, role, mime, title, blob_id, scheduled) in &attachments {
        if !is_embedded_role(role) {
            continue;
        }
        let in_content = found_ids.contains(attachment_id.as_str());
        if scheduled.is_some() && in_content {
            set_attachment_erasure(conn, attachment_id, note_id, role, mime, title, &blob_id.clone().unwrap_or_default(), None)?;
        } else if scheduled.is_none() && !in_content {
            set_attachment_erasure(conn, attachment_id, note_id, role, mime, title, &blob_id.clone().unwrap_or_default(), Some(&utc_now()))?;
        }
    }

    // Attachments the content references that this note does not own must be copied in.
    let existing_ids: HashSet<&str> = attachments.iter().map(|(id, _, _, _, _, _)| id.as_str()).collect();
    let unknown_ids: Vec<String> = found_ids.iter().filter(|id| !existing_ids.contains(id.as_str())).cloned().collect();

    let mut content = content.to_string();
    for unknown_id in &unknown_ids {
        let foreign: Option<(String, String, String, Option<String>, String)> = conn
            .query_row(
                "SELECT a.role, a.mime, a.title, a.blobId, a.ownerId \
                 FROM attachments a JOIN notes n ON n.noteId = a.ownerId \
                 WHERE a.attachmentId = ?1 AND a.isDeleted = 0 AND n.isDeleted = 0",
                params![unknown_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((foreign_role, foreign_mime, foreign_title, Some(foreign_blob), foreign_owner)) = foreign else {
            continue;
        };

        let copied_role = if preview_ids.contains(unknown_id.as_str()) { foreign_role.clone() } else { copied_as(&foreign_role) };

        // An attachment this note already holds with the same content (under the role the copy would
        // take) is reused rather than duplicated.
        let local_id = if let Some(existing) = conn
            .query_row(
                "SELECT attachmentId FROM attachments WHERE ownerId = ?1 AND role = ?2 AND blobId = ?3 AND isDeleted = 0 LIMIT 1",
                params![note_id, copied_role, foreign_blob],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let sched: Option<String> = conn
                .query_row("SELECT utcDateScheduledForErasureSince FROM attachments WHERE attachmentId = ?1", params![existing], |row| row.get(0))
                .optional()?;
            if sched.is_some() {
                let (r2, m2, t2, b2) = conn.query_row(
                    "SELECT role, mime, title, COALESCE(blobId, '') FROM attachments WHERE attachmentId = ?1",
                    params![existing],
                    |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))
                    },
                )?;
                set_attachment_erasure(conn, &existing, note_id, &r2, &m2, &t2, &b2, None)?;
            }
            existing
        } else {
            copy_attachment(conn, note_id, &copied_role, &foreign_mime, &foreign_title, &foreign_blob)?
        };

        // Rewrite every reference — image URLs and reference links alike.
        content = content.replace(
            &format!("api/attachments/{unknown_id}/image"),
            &format!("api/attachments/{local_id}/image"),
        );
        let href_re = Regex::new(&format!(r#"href="[^"]+attachmentId={unknown_id}[^"]*""#)).unwrap();
        content = href_re
            .replace_all(&content, format!(r##"href="#root/{note_id}?viewMode=attachments&amp;attachmentId={local_id}""##))
            .into_owned();
        let _ = foreign_owner; // kept for symmetry with the toast/log the real server emits
    }

    Ok(content)
}

/// `saveLinks`: download and localize images, extract inline attachments, scan the (possibly
/// rewritten) content for internal/image/include-note references and keep them as `relation`
/// attributes on the note — create the missing ones, soft-delete the stale ones, maintain bookmark
/// labels, and schedule orphaned images for erasure. Returns the content the blob should be written as.
fn save_links(conn: &Connection, note: &WriteNote, content: &str, downloaded: &HashMap<String, Vec<u8>>) -> rusqlite::Result<String> {
    let is_markdown = note.note_type == "code"
        && matches!(note.mime.as_str(), "text/markdown" | "text/x-markdown" | "text/x-gfm");
    if note.note_type != "text" && !is_markdown {
        return Ok(content.to_string());
    }

    let mut found: Vec<FoundLink> = Vec::new();
    let rewritten = if note.note_type == "text" {
        // Localize images first (inline base64 + fetched remote), then lift inline `<a>` attachments;
        // both run before link scanning so the relations match the written form of the content.
        let with_images = rewrite_linked_images(conn, note, content, downloaded)?;
        save_attachments(conn, note, &with_images)?
    } else {
        content.to_string()
    };

    let image_api = Regex::new(r"api/images/([a-zA-Z0-9_]+)/").unwrap();
    let hash_root = Regex::new(r"#root[a-zA-Z0-9_/]*/([a-zA-Z0-9_]+)").unwrap();
    let wiki = Regex::new(r"\[\[([a-zA-Z0-9_]+)\]\]").unwrap();
    let href_src = Regex::new(r#"src="[^"]*api/images/([a-zA-Z0-9_]+)/"#).unwrap();
    let href_root = Regex::new(r#"href="[^"]*#root[a-zA-Z0-9_/]*/([a-zA-Z0-9_]+)/?""#).unwrap();
    let include_note = Regex::new(r#"<section class="include-note[^>]+data-note-id="([a-zA-Z0-9_]+)"[^>]*>"#).unwrap();

    if note.note_type == "text" {
        for cap in href_src.captures_iter(&rewritten) {
            found.push(FoundLink { name: "imageLink", value: cap[1].to_string() });
        }
        for cap in href_root.captures_iter(&rewritten) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
        for cap in include_note.captures_iter(&rewritten) {
            found.push(FoundLink { name: "includeNoteLink", value: cap[1].to_string() });
        }
    } else if is_markdown {
        for cap in image_api.captures_iter(&rewritten) {
            found.push(FoundLink { name: "imageLink", value: cap[1].to_string() });
        }
        for cap in hash_root.captures_iter(&rewritten) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
        for cap in wiki.captures_iter(&rewritten) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
    }

    // Dedup, but only keep links whose target note exists (mirrors the becca lookup).
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    found.retain(|link| {
        if seen.contains(&(link.name.to_string(), link.value.clone())) {
            return false;
        }
        seen.insert((link.name.to_string(), link.value.clone()));
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM notes WHERE noteId = ?1 AND isDeleted = 0",
                params![link.value],
                |row| row.get::<_, i64>(0).map(|v| v == 1),
            )
            .unwrap_or(false);
        exists
    });

    sync_relations(conn, &note.note_id, &found)?;
    sync_bookmarks(conn, &note.note_id, &rewritten)?;

    // Orphan cleanup (schedule/clear erasure) and foreign-attachment copy run last, on the fully
    // rewritten content, and may rewrite references to copied attachments.
    check_image_attachments(conn, &note.note_id, is_markdown, &rewritten)
}

/// Attribute entity hash over `attributeId|noteId|type|name|value|isInheritable`.
fn attribute_hash(attribute_id: &str, note_id: &str, attr_type: &str, name: &str, value: &str, is_deleted: bool) -> String {
    let mut input = format!("{attribute_id}|{note_id}|{attr_type}|{name}|{value}|false");
    if is_deleted {
        input.push_str("|deleted");
    }
    hash10(&input)
}

/// Insert a new attribute (relation or label) with a nudged `position`, and record its
/// entity change.
fn insert_attribute(
    conn: &Connection,
    note_id: &str,
    attr_type: &str,
    name: &str,
    value: &str,
) -> rusqlite::Result<()> {
    let attribute_id = random_string(12);
    let max_position: i64 = conn.query_row(
        "SELECT COALESCE(MAX(position), 0) FROM attributes WHERE noteId = ?1 AND isDeleted = 0",
        params![note_id],
        |row| row.get(0),
    )?;
    let utc = utc_now();
    conn.execute(
        "INSERT INTO attributes \
         (attributeId, noteId, type, name, value, position, utcDateModified, isDeleted, deleteId, isInheritable) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, 0)",
        params![attribute_id, note_id, attr_type, name, value, max_position + 10, utc],
    )?;
    let hash = attribute_hash(&attribute_id, note_id, attr_type, name, value, false);
    put_entity_change(conn, "attributes", &attribute_id, &hash, &utc)
}

/// `markAsDeleted` for an attribute: soft-delete row + deleted entity change.
fn delete_attribute(conn: &Connection, attribute_id: &str, note_id: &str, attr_type: &str, name: &str, value: &str) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE attributes SET isDeleted = 1, deleteId = NULL, utcDateModified = ?1 WHERE attributeId = ?2",
        params![utc, attribute_id],
    )?;
    let hash = attribute_hash(attribute_id, note_id, attr_type, name, value, true);
    put_entity_change(conn, "attributes", attribute_id, &hash, &utc)
}

/// Keep the link relations on a note in agreement with the content: add any that are
/// missing, remove any that are no longer referenced.
fn sync_relations(conn: &Connection, note_id: &str, found: &[FoundLink]) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "SELECT attributeId, name, value FROM attributes \
         WHERE noteId = ?1 AND type = 'relation' AND name IN ('internalLink','imageLink','includeNoteLink','relationMapLink') \
         AND isDeleted = 0",
    )?;
    let existing: Vec<(String, String, String)> = stmt
        .query_map(params![note_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    for link in found {
        let already = existing
            .iter()
            .any(|(_, name, value)| name == link.name && value == &link.value);
        if !already {
            insert_attribute(conn, note_id, "relation", link.name, &link.value)?;
        }
    }

    for (attribute_id, name, value) in &existing {
        let still_referenced = found.iter().any(|l| l.name == name && &l.value == value);
        if !still_referenced {
            delete_attribute(conn, attribute_id, note_id, "relation", name, value)?;
        }
    }
    Ok(())
}

/// `saveBookmarks`: CKEditor bookmark anchors (`<a id="..">` with no href) become
/// `internalBookmark` labels; ones no longer in the content are dropped.
fn sync_bookmarks(conn: &Connection, note_id: &str, content: &str) -> rusqlite::Result<()> {
    let anchor = Regex::new(r#"(?i)<a\s+id="([^"]+)"[^>]*>"#).unwrap();
    let mut found: Vec<String> = Vec::new();
    for cap in anchor.captures_iter(content) {
        let tag_full = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        if tag_full.to_lowercase().contains("href=") {
            continue;
        }
        let id = cap[1].to_string();
        if !found.contains(&id) {
            found.push(id);
        }
    }

    let mut stmt = conn.prepare(
        "SELECT attributeId, value FROM attributes \
         WHERE noteId = ?1 AND type = 'label' AND name = 'internalBookmark' AND isDeleted = 0",
    )?;
    let existing: Vec<(String, String)> = stmt
        .query_map(params![note_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    for id in &found {
        let already = existing.iter().any(|(_, value)| value == id);
        if !already {
            insert_attribute(conn, note_id, "label", "internalBookmark", id)?;
        }
    }
    for (attribute_id, value) in &existing {
        if !found.contains(value) {
            delete_attribute(conn, attribute_id, note_id, "label", "internalBookmark", value)?;
        }
    }
    Ok(())
}

/// `updateNoteData`: the whole faithful edit-save in one transaction.
pub fn update_note_data(conn: &Connection, note_id: &str, content: &str) -> Result<(), WriteError> {
    // Remote <img> URLs are fetched *before* the write transaction opens, so the DB lock is never
    // held across a network round-trip. The note read here also gives us the protected check early.
    let pre = load_note(conn, note_id).map_err(WriteError::from)?;
    let Some(pre_note) = pre else {
        return Err(WriteError::not_found(note_id));
    };
    if pre_note.is_protected {
        return Err(WriteError::unavailable(note_id));
    }
    let downloaded: HashMap<String, Vec<u8>> = if pre_note.note_type == "text" {
        collect_and_fetch_external_images(conn, content).map_err(WriteError::from)?
    } else {
        HashMap::new()
    };

    conn.execute_batch("BEGIN")?;

    let run = (|| -> rusqlite::Result<()> {
        let Some(note) = load_note(conn, note_id)? else {
            return Err(rusqlite::Error::QueryReturnedNoRows); // mapped to 404 below
        };

        // Protected content has no decrypted write path yet in this shell.
        if note.is_protected {
            return Err(rusqlite::Error::InvalidQuery); // mapped to 400 below
        }

        save_revision_if_needed(conn, &note)?;

        let mut note = note;
        // saveLinks rewrites the content (images localized, inline attachments extracted, orphaned
        // images scheduled, stale srcset dropped); the blob and link attributes are kept in
        // agreement with the written form.
        let new_content = save_links(conn, &note, content, &downloaded)?;

        // setContent: dedup blob, point the note at it, delete the old one if unused.
        let new_blob_id = hashed_blob_id(&new_content);
        let local = local_now();
        let utc = utc_now();
        insert_blob(conn, &new_blob_id, BlobContent::Text(&new_content), &new_content, &local, &utc)?;

        if note.blob_id.as_deref() != Some(new_blob_id.as_str()) {
            let old_blob_id = note.blob_id.take();
            note.blob_id = Some(new_blob_id);
            save_note(conn, &note)?;
            if let Some(old) = old_blob_id {
                delete_blob_if_not_used(conn, &old)?;
            }
        }
        Ok(())
    })();

    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::not_found(note_id))
        }
        Err(rusqlite::Error::InvalidQuery) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::unavailable(note_id))
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use rand::Rng;

    /// Copy a real Trilium database to a fresh temp file and open it read-write, so the
    /// write path is exercised against the true schema without touching the source.
    fn copy_db(src: &str) -> Connection {
        let mut buf = Vec::new();
        std::fs::File::open(src).unwrap().read_to_end(&mut buf).unwrap();
        let path = std::env::temp_dir().join(format!(
            "trilium-verify-writepath-{}.db",
            rand::thread_rng().gen_range(0u32..1_000_000)
        ));
        std::fs::write(&path, &buf).unwrap();
        Connection::open(&path).unwrap()
    }

    /// A one-shot HTTP server that answers a single request with a PNG whose magic bytes
    /// satisfy `inspect_image`.
    fn serve_png() -> (String, thread::JoinHandle<()>) {
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/pic.png");
        let body = png.to_vec();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.read(&mut [0u8; 4096]);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        (url, handle)
    }

    /// Integration verification of the write path's remote-image download and
    /// attachment-orphan cleanup against a copy of a real database.
    ///
    /// Set `TRILIUM_VERIFY_SOURCE` to a real `document.db` path to enable; otherwise the
    /// test is reported as run-and-skipped (it cannot fabricate the schema by itself).
    #[test]
    fn remote_image_download_and_attachment_cleanup() {
        let Ok(src) = std::env::var("TRILIUM_VERIFY_SOURCE") else {
            eprintln!("TRILIUM_VERIFY_SOURCE not set; integration verification skipped");
            return;
        };
        let conn = copy_db(&src);

        // Remote download is opt-in; turn it on for this write.
        conn.execute("INSERT OR REPLACE INTO options (name, value, isSynced, utcDateModified) VALUES ('downloadImagesAutomatically', 'true', 1, ?1)", params![utc_now()])
            .unwrap();

        // A surviving, non-protected text note to save as; picked through `load_note` so the write
        // can deterministically act on it (a bare `LIMIT 1` can land on a note that will not load).
        let candidate_ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT noteId FROM notes WHERE type = 'text' AND isDeleted = 0").unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.map(|x| x.unwrap()).collect()
        };
        let note_id = candidate_ids
            .iter()
            .find(|id| matches!(load_note(&conn, id), Ok(Some(n)) if !n.is_protected))
            .cloned()
            .expect("no saveable (non-protected, loadable) text note");

        // Two embedded pictures the note owns: one stays referenced (kept), one is dropped (scheduled).
        let local = local_now();
        let utc = utc_now();
        let att_kept = random_string(12);
        let att_orphan = random_string(12);
        for (id, title) in [(&att_kept, "kept.png"), (&att_orphan, "orphan.png")] {
            conn.execute(
                "INSERT INTO attachments \
                 (attachmentId, ownerId, role, mime, title, isProtected, position, blobId, dateModified, \
                  utcDateModified, utcDateScheduledForErasureSince, isDeleted, deleteId) \
                 VALUES (?1, ?2, 'image', 'image/png', ?3, 0, 10, 'dummy-blob', ?4, ?5, NULL, 0, NULL)",
                params![id, note_id, title, local, utc],
            )
            .unwrap();
        }

        let (img_url, server) = serve_png();

        // Content: keep the first picture, drop the second, lift an inline base64 file, and pull a
        // remote picture from the local server.
        let content = format!(
            "<p>keep <img src=\"api/attachments/{att_kept}/image/kept.png\"></p>\
             <p><a href=\"data:image/png;base64,iVBORw0KGgo=\">inline file</a></p>\
             <p><img src=\"{img_url}\"></p>"
        );
        update_note_data(&conn, &note_id, &content).unwrap();
        server.join().unwrap();

        // The referenced picture must not be scheduled; the orphaned one must be.
        let kept_sched: Option<String> = conn
            .query_row("SELECT utcDateScheduledForErasureSince FROM attachments WHERE attachmentId = ?1", params![att_kept], |r| r.get(0))
            .unwrap();
        let orphan_sched: Option<String> = conn
            .query_row("SELECT utcDateScheduledForErasureSince FROM attachments WHERE attachmentId = ?1", params![att_orphan], |r| r.get(0))
            .unwrap();
        assert!(kept_sched.is_none(), "referenced picture must stay un-scheduled");
        assert!(orphan_sched.is_some(), "orphaned picture must be scheduled for erasure");

        // The inline base64 file was lifted into a `file` attachment.
        let inline_files: i64 = conn
            .query_row("SELECT COUNT(*) FROM attachments WHERE ownerId = ?1 AND role = 'file' AND isDeleted = 0", params![note_id], |r| r.get(0))
            .unwrap();
        assert!(inline_files >= 1, "inline attachment should be extracted as a file attachment");

        // The remote picture was fetched and stored: our download is the `image` attachment
        // titled `pic.png` (from the URL basename), and its blob holds PNG magic bytes.
        let remote_image_attachment: bool = {
            let mut stmt = conn
                .prepare("SELECT blobId FROM attachments WHERE ownerId = ?1 AND role = 'image' AND title = 'pic.png' AND isDeleted = 0")
                .unwrap();
            let mut any = false;
            let mut rows = stmt.query_map(params![note_id], |r| r.get::<_, String>(0)).unwrap();
            while let Some(blob_id) = rows.next() {
                if let Ok(blob_id) = blob_id {
                    if conn
                        .query_row("SELECT content FROM blobs WHERE blobId = ?1", params![blob_id], |r| r.get::<_, Vec<u8>>(0))
                        .map_or(false, |b| b.starts_with(b"\x89PNG"))
                    {
                        any = true;
                    }
                }
            }
            any
        };
        assert!(remote_image_attachment, "remote PNG should be stored as an image attachment");

        // The saved content localizes the remote picture and drops the inline data URI.
        let final_content: String = conn
            .query_row(
                "SELECT b.content FROM blobs b JOIN notes n ON n.blobId = b.blobId WHERE n.noteId = ?1 AND n.isDeleted = 0",
                params![note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            final_content.contains("api/attachments/") && !final_content.contains("data:image/png;base64,"),
            "content should be rewritten to attachment URLs"
        );
        eprintln!("write-path verification passed for note {note_id}");
    }
}