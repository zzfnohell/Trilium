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
//! Protected notes are supported end-to-end: content is encrypted at rest with the
//! protected-session data key (AES-128-CBC, see `crypto`), the title is encrypted
//! with it too, and blob ids are always hashed against the `_ENCRYPTED_`-prefixed
//! plaintext so an encrypted entity never shares a blob with its plaintext twin.
//! `protect_note` flips the flag over a note, its revisions and its attachments.
//!
//! Deferred in this vertical slice (separate subsystems): OCR `textRepresentation`
//! writing on regular saves, and image recompression/shrinking. Remote image
//! download and image-attachment orphan cleanup are implemented.

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

use crate::services::protected_session as session;

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
pub fn random_string(length: usize) -> String {
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

/// Whether the given note type/mime stores its content as a string (TEXT) rather
/// than binary bytes — `utils.isStringNote` for the note types this shell writes.
fn is_string_note(note_type: &str, mime: &str) -> bool {
    matches!(
        note_type,
        "text" | "code" | "render" | "relationMap" | "llmChat" | "spreadsheet" | "canvas" | "mindMap" | "contentWidget"
    ) || mime.starts_with("text/")
}

/// `getUnencryptedContentForHashCalculation` twin: a protected entity's blob id
/// is hashed over the `_ENCRYPTED_`-prefixed plaintext, so ciphertext never
/// shares a blob id with the same plaintext elsewhere.
pub fn blob_id_for(is_protected: bool, clear: &[u8]) -> String {
    if is_protected {
        let mut prefixed = Vec::with_capacity(clear.len() + crate::crypto::ENCRYPTED_PREFIX.len());
        prefixed.extend_from_slice(crate::crypto::ENCRYPTED_PREFIX.as_bytes());
        prefixed.extend_from_slice(clear);
        hashed_blob_id_bytes(&prefixed)
    } else {
        hashed_blob_id_bytes(clear)
    }
}

/// `Uint8Array.toString()` twin: join the bytes with commas, as the real server
/// feeds binary blob content into `calculateContentHash`.
fn comma_joined(bytes: &[u8]) -> String {
    bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
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
#[derive(Clone)]
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
/// Persists every editable field, not just the blob — the note-save path in
/// `update_note_data` only ever changes the blob, but the file/image routes write
/// `mime` and `isProtected` in the same row and rely on this to carry them.
fn save_note(conn: &Connection, note: &WriteNote) -> rusqlite::Result<()> {
    let local = local_now();
    let utc = utc_now();
    conn.execute(
        "UPDATE notes SET title = ?1, isProtected = ?2, type = ?3, mime = ?4, blobId = ?5, \
                dateModified = ?6, utcDateModified = ?7 WHERE noteId = ?8",
        params![
            note.title,
            i64::from(note.is_protected),
            note.note_type,
            note.mime,
            note.blob_id,
            local,
            utc,
            note.note_id,
        ],
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
/// For a protected note the content is encrypted and the title is encrypted too — both
/// exactly as the real `BAttachment` stores them.
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

    // Protected content is stored as the UTF-8 bytes of the base64 ciphertext;
    // the blob id is hashed over the `_ENCRYPTED_`-prefixed plaintext.
    let (blob_id, stored, hash_str): (String, Vec<u8>, String) = if is_protected {
        let encrypted = session::encrypt(content).ok_or(rusqlite::Error::InvalidQuery)?;
        let stored = encrypted.into_bytes();
        let hash_str = comma_joined(&stored);
        (blob_id_for(true, content), stored, hash_str)
    } else {
        let hash_str = comma_joined(content);
        (hashed_blob_id_bytes(content), content.to_vec(), hash_str)
    };
    insert_blob(conn, &blob_id, BlobContent::Bytes(&stored), &hash_str, local, utc)?;

    // Attachment titles are encrypted at rest while the attachment is protected.
    let stored_title = if is_protected {
        session::encrypt_string(title).ok_or(rusqlite::Error::InvalidQuery)?
    } else {
        title.to_string()
    };

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
        params![attachment_id, owner_id, role, mime, stored_title, protected, max_position + 10, blob_id, local, utc],
    )?;

    // Attachment hashed properties, in order: attachmentId, ownerId, role, mime, title,
    // blobId, utcDateScheduledForErasureSince. A fresh attachment has the last one unset,
    // which serializes as the literal `undefined`.
    let hash_input = format!("|{attachment_id}|{owner_id}|{role}|{mime}|{stored_title}|{blob_id}|undefined");
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
pub fn encode_uri_component(input: &str) -> String {
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
/// note under `role`, pointing at the same blob. Mirrors `BAttachment.copy()`, which keeps the
/// source attachment's protection state and title verbatim (so a copy from an unprotected note
/// stays plain even when the referencing note is protected).
fn copy_attachment(
    conn: &Connection,
    note_id: &str,
    role: &str,
    mime: &str,
    title: &str,
    blob_id: &str,
    is_protected: bool,
) -> rusqlite::Result<String> {
    let attachment_id = random_string(12);
    let local = local_now();
    let utc = utc_now();
    let max_position: i64 = conn.query_row(
        "SELECT COALESCE(MAX(position), 0) FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
        params![note_id],
        |row| row.get(0),
    )?;
    let protected: i64 = i64::from(is_protected);
    conn.execute(
        "INSERT INTO attachments \
         (attachmentId, ownerId, role, mime, title, isProtected, position, blobId, dateModified, \
          utcDateModified, utcDateScheduledForErasureSince, isDeleted, deleteId) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, 0, NULL)",
        params![attachment_id, note_id, role, mime, title, protected, max_position + 10, blob_id, local, utc],
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
        let foreign: Option<(String, String, String, Option<String>, String, bool)> = conn
            .query_row(
                "SELECT a.role, a.mime, a.title, a.blobId, a.ownerId, a.isProtected \
                 FROM attachments a JOIN notes n ON n.noteId = a.ownerId \
                 WHERE a.attachmentId = ?1 AND a.isDeleted = 0 AND n.isDeleted = 0",
                params![unknown_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get::<_, i64>(5)? != 0)),
            )
            .optional()?;
        let Some((foreign_role, foreign_mime, foreign_title, Some(foreign_blob), foreign_owner, foreign_protected)) = foreign else {
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
            copy_attachment(conn, note_id, &copied_role, &foreign_mime, &foreign_title, &foreign_blob, foreign_protected)?
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

    let rewritten = if note.note_type == "text" {
        // Localize images first (inline base64 + fetched remote), then lift inline `<a>` attachments;
        // both run before link scanning so the relations match the written form of the content.
        let with_images = rewrite_linked_images(conn, note, content, downloaded)?;
        save_attachments(conn, note, &with_images)?
    } else {
        content.to_string()
    };

    let mut found = collect_content_links(note, is_markdown, &rewritten);

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

/// The `internalLink` / `imageLink` / `includeNoteLink` relations a note's content names
/// (`scanForLinks` in the real server). Shared by the edit-save write and the post-conversion
/// parent rewrite — the latter runs it on content whose pictures are already localized, so the
/// image-download half of `save_links` is skipped there.
fn collect_content_links(note: &WriteNote, is_markdown: bool, content: &str) -> Vec<FoundLink> {
    let mut found: Vec<FoundLink> = Vec::new();

    if note.note_type == "text" {
        let image_api = Regex::new(r#"src="[^"]*api/images/([a-zA-Z0-9_]+)/"#).unwrap();
        for cap in image_api.captures_iter(content) {
            found.push(FoundLink { name: "imageLink", value: cap[1].to_string() });
        }
        let href_root = Regex::new(r#"href="[^"]*#root[a-zA-Z0-9_/]*/([a-zA-Z0-9_]+)/?""#).unwrap();
        for cap in href_root.captures_iter(content) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
        let include_note = Regex::new(r#"<section class="include-note[^>]+data-note-id="([a-zA-Z0-9_]+)"[^>]*>"#).unwrap();
        for cap in include_note.captures_iter(content) {
            found.push(FoundLink { name: "includeNoteLink", value: cap[1].to_string() });
        }
    } else if is_markdown {
        let image_api = Regex::new(r"api/images/([a-zA-Z0-9_]+)/").unwrap();
        for cap in image_api.captures_iter(content) {
            found.push(FoundLink { name: "imageLink", value: cap[1].to_string() });
        }
        let hash_root = Regex::new(r"#root[a-zA-Z0-9_/]*/([a-zA-Z0-9_]+)").unwrap();
        for cap in hash_root.captures_iter(content) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
        let wiki = Regex::new(r"\[\[([a-zA-Z0-9_]+)\]\]").unwrap();
        for cap in wiki.captures_iter(content) {
            found.push(FoundLink { name: "internalLink", value: cap[1].to_string() });
        }
    }

    found
}

/// Attribute entity hash over `attributeId|noteId|type|name|value|isInheritable`.
fn attribute_hash(attribute_id: &str, note_id: &str, attr_type: &str, name: &str, value: &str, is_inheritable: bool, is_deleted: bool) -> String {
    let inheritable = if is_inheritable { "true" } else { "false" };
    let mut input = format!("{attribute_id}|{note_id}|{attr_type}|{name}|{value}|{inheritable}");
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
    let hash = attribute_hash(&attribute_id, note_id, attr_type, name, value, false, false);
    put_entity_change(conn, "attributes", &attribute_id, &hash, &utc)
}

/// `markAsDeleted` for an attribute: soft-delete row + deleted entity change.
fn delete_attribute(conn: &Connection, attribute_id: &str, note_id: &str, attr_type: &str, name: &str, value: &str) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE attributes SET isDeleted = 1, deleteId = NULL, utcDateModified = ?1 WHERE attributeId = ?2",
        params![utc, attribute_id],
    )?;
    let hash = attribute_hash(attribute_id, note_id, attr_type, name, value, false, true);
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
    // Editing a protected note requires the decrypted session (saving would otherwise overwrite
    // the ciphertext with plaintext); `isContentAvailable` gates this in the real server too.
    if pre_note.is_protected && !session::is_available() {
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

        // Same protected gate, re-checked inside the transaction.
        if note.is_protected && !session::is_available() {
            return Err(rusqlite::Error::InvalidQuery); // mapped to 400 below
        }

        save_revision_if_needed(conn, &note)?;

        let mut note = note;
        // saveLinks rewrites the content (images localized, inline attachments extracted, orphaned
        // images scheduled, stale srcset dropped); the blob and link attributes are kept in
        // agreement with the written form.
        let new_content = save_links(conn, &note, content, &downloaded)?;

        // setContent: dedup blob, point the note at it, delete the old one if unused.
        // A protected note's blob holds the encrypted content (TEXT), and its blob id is hashed
        // over the `_ENCRYPTED_`-prefixed plaintext.
        let (new_blob_id, stored, hash_str): (String, String, String) = if note.is_protected {
            let encrypted = session::encrypt_string(&new_content).ok_or(rusqlite::Error::InvalidQuery)?;
            (blob_id_for(true, new_content.as_bytes()), encrypted.clone(), encrypted)
        } else {
            (hashed_blob_id(&new_content), new_content.clone(), new_content.clone())
        };
        let local = local_now();
        let utc = utc_now();
        insert_blob(conn, &new_blob_id, BlobContent::Text(&stored), &hash_str, &local, &utc)?;

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

// ---------------------------------------------------------------------------
// Protect / unprotect — `protectNote`, `protectNoteRecursively` and
// `revisionService.protectRevisions` in one transaction.
// ---------------------------------------------------------------------------

/// Flip `isProtected` over a note (and, with `subtree`, its whole descendant
/// tree through the branch table), re-encrypting or re-decrypting the note's
/// blob, every revision's blob and every attachment's blob — plus attachment and
/// revision titles, which are encrypted at rest like note titles. Requires an
/// active protected session; mirror of `noteService.protectNoteRecursively`.
pub fn protect_note(conn: &Connection, note_id: &str, protect: bool, subtree: bool) -> Result<(), WriteError> {
    if !session::is_available() {
        return Err(WriteError {
            status: 400,
            message: format!("Cannot (un)protect note '{}' without an active protected session", note_id),
        });
    }

    let mut ids = Vec::new();
    collect_note_and_descendants(conn, note_id, subtree, &mut ids).map_err(WriteError::from)?;

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        for id in ids {
            protect_one_note(conn, &id, protect)?;
        }
        Ok(())
    })();
    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

/// The note itself plus every descendant through non-deleted branches —
/// `protectNoteRecursively` walks `getChildNotes` the same way.
fn collect_note_and_descendants(conn: &Connection, note_id: &str, subtree: bool, out: &mut Vec<String>) -> rusqlite::Result<()> {
    if !subtree {
        out.push(note_id.to_string());
        return Ok(());
    }
    // `branches.noteId` is the child note id; the recursion deduplicates clones.
    let mut stmt = conn.prepare(
        "WITH RECURSIVE sub(noteId) AS ( \
           SELECT ?1 \
           UNION \
           SELECT b.noteId FROM branches b JOIN sub ON b.parentNoteId = sub.noteId AND b.isDeleted = 0 \
         ) \
         SELECT noteId FROM sub \
         WHERE EXISTS (SELECT 1 FROM notes n WHERE n.noteId = sub.noteId AND n.isDeleted = 0)",
    )?;
    for row in stmt.query_map(params![note_id], |row| row.get::<_, String>(0))? {
        out.push(row?);
    }
    Ok(())
}

/// Read a blob's stored bytes and, for a protected entity, decrypt them to the
/// plaintext. TEXT and BLOB storage both come back as bytes here — string notes hold
/// their content as TEXT, binary entities as BLOB. `pub` because the media-serving
/// command in `commands::api` reads attachment and image-note blobs the same way.
pub fn read_clear_bytes(conn: &Connection, blob_id: &str, was_protected: bool) -> rusqlite::Result<Vec<u8>> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT content FROM blobs WHERE blobId = ?1", params![blob_id], |row| {
            match row.get::<_, rusqlite::types::Value>(0)? {
                rusqlite::types::Value::Text(text) => Ok(text.into_bytes()),
                rusqlite::types::Value::Blob(bytes) => Ok(bytes),
                _ => Ok(Vec::new()),
            }
        })
        .optional()?;
    let Some(stored) = stored else {
        return Ok(Vec::new());
    };
    if !was_protected {
        return Ok(stored);
    }
    // Protected content is held as the UTF-8 bytes of the base64 ciphertext.
    let cipher_text = String::from_utf8_lossy(&stored).into_owned();
    Ok(session::decrypt_bytes(&cipher_text).unwrap_or_default())
}

/// Store entity content under the given protection: encrypt and prefix-hash when
/// protected, store verbatim otherwise. Returns the (possibly already-existing)
/// blob id.
fn store_entity_content(
    conn: &Connection,
    is_protected: bool,
    is_string: bool,
    clear: &[u8],
    local: &str,
    utc: &str,
) -> rusqlite::Result<String> {
    let blob_id = blob_id_for(is_protected, clear);
    let stored_bytes = if is_protected {
        let encrypted = session::encrypt(clear).ok_or(rusqlite::Error::InvalidQuery)?;
        encrypted.into_bytes()
    } else {
        clear.to_vec()
    };
    let text_form: Option<String> = is_string.then(|| String::from_utf8_lossy(&stored_bytes).into_owned());
    let hash_str = text_form.as_ref().map_or_else(|| comma_joined(&stored_bytes), Clone::clone);
    match text_form.as_deref() {
        Some(text) => insert_blob(conn, &blob_id, BlobContent::Text(text), &hash_str, local, utc)?,
        None => insert_blob(conn, &blob_id, BlobContent::Bytes(&stored_bytes), &hash_str, local, utc)?,
    };
    Ok(blob_id)
}

/// `readExtractedText` + `writeExtractedText` for the re-protect path: the OCR
/// text is read off the old blob under the old protection and stored on the new
/// blob under the new one. A blob that never held extracted text is untouched.
fn migrate_text_representation(
    conn: &Connection,
    old_blob: &str,
    new_blob: &str,
    was_protected: bool,
    now_protected: bool,
) -> rusqlite::Result<()> {
    let old_tr: Option<String> = conn
        .query_row("SELECT textRepresentation FROM blobs WHERE blobId = ?1", params![old_blob], |row| row.get(0))
        .optional()?;
    let Some(tr) = old_tr.filter(|t| !t.is_empty()) else {
        return Ok(());
    };
    let clear = if was_protected {
        if session::is_available() {
            session::decrypt_bytes(&tr)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        tr
    };
    if clear.is_empty() {
        return Ok(());
    }
    let stored = if now_protected {
        session::encrypt_string(&clear).ok_or(rusqlite::Error::InvalidQuery)?
    } else {
        clear
    };
    conn.execute("UPDATE blobs SET textRepresentation = ?1 WHERE blobId = ?2", params![stored, new_blob])?;
    Ok(())
}

/// Flip protection on a single note: its row/blob, then its revisions, then its
/// attachments — each entity written with its own (post-flip) entity change.
fn protect_one_note(conn: &Connection, note_id: &str, protect: bool) -> rusqlite::Result<()> {
    let Some(note) = load_note(conn, note_id)? else {
        return Ok(()); // already erased — nothing to flip
    };

    // --- the note's own content ---
    if note.is_protected != protect {
        let mut updated = note.clone();
        updated.is_protected = protect;
        if let Some(old_blob) = updated.blob_id.take() {
            let is_string = is_string_note(&updated.note_type, &updated.mime);
            let content = read_clear_bytes(conn, &old_blob, note.is_protected)?;
            let local = local_now();
            let utc = utc_now();
            let new_blob = store_entity_content(conn, protect, is_string, &content, &local, &utc)?;
            migrate_text_representation(conn, &old_blob, &new_blob, note.is_protected, protect)?;
            updated.blob_id = Some(new_blob.clone());
            conn.execute(
                "UPDATE notes SET isProtected = ?1, blobId = ?2, dateModified = ?3, utcDateModified = ?4 WHERE noteId = ?5",
                params![i64::from(protect), new_blob, local, utc, note.note_id],
            )?;
            delete_blob_if_not_used(conn, &old_blob)?;
        } else {
            conn.execute(
                "UPDATE notes SET isProtected = ?1 WHERE noteId = ?2",
                params![i64::from(protect), note.note_id],
            )?;
        }
        put_entity_change(conn, "notes", &note.note_id, &note_hash(&updated, false), &utc_now())?;
    }

    // --- revisions: `revisionService.protectRevisions` ---
    {
        let mut stmt = conn.prepare(
            "SELECT revisionId, noteId, title, type, mime, isProtected, COALESCE(blobId, ''), \
                    dateLastEdited, dateCreated, utcDateLastEdited, utcDateCreated, utcDateModified \
             FROM revisions WHERE noteId = ?1",
        )?;
        let revisions: Vec<(String, String, String, String, String, i64, String, String, String, String, String, String)> = stmt
            .query_map(params![note_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (revision_id, rev_note_id, title, rev_type, rev_mime, rev_protected_raw, rev_blob, date_last_edited, date_created, utc_date_last_edited, utc_date_created, utc_date_modified) in revisions {
            let rev_protected = rev_protected_raw != 0;
            if rev_protected == protect || rev_blob.is_empty() {
                continue;
            }
            let content = read_clear_bytes(conn, &rev_blob, rev_protected)?;
            let is_string = is_string_note(&rev_type, &rev_mime);
            let local = local_now();
            let utc = utc_now();
            let new_blob = store_entity_content(conn, protect, is_string, &content, &local, &utc)?;
            migrate_text_representation(conn, &rev_blob, &new_blob, rev_protected, protect)?;
            conn.execute(
                "UPDATE revisions SET isProtected = ?1, blobId = ?2, dateLastEdited = ?3, utcDateModified = ?4 WHERE revisionId = ?5",
                params![i64::from(protect), new_blob, local, utc, revision_id],
            )?;
            // Revision hashed properties, in create_revision order.
            let protected = if protect { "true" } else { "false" };
            let hash_input = format!(
                "{revision_id}|{rev_note_id}|{title}||auto|{protected}|{date_last_edited}|{date_created}|{utc_date_last_edited}|{utc_date_created}|{utc_date_modified}|{new_blob}"
            );
            put_entity_change(conn, "revisions", &revision_id, &hash10(&hash_input), &utc)?;
            delete_blob_if_not_used(conn, &rev_blob)?;
        }
    }

    // --- attachments ---
    {
        let mut stmt = conn.prepare(
            "SELECT attachmentId, role, mime, title, isProtected, COALESCE(blobId, '') \
             FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
        )?;
        let attachments: Vec<(String, String, String, String, i64, String)> = stmt
            .query_map(params![note_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (attachment_id, role, mime, title, att_protected_raw, att_blob) in attachments {
            let att_protected = att_protected_raw != 0;
            if att_protected == protect || att_blob.is_empty() {
                continue;
            }
            let content = read_clear_bytes(conn, &att_blob, att_protected)?;
            let local = local_now();
            let utc = utc_now();
            let new_blob = store_entity_content(conn, protect, false, &content, &local, &utc)?;
            migrate_text_representation(conn, &att_blob, &new_blob, att_protected, protect)?;
            // Attachment titles are encrypted at rest, so flip them together.
            let stored_title = if protect {
                session::encrypt_string(&title).ok_or(rusqlite::Error::InvalidQuery)?
            } else if att_protected {
                session::decrypt_bytes(&title)
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or(title)
            } else {
                title.clone()
            };
            conn.execute(
                "UPDATE attachments SET isProtected = ?1, blobId = ?2, title = ?3, dateModified = ?4, \
                        utcDateModified = ?5 WHERE attachmentId = ?6",
                params![i64::from(protect), new_blob, stored_title, local, utc, attachment_id],
            )?;
            let scheduled: Option<String> = conn
                .query_row(
                    "SELECT utcDateScheduledForErasureSince FROM attachments WHERE attachmentId = ?1",
                    params![attachment_id],
                    |row| row.get(0),
                )
                .optional()?;
            let scheduled_hash = scheduled.unwrap_or_else(|| "undefined".to_string());
            let hash_input = format!("|{attachment_id}|{note_id}|{role}|{mime}|{stored_title}|{new_blob}|{scheduled_hash}");
            put_entity_change(conn, "attachments", &attachment_id, &hash10(&hash_input), &utc)?;
            delete_blob_if_not_used(conn, &att_blob)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Attachment CRUD — `saveAttachment`, `renameAttachment`, `deleteAttachment` and
// the `markAsDeleted` side of the attachments panel.
// ---------------------------------------------------------------------------

/// The `attachments` entity hash, over `attachmentId|ownerId|role|mime|title|blobId|
/// utcDateScheduledForErasureSince` (`undefined` when unset), `+deleted` suffix for
/// the soft-delete state.
fn attachment_hash_value(
    attachment_id: &str,
    owner_id: &str,
    role: &str,
    mime: &str,
    title: &str,
    blob_id: &str,
    scheduled: Option<&str>,
    is_deleted: bool,
) -> String {
    let scheduled = scheduled.unwrap_or("undefined");
    let mut input = format!("|{attachment_id}|{owner_id}|{role}|{mime}|{title}|{blob_id}|{scheduled}");
    if is_deleted {
        input.push_str("|deleted");
    }
    hash10(&input)
}

/// `note.saveAttachment`: find an existing attachment (by its id, or by title
/// within the note with `matchBy=title`), otherwise create one owned by the note
/// with the note's protection. Matched attachments only re-store their content
/// (metadata stays as stored); the write is force-saved, so the row is always
/// re-stamped and recorded even when the blob id is unchanged.
pub fn save_attachment_route(
    conn: &Connection,
    note_id: &str,
    attachment_id: Option<&str>,
    role: &str,
    mime: &str,
    title: &str,
    content: Option<Vec<u8>>,
    match_by: Option<&str>,
) -> Result<String, WriteError> {
    let note = load_note(conn, note_id)
        .map_err(WriteError::from)?
        .ok_or_else(|| WriteError::not_found(note_id))?;

    let existing: Option<(String, String, String, String, bool, String)> = if match_by == Some("title") && !title.is_empty() {
        conn.query_row(
            "SELECT attachmentId, role, mime, title, isProtected, COALESCE(blobId, '') FROM attachments \
             WHERE ownerId = ?1 AND title = ?2 AND isDeleted = 0 LIMIT 1",
            params![note_id, title],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    } else if let Some(id) = attachment_id {
        conn.query_row(
            "SELECT attachmentId, role, mime, title, isProtected, COALESCE(blobId, '') FROM attachments \
             WHERE attachmentId = ?1 AND isDeleted = 0",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    } else {
        None
    };

    // `content = content || ""`, like the real service: an absent payload still
    // force-writes an (empty) blob.
    let content = content.unwrap_or_default();

    if let Some((id, _role, _mime, _title, is_protected, old_blob)) = existing {
        if old_blob.is_empty() {
            return Err(WriteError {
                status: 404,
                message: format!("Attachment '{}' has no blob", id),
            });
        }
        let local = local_now();
        let utc = utc_now();
        let (new_blob, _hash_str) = store_attachment_blob(conn, is_protected, &content, &local, &utc)?;
        conn.execute(
            "UPDATE attachments SET blobId = ?1, dateModified = ?2, utcDateModified = ?3 WHERE attachmentId = ?4",
            params![new_blob, local, utc, id],
        )?;
        let owner_id: String = conn.query_row("SELECT ownerId FROM attachments WHERE attachmentId = ?1", params![id], |row| row.get(0))?;
        // Re-stat with the stored title/role/mime so the hash matches the row.
        let (role, mime, title, scheduled): (String, String, String, Option<String>) = conn.query_row(
            "SELECT role, mime, title, utcDateScheduledForErasureSince FROM attachments WHERE attachmentId = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        put_entity_change(
            conn,
            "attachments",
            &id,
            &attachment_hash_value(&id, &owner_id, &role, &mime, &title, &new_blob, scheduled.as_deref(), false),
            &utc,
        )?;
        if new_blob != old_blob {
            delete_blob_if_not_used(conn, &old_blob)?;
        }
        Ok(id)
    } else {
        let local = local_now();
        let utc = utc_now();
        save_attachment(conn, note_id, role, mime, title, note.is_protected, &content, &local, &utc)
            .map_err(WriteError::from)
    }
}

/// Store one attachment's content as a blob (encrypted when protected) and
/// return its id plus the content string/bytes the entity change hash needs.
fn store_attachment_blob(
    conn: &Connection,
    is_protected: bool,
    content: &[u8],
    local: &str,
    utc: &str,
) -> rusqlite::Result<(String, String)> {
    if is_protected {
        let encrypted = session::encrypt(content).ok_or(rusqlite::Error::InvalidQuery)?;
        let stored = encrypted.into_bytes();
        let hash_str = comma_joined(&stored);
        let blob_id = blob_id_for(true, content);
        insert_blob(conn, &blob_id, BlobContent::Bytes(&stored), &hash_str, local, utc)?;
        Ok((blob_id, hash_str))
    } else {
        let hash_str = comma_joined(content);
        let blob_id = hashed_blob_id_bytes(content);
        insert_blob(conn, &blob_id, BlobContent::Bytes(content), &hash_str, local, utc)?;
        Ok((blob_id, hash_str))
    }
}

/// `renameAttachment`: non-empty title, encrypted at rest for protected
/// attachments; the attachment row and its entity change follow.
pub fn rename_attachment(conn: &Connection, attachment_id: &str, title: &str) -> Result<(), WriteError> {
    if title.trim().is_empty() {
        return Err(WriteError {
            status: 400,
            message: "Title must not be empty".to_string(),
        });
    }
    let Some((owner_id, role, mime, is_protected, blob_id, scheduled)) = conn
        .query_row(
            "SELECT ownerId, role, mime, isProtected, COALESCE(blobId, ''), utcDateScheduledForErasureSince \
             FROM attachments WHERE attachmentId = ?1 AND isDeleted = 0",
            params![attachment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    else {
        return Err(WriteError::not_found(attachment_id));
    };

    let stored_title = if is_protected {
        session::encrypt_string(title).ok_or(rusqlite::Error::InvalidQuery).map_err(WriteError::from)?
    } else {
        title.to_string()
    };
    let local = local_now();
    let utc = utc_now();
    conn.execute(
        "UPDATE attachments SET title = ?1, dateModified = ?2, utcDateModified = ?3 WHERE attachmentId = ?4",
        params![stored_title, local, utc, attachment_id],
    )?;
    put_entity_change(
        conn,
        "attachments",
        attachment_id,
        &attachment_hash_value(attachment_id, &owner_id, &role, &mime, &stored_title, &blob_id, scheduled.as_deref(), false),
        &utc,
    )?;
    Ok(())
}

/// `deleteAttachment` — `BAttachment.markAsDeleted()`: soft-delete the row,
/// stamp it and record the deleted entity change. A missing attachment is a
/// silent no-op, like `becca.getAttachment` returning null in the real route.
pub fn delete_attachment(conn: &Connection, attachment_id: &str) -> Result<(), WriteError> {
    let Some((owner_id, role, mime, title, blob_id, scheduled)) = conn
        .query_row(
            "SELECT ownerId, role, mime, title, COALESCE(blobId, ''), utcDateScheduledForErasureSince \
             FROM attachments WHERE attachmentId = ?1 AND isDeleted = 0",
            params![attachment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    else {
        return Ok(());
    };

    let utc = utc_now();
    conn.execute(
        "UPDATE attachments SET isDeleted = 1, deleteId = NULL, utcDateModified = ?1 WHERE attachmentId = ?2",
        params![utc, attachment_id],
    )?;
    put_entity_change(
        conn,
        "attachments",
        attachment_id,
        &attachment_hash_value(attachment_id, &owner_id, &role, &mime, &title, &blob_id, scheduled.as_deref(), true),
        &utc,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Multipart uploads and convert-to-note — the `server.upload` twins and
// `BAttachment.convertToNote` (attachment → note).
// ---------------------------------------------------------------------------

/// Whether the given MIME type is handled as a picture by the upload endpoints —
/// `isAcceptedImageMime` over the shared list in `commons` `image_mimes.ts`.
fn is_accepted_image_mime(mime: &str) -> bool {
    matches!(
        mime,
        "image/png"
            | "image/jpg"
            | "image/jpeg"
            | "image/gif"
            | "image/bmp"
            | "image/webp"
            | "image/avif"
            | "image/svg"
            | "image/svg+xml"
            | "image/x-icon"
            | "image/vnd.microsoft.icon"
    )
}

/// How an uploaded file was stored by `POST /notes/{id}/attachments/upload`; the
/// URL the route answers with differs by branch, mirroring `uploadAttachment`.
pub enum UploadedAttachment {
    /// Stored as an `image`-role attachment; addressed as `api/attachments/{id}/image/{title}`.
    Image { attachment_id: String, title: String },
    /// Stored as a `file`-role attachment; addressed as a reference link to the attachments panel.
    File { attachment_id: String },
}

/// `POST /notes/{id}/attachments/upload` — `attachmentsApiRoute.uploadAttachment`.
/// A picture becomes an `image`-role attachment and answers with its serving URL; anything else
/// becomes a `file` attachment and answers with the attachments-panel reference instead.
pub fn save_uploaded_attachment(
    conn: &Connection,
    note_id: &str,
    original_name: &str,
    mime: &str,
    content: &[u8],
) -> Result<UploadedAttachment, WriteError> {
    let note = load_note(conn, note_id)
        .map_err(WriteError::from)?
        .ok_or_else(|| WriteError::not_found(note_id))?;
    if note.is_protected && !session::is_available() {
        return Err(WriteError::unavailable(note_id));
    }

    let local = local_now();
    let utc = utc_now();
    if is_accepted_image_mime(mime) {
        let (attachment_id, title) = save_image_attachment(conn, &note, original_name, content, &local, &utc)
            .map_err(WriteError::from)?;
        Ok(UploadedAttachment::Image { attachment_id, title })
    } else {
        let attachment_id = save_attachment(conn, note_id, "file", original_name, mime, note.is_protected, content, &local, &utc)
            .map_err(WriteError::from)?;
        Ok(UploadedAttachment::File { attachment_id })
    }
}

/// Store an uploaded file as a note's content and point the note at it. The whole
/// `setContent` tail of `updateNoteData`: dedup blob, swap the note's blob id, delete
/// the old blob if unused — with the note's mime already updated by the caller.
fn store_note_content(conn: &Connection, note: &mut WriteNote, content: &[u8], is_string: bool) -> rusqlite::Result<()> {
    let local = local_now();
    let utc = utc_now();
    let new_blob = store_entity_content(conn, note.is_protected, is_string, content, &local, &utc)?;
    if note.blob_id.as_deref() != Some(new_blob.as_str()) {
        let old_blob = note.blob_id.take();
        note.blob_id = Some(new_blob);
        save_note(conn, note)?;
        if let Some(old) = old_blob {
            delete_blob_if_not_used(conn, &old)?;
        }
    }
    Ok(())
}

/// `asyncPostProcessContent` (`scanForLinks`) for the routes that replace a note's content
/// without sending it through `update_note_data`: keep the link relations, bookmark labels and
/// image-attachment erasure schedules in agreement with the new content. Unlike `save_links`,
/// pictures are not localized or downloaded — they were already in the content.
fn post_process_links(conn: &Connection, note: &WriteNote, content: &str) -> rusqlite::Result<()> {
    let is_markdown = note.note_type == "code"
        && matches!(note.mime.as_str(), "text/markdown" | "text/x-markdown" | "text/x-gfm");
    if note.note_type != "text" && !is_markdown {
        return Ok(());
    }
    let found = collect_content_links(note, is_markdown, content);
    sync_relations(conn, &note.note_id, &found)?;
    sync_bookmarks(conn, &note.note_id, content)?;
    check_image_attachments(conn, &note.note_id, is_markdown, content)?;
    Ok(())
}

/// `PUT /notes/{id}/file` — `filesRoute.updateFile`: write an uploaded file over a note's
/// content. `replace=1` skips the revision snapshot (an editor saving its own work); otherwise a
/// revision is taken first, exactly like `note.saveRevision()`.
pub fn update_file_note(conn: &Connection, note_id: &str, original_name: &str, mime: &str, content: &[u8], replace: bool) -> Result<(), WriteError> {
    if let Some(note) = load_note(conn, note_id).map_err(WriteError::from)? {
        if note.is_protected && !session::is_available() {
            return Err(WriteError::unavailable(note_id));
        }
    } else {
        return Err(WriteError::not_found(note_id));
    }

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        // Re-load inside the transaction so the snapshot reflects the row we hold the lock on.
        let mut note = load_note(conn, note_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        if note.is_protected && !session::is_available() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if !replace {
            create_revision(conn, &note)?;
        }
        note.mime = mime.to_lowercase();
        let is_string = is_string_note(&note.note_type, &note.mime);
        store_note_content(conn, &mut note, content, is_string)?;
        set_note_label(conn, note_id, "originalFileName", original_name)?;
        Ok(())
    })();
    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            // Run outside the transaction like `void asyncPostProcessContent` in the real route.
            if let Ok(saved) = load_note(conn, note_id) {
                if let Some(saved) = saved {
                    let text = String::from_utf8_lossy(content).into_owned();
                    let _ = post_process_links(conn, &saved, &text);
                }
            }
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

/// `PUT /attachments/{id}/file` — `filesRoute.updateAttachment`: overwrite an attachment's
/// file, snapshotting the owning note first (`attachment.getNote().saveRevision()`).
pub fn update_file_attachment(conn: &Connection, attachment_id: &str, mime: &str, content: &[u8]) -> Result<(), WriteError> {
    let Some((owner_id, role, title, is_protected, old_blob, scheduled)) = conn
        .query_row(
            "SELECT ownerId, role, title, isProtected, COALESCE(blobId, ''), utcDateScheduledForErasureSince \
             FROM attachments WHERE attachmentId = ?1 AND isDeleted = 0",
            params![attachment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    else {
        return Err(WriteError {
            status: 404,
            message: format!("Attachment '{}' not found", attachment_id),
        });
    };

    let owner = load_note(conn, &owner_id)
        .map_err(WriteError::from)?
        .ok_or_else(|| WriteError::not_found(&owner_id))?;
    if (owner.is_protected || is_protected) && !session::is_available() {
        return Err(WriteError::unavailable(&owner_id));
    }

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        let owner = load_note(conn, &owner_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        create_revision(conn, &owner)?;

        let local = local_now();
        let utc = utc_now();
        let new_blob = store_attachment_blob(conn, is_protected, content, &local, &utc)?.0;
        conn.execute(
            "UPDATE attachments SET mime = ?1, blobId = ?2, dateModified = ?3, utcDateModified = ?4 WHERE attachmentId = ?5",
            params![mime.to_lowercase(), new_blob, local, utc, attachment_id],
        )?;
        put_entity_change(
            conn,
            "attachments",
            attachment_id,
            &attachment_hash_value(attachment_id, &owner_id, &role, &mime.to_lowercase(), &title, &new_blob, scheduled.as_deref(), false),
            &utc,
        )?;
        if new_blob != old_blob {
            delete_blob_if_not_used(conn, &old_blob)?;
        }
        Ok(())
    })();
    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            match err {
                rusqlite::Error::QueryReturnedNoRows => Err(WriteError::not_found(&owner_id)),
                rusqlite::Error::InvalidQuery => Err(WriteError::unavailable(&owner_id)),
                other => Err(WriteError::from(other)),
            }
        }
    }
}

/// `PUT /images/{noteId}` — `imageRoute.updateImage`: replace an image note's content,
/// snapshotting it first and detecting the format from the byte soup (the real route
/// re-compresses; this shell stores the bytes as given).
pub fn update_image_note(conn: &Connection, note_id: &str, original_name: &str, content: &[u8]) -> Result<(), WriteError> {
    if let Some(note) = load_note(conn, note_id).map_err(WriteError::from)? {
        if note.is_protected && !session::is_available() {
            return Err(WriteError::unavailable(note_id));
        }
    } else {
        return Err(WriteError::not_found(note_id));
    }

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        let mut note = load_note(conn, note_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        if note.is_protected && !session::is_available() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        create_revision(conn, &note)?;
        let mime = inspect_image(content).map_or("unknown", |d| d.mime).to_string();
        note.mime = mime;
        let is_string = is_string_note(&note.note_type, &note.mime);
        store_note_content(conn, &mut note, content, is_string)?;
        set_note_label(conn, note_id, "originalFileName", original_name)?;
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

/// The note + branch a note creation produced, as the `convert-to-note` response needs them.
pub struct NewNote {
    pub note_id: String,
    pub branch_id: String,
}

/// `getNewNotePosition` + `BBranch.beforeSaving`: one step below the deepest child,
/// skipping the `_hidden` pseudo-note that pins itself to the end of the list.
fn note_position_for(conn: &Connection, parent_note_id: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(MAX(notePosition), 0) + 10 FROM branches \
         WHERE parentNoteId = ?1 AND isDeleted = 0 AND noteId != '_hidden'",
        params![parent_note_id],
        |row| row.get(0),
    )
}

/// `BNote.setLabel`: keep a single `label`-type attribute of the given name — update the
/// existing non-deleted one, insert when absent. Used for `originalFileName` on the
/// file/image replace routes.
fn set_note_label(conn: &Connection, note_id: &str, name: &str, value: &str) -> rusqlite::Result<()> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT attributeId FROM attributes WHERE noteId = ?1 AND type = 'label' AND name = ?2 AND isDeleted = 0 LIMIT 1",
            params![note_id, name],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(attribute_id) = existing {
        let utc = utc_now();
        conn.execute(
            "UPDATE attributes SET value = ?1, utcDateModified = ?2 WHERE attributeId = ?3",
            params![value, utc, attribute_id],
        )?;
        let hash = attribute_hash(&attribute_id, note_id, "label", name, value, false, false);
        put_entity_change(conn, "attributes", &attribute_id, &hash, &utc)?;
    } else {
        insert_attribute(conn, note_id, "label", name, value)?;
    }
    Ok(())
}

/// `copyChildAttributes`: the parent's `child:`-prefixed attributes are copied onto a
/// newly created child with the prefix stripped (so `child:template` on the parent seeds a
/// `~template` on the child). A `child:template` relation whose target is a note of a
/// different type is skipped — the explicitly chosen type wins over the default template.
fn copy_child_attributes(conn: &Connection, parent_note_id: &str, child_note_id: &str) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "SELECT type, name, value, position, isInheritable FROM attributes \
         WHERE noteId = ?1 AND name LIKE 'child:%' AND isDeleted = 0",
    )?;
    let rows: Vec<(String, String, String, i64, i64)> = stmt
        .query_map(params![parent_note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (attr_type, name, value, position, is_inheritable) in rows {
        let stripped = name.strip_prefix("child:").unwrap_or(&name).to_string();
        if attr_type == "relation" && stripped == "template" {
            // A template the user chose explicitly at creation (an owned `~template`
            // relation, added before this runs) suppresses the parent's `child:template`
            // default; only the default path applies the type-match filter below.
            let owned_template: bool = conn
                .query_row(
                    "SELECT 1 FROM attributes WHERE noteId = ?1 AND type = 'relation' AND name = 'template' AND isDeleted = 0 LIMIT 1",
                    params![child_note_id],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0)
                == 1;
            if owned_template {
                continue;
            }
            let template_type: Option<String> = conn
                .query_row("SELECT type FROM notes WHERE noteId = ?1 AND isDeleted = 0", params![value], |row| row.get(0))
                .optional()?;
            let child_type: String = conn.query_row("SELECT type FROM notes WHERE noteId = ?1", params![child_note_id], |row| row.get(0))?;
            if let Some(template_type) = template_type {
                if template_type != child_type {
                    continue;
                }
            }
        }
        let attribute_id = random_string(12);
        let utc = utc_now();
        conn.execute(
            "INSERT INTO attributes (attributeId, noteId, type, name, value, position, utcDateModified, isDeleted, deleteId, isInheritable) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, ?8)",
            params![attribute_id, child_note_id, attr_type, stripped, value, position, utc, is_inheritable],
        )?;
        let hash = attribute_hash(&attribute_id, child_note_id, &attr_type, &stripped, &value, is_inheritable != 0, false);
        put_entity_change(conn, "attributes", &attribute_id, &hash, &utc)?;
    }
    Ok(())
}

/// `noteService.createNewNote` for this shell: a note under a parent with content stored
/// according to its type, a branch, and `child:`-prefixed attributes copied from the parent.
/// Requires the caller to hold a transaction. Returns the new note's ids.
pub fn create_new_note(
    conn: &Connection,
    parent_note_id: &str,
    title: &str,
    note_type: &str,
    mime: &str,
    is_protected: bool,
    content: &[u8],
) -> rusqlite::Result<NewNote> {
    let created = create_note_entity(conn, parent_note_id, title, note_type, mime, is_protected, content, None, None, false, None)?;
    copy_child_attributes(conn, parent_note_id, &created.note_id)?;
    Ok(created)
}

/// The low-level create used by both `create_new_note` (convert-to-note) and the public
/// create route: notes row + blob + branch, each with its entity change, honoring the
/// optional overrides the route passes through (`notePosition`, forced `noteId`,
/// `isExpanded`, `prefix`). `copy_child_attributes` is the caller's job so a template
/// relation can be recorded before the `child:` attributes are copied.
#[allow(clippy::too_many_arguments)]
fn create_note_entity(
    conn: &Connection,
    parent_note_id: &str,
    title: &str,
    note_type: &str,
    mime: &str,
    is_protected: bool,
    content: &[u8],
    note_position: Option<i64>,
    note_id: Option<&str>,
    is_expanded: bool,
    prefix: Option<&str>,
) -> rusqlite::Result<NewNote> {
    let note_id = note_id.map(str::to_string).unwrap_or_else(|| random_string(12));
    let branch_id = format!("{parent_note_id}_{note_id}");
    let local = local_now();
    let utc = utc_now();

    // Note titles are encrypted at rest while the note is protected, like every other write.
    let stored_title = if is_protected {
        session::encrypt_string(title).ok_or(rusqlite::Error::InvalidQuery)?
    } else {
        title.to_string()
    };
    let is_string = is_string_note(note_type, mime);
    let blob_id = store_entity_content(conn, is_protected, is_string, content, &local, &utc)?;
    let note_position = note_position.unwrap_or(note_position_for(conn, parent_note_id)?);

    conn.execute(
        "INSERT INTO notes (noteId, title, isProtected, type, mime, blobId, isDeleted, deleteId, \
                dateCreated, dateModified, utcDateCreated, utcDateModified) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, ?7, ?8, ?9, ?10)",
        params![
            note_id,
            stored_title,
            i64::from(is_protected),
            note_type,
            mime,
            blob_id,
            local,
            local,
            utc,
            utc,
        ],
    )?;
    let note = WriteNote {
        note_id: note_id.clone(),
        title: stored_title,
        note_type: note_type.to_string(),
        mime: mime.to_string(),
        is_protected,
        blob_id: Some(blob_id),
        date_modified: local,
        utc_date_created: utc.clone(),
        utc_date_modified: utc.clone(),
    };
    put_entity_change(conn, "notes", &note.note_id, &note_hash(&note, false), &utc)?;

    conn.execute(
        "INSERT INTO branches (branchId, noteId, parentNoteId, notePosition, prefix, isExpanded, isDeleted, deleteId, utcDateModified) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, ?7)",
        params![branch_id, note_id, parent_note_id, note_position, prefix.unwrap_or(""), i64::from(is_expanded), utc],
    )?;
    let branch_input = format!("|{branch_id}|{note_id}|{parent_note_id}|{}", prefix.unwrap_or(""));
    put_entity_change(conn, "branches", &branch_id, &hash10(&branch_input), &utc)?;

    Ok(NewNote { note_id, branch_id })
}

/// `BAttachment.convertToNote`: lift the attachment into a note of its own under the
/// parent (image/favicon → image note, file → file note), re-point the parent's text content
/// at the new note, and soft-delete the attachment. Requires the transaction to be held open
/// by the caller. Returns the created note ids.
pub fn convert_attachment_to_note(conn: &Connection, attachment_id: &str) -> Result<NewNote, WriteError> {
    let Some((owner_id, role, mime, title, is_protected, blob_id)) = conn
        .query_row(
            "SELECT ownerId, role, mime, title, isProtected, COALESCE(blobId, '') \
             FROM attachments WHERE attachmentId = ?1 AND isDeleted = 0",
            params![attachment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(WriteError::from)?
    else {
        return Err(WriteError {
            status: 404,
            message: format!("Attachment '{}' not found", attachment_id),
        });
    };

    let note_type = match role.as_str() {
        "image" | "favicon" => "image",
        "file" => "file",
        other => {
            return Err(WriteError {
                status: 400,
                message: format!("Mapping from attachment role '{other}' to note's type is not defined"),
            });
        }
    };

    // `isContentAvailable`: a protected attachment is only convertible while the session is open.
    if is_protected && !session::is_available() {
        return Err(WriteError {
            status: 400,
            message: format!("Cannot convert protected attachment '{}' outside of protected session", attachment_id),
        });
    }

    let parent = load_note(conn, &owner_id)
        .map_err(WriteError::from)?
        .ok_or_else(|| WriteError::not_found(&owner_id))?;
    if parent.is_protected && !session::is_available() {
        return Err(WriteError::unavailable(&owner_id));
    }

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<NewNote> {
        let clear = read_clear_bytes(conn, &blob_id, is_protected)?;
        let created = create_new_note(conn, &owner_id, &title, note_type, &mime, is_protected, &clear)?;

        delete_attachment(conn, attachment_id).map_err(|err| {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(err.message))
        })?;

        // A text parent gets its content re-pointed at the converted note: embedded image URLs
        // (`api/attachments/{id}/image/...`) become `api/images/{noteId}/...` and reference links
        // to the attachment collapse to a plain note link (the `&` may be HTML-encoded as `&amp;`).
        let parent_note = load_note(conn, &owner_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        if parent_note.note_type == "text" {
            let orig_bytes = read_clear_bytes(conn, &parent_note.blob_id.clone().unwrap_or_default(), parent_note.is_protected)?;
            let orig = String::from_utf8_lossy(&orig_bytes).into_owned();
            let mut fixed = orig.clone();
            if note_type == "image" {
                let old_url = format!("api/attachments/{attachment_id}/image/");
                let new_url = format!("api/images/{}/", created.note_id);
                fixed = fixed.replace(&old_url, &new_url);
            }
            let href_re = Regex::new(&format!(r#"href="[^"]*attachmentId={attachment_id}[^"]*""#)).unwrap();
            fixed = href_re
                .replace_all(&fixed, format!(r##"href="#root/{}""##, created.note_id))
                .into_owned();

            // Re-scan the parent (not the new image/file note, which has no scannable links) so its
            // link relations and orphaned-image schedules reflect the rewritten content.
            post_process_links(conn, &parent_note, &fixed)?;

            if fixed != orig {
                let mut parent_note = parent_note;
                store_note_content(conn, &mut parent_note, fixed.as_bytes(), true)?;
            }
        }
        Ok(created)
    })();
    match run {
        Ok(created) => {
            conn.execute_batch("COMMIT")?;
            Ok(created)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::not_found(&owner_id))
        }
        Err(rusqlite::Error::InvalidQuery) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::unavailable(&owner_id))
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

// ---------------------------------------------------------------------------
// Note lifecycle writes — the `notes` create / rename / delete / undelete routes.
// Mirrors `noteService.createNewNote[WithTarget]` and `changeTitle`, `BNote.deleteNote`
// (+ `BBranch.deleteBranch` cascade) and the undelete walk in `services/notes.ts`.
// ---------------------------------------------------------------------------

/// One attribute to be set on a newly created note, atomically with the note itself
/// (`NoteParams.attributes`); `attr_type` is `label` or `relation`.
pub struct CreateAttribute {
    pub attr_type: String,
    pub name: String,
    pub value: String,
    pub is_inheritable: bool,
}

/// `NoteParams` of the public create route. Every `Option` falls back to the same
/// default `noteService.createNewNote` applies: the title to the app default, the
/// type/mime derived from the parent and the per-type default-mime table, the position
/// after the deepest sibling.
pub struct NoteCreateParams {
    pub parent_note_id: String,
    pub title: Option<String>,
    pub note_type: Option<String>,
    pub mime: Option<String>,
    pub content: String,
    pub is_protected: bool,
    pub is_expanded: bool,
    pub prefix: Option<String>,
    pub note_position: Option<i64>,
    pub note_id: Option<String>,
    pub template_note_id: Option<String>,
    pub attributes: Vec<CreateAttribute>,
    pub ignore_forbidden_parents: bool,
}

/// `deriveMime`: the default MIME per note type when none was given.
fn default_mime_for(note_type: &str) -> String {
    match note_type {
        "text" => "text/html",
        "code" => "text/plain",
        "file" => "application/octet-stream",
        "relationMap" | "canvas" | "mindMap" | "spreadsheet" | "llmChat" => "application/json",
        "mermaid" => "text/vnd.mermaid",
        // render/image/search/book/noteMap/webView/launcher/doc/contentWidget have no default
        _ => "",
    }
    .to_string()
}

/// `getAndValidateParent`: the parent must exist, not be a launcher (other than the
/// bookmarks bar) and — unless `ignoreForbiddenParents` — not be a structural root.
fn validate_parent_for_child(parent: &WriteNote, ignore_forbidden: bool) -> Result<(), WriteError> {
    if parent.note_type == "launcher" && parent.note_id != "_lbBookmarks" {
        return Err(WriteError {
            status: 400,
            message: "Creating child notes into launcher notes is not allowed.".to_string(),
        });
    }
    if ignore_forbidden {
        return Ok(());
    }
    let forbidden = parent.note_id == "_lbRoot"
        || parent.note_id == "_hidden"
        || parent.note_id.starts_with("_lbTpl")
        || parent.note_id.starts_with("_help")
        || parent.note_id.starts_with("_options"); // isOptions()
    if forbidden {
        return Err(WriteError {
            status: 400,
            message: format!("Creating child notes into '{}' is not allowed.", parent.note_id),
        });
    }
    Ok(())
}

/// Where the new branch lands: at the tail (`into`), or right after/before a sibling
/// branch (`after`/`before`), which also shifts the sibling positions.
enum PositionPlan {
    Tail,
    After(String),
    Before(String),
}

/// `createNewNoteWithTarget` + the `createNewNote` orchestration for the shell: parent
/// validation, type/mime derivation, default title, optional template support (mime
/// inheritance, binary content copy, `~template` relation, attachment copies), atomic
/// body attributes and `child:`-prefixed copies. Owns its transaction.
pub fn create_note_with_target(
    conn: &Connection,
    target: &str,
    target_branch_id: Option<&str>,
    params: NoteCreateParams,
) -> Result<NewNote, WriteError> {
    let plan = match target {
        "into" => PositionPlan::Tail,
        "after" => PositionPlan::After(target_branch_id.unwrap_or("").to_string()),
        "before" => PositionPlan::Before(target_branch_id.unwrap_or("").to_string()),
        _ => {
            return Err(WriteError {
                status: 400,
                message: "Invalid target type.".to_string(),
            });
        }
    };

    let parent = load_note(conn, &params.parent_note_id)
        .map_err(WriteError::from)?
        .ok_or_else(|| WriteError {
            status: 400,
            message: format!("Parent note '{}' was not found.", params.parent_note_id),
        })?;
    validate_parent_for_child(&parent, params.ignore_forbidden_parents)?;

    // Type defaults mirror `createNewNoteWithTarget`: no explicit type inherits a `code`
    // parent's type (and mime), and everything else becomes `text`/`text/html`.
    let is_type_defaulted = params.note_type.is_none();
    let note_type = params
        .note_type
        .clone()
        .unwrap_or_else(|| if parent.note_type == "code" { "code".to_string() } else { "text".to_string() });
    let defaulted_mime = if is_type_defaulted {
        Some(if parent.note_type == "code" { parent.mime.clone() } else { "text/html".to_string() })
    } else {
        None
    };

    // Template: existence check is deferred to inside the transaction; its mime only
    // inherits when neither the payload nor the type-defaulting supplied one.
    if let Some(template_id) = &params.template_note_id {
        let template = load_note(conn, template_id).map_err(WriteError::from)?;
        if template.is_none() {
            return Err(WriteError {
                status: 400,
                message: format!("Template note '{template_id}' does not exist."),
            });
        }
    }

    let template_note = params
        .template_note_id
        .as_deref()
        .and_then(|id| load_note(conn, id).ok().flatten());
    let mime = params
        .mime
        .clone()
        .or(defaulted_mime)
        .or_else(|| template_note.as_ref().map(|t| t.mime.clone()))
        .unwrap_or_else(|| default_mime_for(&note_type));

    // `getNewNoteTitle`: the app default for "new note". The real titleTemplate
    // evaluation on the parent is not reproduced in this shell.
    let title = params.title.clone().unwrap_or_else(|| "New note".to_string());

    let content = params.content.clone();
    let template = template_note;

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<NewNote> {
        // Position plan: `after`/`before` shift the sibling positions and record a
        // note-reordering change for the parent (positions are not part of branch hashes).
        let (note_position, reorder) = match &plan {
            PositionPlan::Tail => (params.note_position, false),
            PositionPlan::After(target_branch_id) => {
                let after_pos: i64 = conn
                    .query_row(
                        "SELECT notePosition FROM branches WHERE branchId = ?1 AND parentNoteId = ?2 AND isDeleted = 0",
                        params![target_branch_id, params.parent_note_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
                conn.execute(
                    "UPDATE branches SET notePosition = notePosition + 10 \
                     WHERE parentNoteId = ?1 AND notePosition > ?2 AND isDeleted = 0",
                    params![params.parent_note_id, after_pos],
                )?;
                (Some(after_pos + 10), true)
            }
            PositionPlan::Before(target_branch_id) => {
                let before_pos: i64 = conn
                    .query_row(
                        "SELECT notePosition FROM branches WHERE branchId = ?1 AND parentNoteId = ?2 AND isDeleted = 0",
                        params![target_branch_id, params.parent_note_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
                conn.execute(
                    "UPDATE branches SET notePosition = notePosition - 10 \
                     WHERE parentNoteId = ?1 AND notePosition < ?2 AND isDeleted = 0",
                    params![params.parent_note_id, before_pos],
                )?;
                (Some(before_pos - 10), true)
            }
        };

        let created = create_note_entity(
            conn,
            &params.parent_note_id,
            &title,
            &note_type,
            &mime,
            params.is_protected,
            content.as_bytes(),
            note_position,
            params.note_id.as_deref(),
            params.is_expanded,
            params.prefix.as_deref(),
        )?;
        if reorder {
            put_entity_change(conn, "note_reordering", &params.parent_note_id, "N/A", &utc_now())?;
        }

        // A binary-type template fills the new note with its content (string templates
        // leave the sent `content` in place — the note already holds it).
        if let Some(template) = &template {
            if !is_string_note(&template.note_type, &template.mime) {
                let old_blob = created_note_blob(conn, &created.note_id)?;
                let bytes = match &template.blob_id {
                    Some(blob_id) => read_clear_bytes(conn, blob_id, template.is_protected)?,
                    None => Vec::new(),
                };
                let local = local_now();
                let utc = utc_now();
                let new_blob = store_entity_content(conn, params.is_protected, false, &bytes, &local, &utc)?;
                if old_blob.as_ref() != Some(&new_blob) {
                    conn.execute(
                        "UPDATE notes SET blobId = ?1, dateModified = ?2, utcDateModified = ?3 WHERE noteId = ?4",
                        params![new_blob, local, utc, created.note_id],
                    )?;
                    let mut note = load_note(conn, &created.note_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
                    note.blob_id = Some(new_blob);
                    put_entity_change(conn, "notes", &created.note_id, &note_hash(&note, false), &utc)?;
                    if let Some(old) = old_blob {
                        delete_blob_if_not_used(conn, &old)?;
                    }
                }
            }

            // The `~template` relation is recorded before `copy_child_attributes` runs, so a
            // parent's `child:template` default is suppressed by this explicit choice.
            insert_attribute(conn, &created.note_id, "relation", "template", &template.note_id)?;

            // Non-image attachments of the template are copied over (`copyAttachments`;
            // image roles are handled by the later link scan in `check_image_attachments`).
            let mut stmt = conn.prepare(
                "SELECT attachmentId, role, mime, title, COALESCE(blobId, ''), isProtected \
                 FROM attachments WHERE ownerId = ?1 AND isDeleted = 0 AND role != 'image'",
            )?;
            let copies: Vec<(String, String, String, String, String, i64)> = stmt
                .query_map(params![template.note_id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (_attachment_id, role, mime, title, blob_id, is_protected) in copies {
                copy_attachment(conn, &created.note_id, &role, &mime, &title, &blob_id, is_protected != 0)?;
            }
        }

        // Body attributes are written atomically with the note.
        for attribute in &params.attributes {
            let attribute_id = random_string(12);
            let utc = utc_now();
            let max_position: i64 = conn.query_row(
                "SELECT COALESCE(MAX(position), 0) FROM attributes WHERE noteId = ?1 AND isDeleted = 0",
                params![created.note_id],
                |row| row.get(0),
            )?;
            conn.execute(
                "INSERT INTO attributes (attributeId, noteId, type, name, value, position, utcDateModified, isDeleted, deleteId, isInheritable) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, ?8)",
                params![attribute_id, created.note_id, attribute.attr_type, attribute.name, attribute.value, max_position + 10, utc, attribute.is_inheritable],
            )?;
            let hash = attribute_hash(&attribute_id, &created.note_id, &attribute.attr_type, &attribute.name, &attribute.value, attribute.is_inheritable, false);
            put_entity_change(conn, "attributes", &attribute_id, &hash, &utc)?;
        }

        copy_child_attributes(conn, &params.parent_note_id, &created.note_id)?;

        // The same link scan a save performs, on the content handed in at creation.
        if is_type_defaulted && !content.is_empty() {
            if let Ok(saved) = load_note(conn, &created.note_id) {
                if let Some(saved) = saved {
                    let _ = post_process_links(conn, &saved, &content);
                }
            }
        }
        Ok(created)
    })();
    match run {
        Ok(created) => {
            conn.execute_batch("COMMIT")?;
            Ok(created)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError {
                status: 400,
                message: "Missing or incorrect type for target branch ID.".to_string(),
            })
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

/// The blob a note currently points at, for the template content-copy overwrite.
fn created_note_blob(conn: &Connection, note_id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT blobId FROM notes WHERE noteId = ?1", params![note_id], |row| row.get(0)).optional()
}

/// `PUT /notes/{id}/title` — `notesApiRoute.changeTitle`: snapshot the note when the
/// title actually changes, then store the new title (encrypted at rest for protected
/// notes) with a fresh entity change. Protected notes require the open session.
pub fn change_note_title(conn: &Connection, note_id: &str, title: &str) -> Result<(), WriteError> {
    let note = load_note(conn, note_id).map_err(WriteError::from)?.ok_or_else(|| WriteError::not_found(note_id))?;
    if note.is_protected && !session::is_available() {
        return Err(WriteError {
            status: 400,
            message: format!("Note '{note_id}' is not available for change"),
        });
    }
    // The stored title of a protected note is ciphertext; compare against the decrypted
    // form so an untouched save does not take a spurious revision.
    let current_title = if note.is_protected {
        session::decrypt_bytes(&note.title)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| note.title.clone())
    } else {
        note.title.clone()
    };
    if current_title != title {
        save_revision_if_needed(conn, &note).map_err(WriteError::from)?;
    }

    let mut note = note;
    note.title = if note.is_protected {
        session::encrypt_string(title).ok_or_else(|| WriteError {
            status: 500,
            message: "Failed to encrypt the note title".to_string(),
        })?
    } else {
        title.to_string()
    };
    save_note(conn, &note).map_err(WriteError::from)?;
    Ok(())
}

/// A `notes` row regardless of deletion state — the delete/undelete paths read and
/// rewrite soft-deleted rows, which `load_note` filters out.
struct NoteRowAny {
    note: WriteNote,
    is_deleted: bool,
    delete_id: Option<String>,
}

fn load_note_any(conn: &Connection, note_id: &str) -> rusqlite::Result<Option<NoteRowAny>> {
    conn.query_row(
        "SELECT noteId, title, isProtected, type, mime, blobId, dateModified, utcDateCreated, \
                utcDateModified, isDeleted, deleteId \
         FROM notes WHERE noteId = ?1",
        params![note_id],
        |row| {
            Ok(NoteRowAny {
                note: WriteNote {
                    note_id: row.get(0)?,
                    title: row.get(1)?,
                    note_type: row.get(3)?,
                    mime: row.get(4)?,
                    is_protected: row.get::<_, i64>(2)? != 0,
                    blob_id: row.get(5)?,
                    date_modified: row.get(6)?,
                    utc_date_created: row.get(7)?,
                    utc_date_modified: row.get(8)?,
                },
                is_deleted: row.get::<_, i64>(9)? != 0,
                delete_id: row.get(10)?,
            })
        },
    )
    .optional()
}

/// A `branches` row regardless of deletion state — only the fields the delete/undelete
/// cascade reads, not the tree-rendering ones.
struct BranchState {
    branch_id: String,
    note_id: String,
    parent_note_id: String,
    prefix: Option<String>,
    is_deleted: bool,
}

fn branch_from_row(row: &rusqlite::Row) -> rusqlite::Result<BranchState> {
    Ok(BranchState {
        branch_id: row.get(0)?,
        note_id: row.get(1)?,
        parent_note_id: row.get(2)?,
        prefix: row.get(3)?,
        is_deleted: row.get::<_, i64>(4)? != 0,
    })
}

fn load_branch(conn: &Connection, branch_id: &str) -> rusqlite::Result<Option<BranchState>> {
    conn.query_row(
        "SELECT branchId, noteId, parentNoteId, prefix, isDeleted FROM branches WHERE branchId = ?1",
        params![branch_id],
        branch_from_row,
    )
    .optional()
}

/// The `branches` entity hash over `branchId|noteId|parentNoteId|prefix` — notePosition
/// deliberately excluded — with the `|deleted` suffix for the soft-delete state.
fn branch_hash_value(branch_id: &str, note_id: &str, parent_note_id: &str, prefix: Option<&str>, is_deleted: bool) -> String {
    let mut input = format!("|{branch_id}|{note_id}|{parent_note_id}|{}", prefix.unwrap_or(""));
    if is_deleted {
        input.push_str("|deleted");
    }
    hash10(&input)
}

/// `markAsDeleted` for a branch: soft-delete row + deleted entity change.
fn mark_branch_deleted(conn: &Connection, branch: &BranchState, delete_id: &str) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE branches SET isDeleted = 1, deleteId = ?1, utcDateModified = ?2 WHERE branchId = ?3",
        params![delete_id, utc, branch.branch_id],
    )?;
    put_entity_change(conn, "branches", &branch.branch_id, &branch_hash_value(&branch.branch_id, &branch.note_id, &branch.parent_note_id, branch.prefix.as_deref(), true), &utc)
}

/// `markAsDeleted` for an attribute (owned labels and target relations alike).
fn mark_attribute_deleted(
    conn: &Connection,
    attribute_id: &str,
    note_id: &str,
    attr_type: &str,
    name: &str,
    value: &str,
    is_inheritable: bool,
    delete_id: &str,
) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE attributes SET isDeleted = 1, deleteId = ?1, utcDateModified = ?2 WHERE attributeId = ?3",
        params![delete_id, utc, attribute_id],
    )?;
    let hash = attribute_hash(attribute_id, note_id, attr_type, name, value, is_inheritable, true);
    put_entity_change(conn, "attributes", attribute_id, &hash, &utc)
}

/// `markAsDeleted` for an attachment.
fn mark_attachment_deleted(
    conn: &Connection,
    attachment_id: &str,
    owner_id: &str,
    role: &str,
    mime: &str,
    title: &str,
    blob_id: &str,
    scheduled: Option<&str>,
    delete_id: &str,
) -> rusqlite::Result<()> {
    let utc = utc_now();
    conn.execute(
        "UPDATE attachments SET isDeleted = 1, deleteId = ?1, utcDateModified = ?2 WHERE attachmentId = ?3",
        params![delete_id, utc, attachment_id],
    )?;
    let hash = attachment_hash_value(attachment_id, owner_id, role, mime, title, blob_id, scheduled, true);
    put_entity_change(conn, "attachments", attachment_id, &hash, &utc)
}

/// `markAsDeleted` for the note itself.
fn mark_note_deleted(conn: &Connection, note: &WriteNote, delete_id: &str) -> rusqlite::Result<()> {
    let local = local_now();
    let utc = utc_now();
    conn.execute(
        "UPDATE notes SET isDeleted = 1, deleteId = ?1, dateModified = ?2, utcDateModified = ?3 WHERE noteId = ?4",
        params![delete_id, local, utc, note.note_id],
    )?;
    put_entity_change(conn, "notes", &note.note_id, &note_hash(note, true), &utc)
}

/// `BBranch.deleteBranch`: mark the branch deleted; once the note keeps no strong parent,
/// cascade the same `deleteId` over its weak branches, child branches, owned attributes,
/// target relations, attachments and finally the note itself. Returns whether the note
/// (and its subtree) went along with the branch.
fn delete_branch_recursively(conn: &Connection, branch: &BranchState, delete_id: &str) -> rusqlite::Result<bool> {
    let is_weak = branch.parent_note_id == "_share" || branch.parent_note_id == "_lbBookmarks";
    if branch.note_id == "root" && !is_weak {
        return Err(rusqlite::Error::InvalidQuery); // "Can't delete root or hoisted branch/note"
    }

    mark_branch_deleted(conn, branch, delete_id)?;

    // The note keeps another strong parent → this was a clone deletion, the note survives.
    let strong_parents: i64 = conn.query_row(
        "SELECT COUNT(*) FROM branches WHERE noteId = ?1 AND isDeleted = 0 \
         AND parentNoteId NOT IN ('_share', '_lbBookmarks')",
        params![branch.note_id],
        |row| row.get(0),
    )?;
    if strong_parents != 0 {
        return Ok(false);
    }

    // Weak parents (shares, bookmarks) follow the note into deletion.
    let mut stmt = conn.prepare(
        "SELECT branchId, noteId, parentNoteId, prefix, isDeleted \
         FROM branches WHERE noteId = ?1 AND isDeleted = 0",
    )?;
    let weak_parents: Vec<BranchState> = stmt
        .query_map(params![branch.note_id], branch_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    for weak in weak_parents {
        mark_branch_deleted(conn, &weak, delete_id)?;
    }

    // Children first, then the parent — the deletion shows up in recent changes in that order.
    let mut stmt = conn.prepare(
        "SELECT branchId, noteId, parentNoteId, prefix, isDeleted \
         FROM branches WHERE parentNoteId = ?1 AND isDeleted = 0",
    )?;
    let child_branches: Vec<BranchState> = stmt
        .query_map(params![branch.note_id], branch_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    for child in child_branches {
        delete_branch_recursively(conn, &child, delete_id)?;
    }

    // Owned attributes and relations pointing at this note.
    let mut stmt = conn.prepare(
        "SELECT attributeId, noteId, type, name, value, isInheritable FROM attributes \
         WHERE (noteId = ?1 OR (type = 'relation' AND value = ?1)) AND isDeleted = 0",
    )?;
    let attrs: Vec<(String, String, String, String, String, i64)> = stmt
        .query_map(params![branch.note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (attribute_id, note_id, attr_type, name, value, is_inheritable) in attrs {
        mark_attribute_deleted(conn, &attribute_id, &note_id, &attr_type, &name, &value, is_inheritable != 0, delete_id)?;
    }

    // Attachments owned by the note.
    let mut stmt = conn.prepare(
        "SELECT attachmentId, ownerId, role, mime, title, COALESCE(blobId, ''), utcDateScheduledForErasureSince \
         FROM attachments WHERE ownerId = ?1 AND isDeleted = 0",
    )?;
    let attachments: Vec<(String, String, String, String, String, String, Option<String>)> = stmt
        .query_map(params![branch.note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (attachment_id, owner_id, role, mime, title, blob_id, scheduled) in attachments {
        mark_attachment_deleted(conn, &attachment_id, &owner_id, &role, &mime, &title, &blob_id, scheduled.as_deref(), delete_id)?;
    }

    let note = load_note_any(conn, &branch.note_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    mark_note_deleted(conn, &note.note, delete_id)?;
    Ok(true)
}

/// `DELETE /notes/{id}` — `note.deleteNote(deleteId)`: soft-delete the note and, through
/// `deleteBranch`, its whole subtree under one `deleteId`. A note already deleted is a
/// silent no-op; a missing one is a 404 (mirrors `becca.getNoteOrThrow`).
pub fn delete_note(conn: &Connection, note_id: &str, delete_id: &str) -> Result<(), WriteError> {
    let Some(row) = load_note_any(conn, note_id).map_err(WriteError::from)? else {
        return Err(WriteError::not_found(note_id));
    };
    if row.is_deleted {
        return Ok(());
    }

    let parent_branches: Vec<BranchState> = {
        let mut stmt = conn.prepare(
            "SELECT branchId, noteId, parentNoteId, prefix, isDeleted \
             FROM branches WHERE noteId = ?1 AND isDeleted = 0",
        )?;
        let rows = stmt.query_map(params![note_id], branch_from_row)?;
        let mut branches = Vec::new();
        for row in rows {
            branches.push(row?);
        }
        branches
    };

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        for branch in parent_branches {
            delete_branch_recursively(conn, &branch, delete_id)?;
        }
        Ok(())
    })();
    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

/// Physical deletion of entity rows plus their entity changes marked as erased —
/// `eraseNotes`/`eraseBranches`/… in `erase.ts`: the rows are dropped and the matching
/// `entity_changes` rows keep their hash but flip `isErased` with a fresh change id so
/// connected clients learn about the erasure.
fn erase_entity_rows(conn: &Connection, table: &str, pk: &str, entity_name: &str, ids: &[String]) -> rusqlite::Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    conn.execute(&format!("DELETE FROM {table} WHERE {pk} IN ({placeholders})"), rusqlite::params_from_iter(refs))?;
    for id in ids {
        conn.execute(
            "UPDATE entity_changes SET isErased = 1, changeId = ?1, componentId = 'NA', instanceId = ?2, isSynced = 1, utcDateChanged = ?3 \
             WHERE entityName = ?4 AND entityId = ?5",
            params![random_string(12), instance_id(), utc_now(), entity_name, id],
        )?;
    }
    Ok(())
}

/// `eraseUnusedBlobs`: purge blobs no note/attachment/revision references any more.
fn erase_unused_blobs(conn: &Connection) -> rusqlite::Result<()> {
    let orphaned: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT b.blobId FROM blobs b \
             LEFT JOIN notes n ON n.blobId = b.blobId \
             LEFT JOIN attachments a ON a.blobId = b.blobId \
             LEFT JOIN revisions r ON r.blobId = b.blobId \
             WHERE n.noteId IS NULL AND a.attachmentId IS NULL AND r.revisionId IS NULL",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out
    };
    for blob_id in orphaned {
        conn.execute("DELETE FROM blobs WHERE blobId = ?1", params![blob_id])?;
        conn.execute("DELETE FROM entity_changes WHERE entityName = 'blobs' AND entityId = ?1", params![blob_id])?;
    }
    Ok(())
}

/// `eraseNotesWithDeleteId`: after a `?eraseNotes=true` delete, physically erase every
/// soft-deleted row stamped with the batch's `deleteId` (and the revisions of the erased
/// notes), then purge now-unreferenced blobs.
pub fn erase_notes_with_delete_id(conn: &Connection, delete_id: &str) -> rusqlite::Result<()> {
    fn ids_for(conn: &Connection, sql: &str, arg: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![arg], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<()> {
        let note_ids = ids_for(conn, "SELECT noteId FROM notes WHERE isDeleted = 1 AND deleteId = ?1", delete_id)?;
        erase_entity_rows(conn, "notes", "noteId", "notes", &note_ids)?;
        if !note_ids.is_empty() {
            let placeholders = note_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let refs: Vec<&str> = note_ids.iter().map(String::as_str).collect();
            let mut stmt = conn.prepare(&format!("SELECT revisionId FROM revisions WHERE noteId IN ({placeholders})"))?;
            let revision_ids: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(refs), |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            erase_entity_rows(conn, "revisions", "revisionId", "revisions", &revision_ids)?;
        }
        let branch_ids = ids_for(conn, "SELECT branchId FROM branches WHERE isDeleted = 1 AND deleteId = ?1", delete_id)?;
        erase_entity_rows(conn, "branches", "branchId", "branches", &branch_ids)?;
        let attribute_ids = ids_for(conn, "SELECT attributeId FROM attributes WHERE isDeleted = 1 AND deleteId = ?1", delete_id)?;
        erase_entity_rows(conn, "attributes", "attributeId", "attributes", &attribute_ids)?;
        let attachment_ids = ids_for(conn, "SELECT attachmentId FROM attachments WHERE isDeleted = 1 AND deleteId = ?1", delete_id)?;
        erase_entity_rows(conn, "attachments", "attachmentId", "attachments", &attachment_ids)?;
        erase_unused_blobs(conn)?;
        Ok(())
    })();
    match run {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(err)
        }
    }
}

/// The outcome of an undelete, as the route's `UndeleteNoteResult` shape.
pub struct UndeleteResult {
    pub undeleted: bool,
    pub restored_to_fallback_parent: bool,
}

/// `PUT /notes/{id}/undelete` — `noteService.undeleteNote`: restore a soft-deleted note
/// through whichever of its original parents still lives; a note whose parents are all
/// gone is only restorable under an explicit fallback parent. Returns whether anything
/// was actually restored (an already-erased note cannot be).
pub fn undelete_note(conn: &Connection, note_id: &str, fallback_parent_note_id: Option<&str>) -> Result<UndeleteResult, WriteError> {
    let failed = UndeleteResult { undeleted: false, restored_to_fallback_parent: false };

    let Some(row) = load_note_any(conn, note_id).map_err(WriteError::from)? else {
        return Ok(failed); // erased in the meantime — nothing to restore
    };
    if !row.is_deleted {
        return Ok(failed);
    }
    let Some(delete_id) = row.delete_id.clone() else {
        return Ok(failed);
    };

    conn.execute_batch("BEGIN")?;
    let run = (|| -> rusqlite::Result<UndeleteResult> {
        // Original parents that still live: restore through them.
        let mut stmt = conn.prepare(
            "SELECT b.branchId FROM branches b JOIN notes p ON p.noteId = b.parentNoteId \
             WHERE b.noteId = ?1 AND b.isDeleted = 1 AND b.deleteId = ?2 AND p.isDeleted = 0",
        )?;
        let branch_ids: Vec<String> = stmt
            .query_map(params![note_id, delete_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if !branch_ids.is_empty() {
            for branch_id in &branch_ids {
                undelete_branch(conn, branch_id, &delete_id)?;
            }
            return Ok(UndeleteResult { undeleted: true, restored_to_fallback_parent: false });
        }

        // Orphan: give it a new home under the fallback parent, if one was named and lives.
        let Some(fallback) = fallback_parent_note_id else {
            return Ok(failed);
        };
        if load_note(conn, fallback)?.is_none() {
            return Ok(failed);
        }
        let branch_id = format!("{fallback}_{note_id}");
        let position = note_position_for(conn, fallback)?;
        let utc = utc_now();
        conn.execute(
            "INSERT INTO branches (branchId, noteId, parentNoteId, notePosition, prefix, isExpanded, isDeleted, deleteId, utcDateModified) \
             VALUES (?1, ?2, ?3, ?4, '', 0, 0, NULL, ?5)",
            params![branch_id, note_id, fallback, position, utc],
        )?;
        put_entity_change(conn, "branches", &branch_id, &branch_hash_value(&branch_id, note_id, fallback, Some(""), false), &utc)?;
        restore_note_and_descendants(conn, note_id, &delete_id)?;
        Ok(UndeleteResult { undeleted: true, restored_to_fallback_parent: true })
    })();
    match run {
        Ok(result) => {
            conn.execute_batch("COMMIT")?;
            Ok(result)
        }
        Err(err) => {
            conn.execute_batch("ROLLBACK")?;
            Err(WriteError::from(err))
        }
    }
}

/// `undeleteBranch`: restore one soft-deleted branch (skipped when its note was deleted in
/// a different batch), recursing into the note's own subtree when it shares the deleteId.
fn undelete_branch(conn: &Connection, branch_id: &str, delete_id: &str) -> rusqlite::Result<()> {
    let Some(branch) = load_branch(conn, branch_id)? else {
        return Ok(());
    };
    if !branch.is_deleted {
        return Ok(());
    }
    let note_state = load_note_any(conn, &branch.note_id)?;
    if let Some(note) = &note_state {
        if note.is_deleted && note.delete_id.as_deref() != Some(delete_id) {
            return Ok(());
        }
    }

    conn.execute("UPDATE branches SET isDeleted = 0 WHERE branchId = ?1", params![branch.branch_id])?;
    put_entity_change(conn, "branches", &branch.branch_id, &branch_hash_value(&branch.branch_id, &branch.note_id, &branch.parent_note_id, branch.prefix.as_deref(), false), &utc_now())?;

    if let Some(note) = &note_state {
        if note.is_deleted && note.delete_id.as_deref() == Some(delete_id) {
            restore_note_and_descendants(conn, &branch.note_id, delete_id)?;
        }
    }
    Ok(())
}

/// `restoreNoteAndDescendants`: restore the note's row, the attributes and attachments
/// deleted with it (matching the deleteId), then recurse into the child branches of the
/// subtree. Each row keeps its stored values; only `isDeleted` flips back, which is
/// exactly what `entity.save()` — a full upsert with `isDeleted: false` — does.
fn restore_note_and_descendants(conn: &Connection, note_id: &str, delete_id: &str) -> rusqlite::Result<()> {
    let Some(row) = load_note_any(conn, note_id)? else {
        return Ok(());
    };
    conn.execute("UPDATE notes SET isDeleted = 0 WHERE noteId = ?1", params![note_id])?;
    put_entity_change(conn, "notes", note_id, &note_hash(&row.note, false), &utc_now())?;

    let mut stmt = conn.prepare(
        "SELECT attributeId, noteId, type, name, value, isInheritable FROM attributes \
         WHERE isDeleted = 1 AND deleteId = ?1 AND (noteId = ?2 OR (type = 'relation' AND value = ?2))",
    )?;
    let attrs: Vec<(String, String, String, String, String, i64)> = stmt
        .query_map(params![delete_id, note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (attribute_id, attr_note_id, attr_type, name, value, is_inheritable) in attrs {
        conn.execute("UPDATE attributes SET isDeleted = 0 WHERE attributeId = ?1", params![attribute_id])?;
        let hash = attribute_hash(&attribute_id, &attr_note_id, &attr_type, &name, &value, is_inheritable != 0, false);
        put_entity_change(conn, "attributes", &attribute_id, &hash, &utc_now())?;
    }

    let mut stmt = conn.prepare(
        "SELECT attachmentId, ownerId, role, mime, title, COALESCE(blobId, ''), utcDateScheduledForErasureSince \
         FROM attachments WHERE isDeleted = 1 AND deleteId = ?1 AND ownerId = ?2",
    )?;
    let attachments: Vec<(String, String, String, String, String, String, Option<String>)> = stmt
        .query_map(params![delete_id, note_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (attachment_id, owner_id, role, mime, title, blob_id, scheduled) in attachments {
        conn.execute("UPDATE attachments SET isDeleted = 0 WHERE attachmentId = ?1", params![attachment_id])?;
        let hash = attachment_hash_value(&attachment_id, &owner_id, &role, &mime, &title, &blob_id, scheduled.as_deref(), false);
        put_entity_change(conn, "attachments", &attachment_id, &hash, &utc_now())?;
    }

    let mut stmt = conn.prepare("SELECT branchId FROM branches WHERE isDeleted = 1 AND deleteId = ?1 AND parentNoteId = ?2")?;
    let child_ids: Vec<String> = stmt
        .query_map(params![delete_id, note_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for branch_id in child_ids {
        undelete_branch(conn, &branch_id, delete_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
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

    /// The upload-endpoint picture gate matches the shared `image_mimes` list exactly.
    #[test]
    fn accepted_image_mimes_match_commons_list() {
        for mime in [
            "image/png",
            "image/jpg",
            "image/jpeg",
            "image/gif",
            "image/bmp",
            "image/webp",
            "image/avif",
            "image/svg",
            "image/svg+xml",
            "image/x-icon",
            "image/vnd.microsoft.icon",
        ] {
            assert!(is_accepted_image_mime(mime), "{mime} should be a picture");
        }
        for mime in ["text/plain", "application/pdf", "image/tiff", "", "whatever"] {
            assert!(!is_accepted_image_mime(mime), "{mime:?} should not be a picture");
        }
    }

    /// A reusable helper for the multipart/convert integration run: a surviving,
    /// non-protected text note that `load_note` can act on.
    fn pick_text_note(conn: &Connection) -> String {
        let mut stmt = conn.prepare("SELECT noteId FROM notes WHERE type = 'text' AND isDeleted = 0").unwrap();
        let ids: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|x| x.unwrap()).collect();
        ids.iter()
            .find(|id| matches!(load_note(conn, id), Ok(Some(n)) if !n.is_protected))
            .cloned()
            .expect("no non-protected text note to run against")
            .clone()
    }

    /// Upload → convert-to-note over a copy of a real database: a PNG upload lands as an
    /// `image` attachment, converting it creates an image note under the same parent with the
    /// same bytes, the attachment is soft-deleted, and a text parent's content is re-pointed
    /// at the new note.
    #[test]
    fn upload_and_convert_attachment_to_note() {
        let Ok(src) = std::env::var("TRILIUM_VERIFY_SOURCE") else {
            eprintln!("TRILIUM_VERIFY_SOURCE not set; integration verification skipped");
            return;
        };
        let conn = copy_db(&src);
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x00\x50";

        let note_id = pick_text_note(&conn);

        // Upload the picture: role `image`, blob holding PNG magic bytes.
        let UploadedAttachment::Image { attachment_id, title } = save_uploaded_attachment(
            &conn, &note_id, "photo.png", "image/png", png,
        )
        .unwrap()
        else {
            panic!("a PNG upload must take the image branch");
        };
        assert_eq!(title, "photo.png");
        let (role, blob): (String, String) = conn
            .query_row(
                "SELECT a.role, a.blobId FROM attachments a WHERE a.attachmentId = ?1",
                params![attachment_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(role, "image");
        let stored: Vec<u8> = conn.query_row("SELECT content FROM blobs WHERE blobId = ?1", params![blob], |r| r.get(0)).unwrap();
        assert!(stored.starts_with(b"\x89PNG"), "uploaded bytes must be stored verbatim");

        // Reference the picture from the parent's content, as the editor would.
        let content = format!(r#"<p>see <img src="api/attachments/{attachment_id}/image/photo.png"></p>"#);
        update_note_data(&conn, &note_id, &content).unwrap();

        // Convert: a new image note under the same parent, the attachment soft-deleted, and the
        // parent's content re-pointed at `api/images/{newNoteId}/`.
        let created = convert_attachment_to_note(&conn, &attachment_id).unwrap();
        let created_parent: String = conn
            .query_row("SELECT parentNoteId FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0))
            .unwrap();
        assert_eq!(created_parent, note_id);
        let (note_type, is_protected, new_blob): (String, i64, String) = conn
            .query_row(
                "SELECT type, isProtected, blobId FROM notes WHERE noteId = ?1 AND isDeleted = 0",
                params![created.note_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(note_type, "image");
        assert_eq!(is_protected, 0);
        let new_stored: Vec<u8> = conn.query_row("SELECT content FROM blobs WHERE blobId = ?1", params![new_blob], |r| r.get(0)).unwrap();
        assert_eq!(new_stored, png, "converted note must hold the attachment bytes");
        let branch_parent: String = conn
            .query_row(
                "SELECT parentNoteId FROM branches WHERE branchId = ?1",
                params![created.branch_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(branch_parent, note_id);

        let deleted: i64 = conn
            .query_row("SELECT isDeleted FROM attachments WHERE attachmentId = ?1", params![attachment_id], |r| r.get(0))
            .unwrap();
        assert_eq!(deleted, 1, "the converted attachment must be marked deleted");

        let final_content: String = conn
            .query_row(
                "SELECT b.content FROM blobs b JOIN notes n ON n.blobId = b.blobId WHERE n.noteId = ?1",
                params![note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            final_content.contains(&format!("api/images/{}/", created.note_id)),
            "parent content must point at the new image note: {final_content}"
        );
        assert!(!final_content.contains(&format!("api/attachments/{attachment_id}/image/")), "old attachment URL must be gone");

        eprintln!("upload+convert verification passed (note {}, image note {})", note_id, created.note_id);
    }

    /// Multipart file routes over a copy of a real database: `PUT attachments/{id}/file`
    /// replaces the bytes (mime included), and `PUT notes/{id}/file` writes the file over a
    /// note's content and stamps `originalFileName`.
    #[test]
    fn upload_file_routes_replace_content() {
        let Ok(src) = std::env::var("TRILIUM_VERIFY_SOURCE") else {
            eprintln!("TRILIUM_VERIFY_SOURCE not set; integration verification skipped");
            return;
        };
        let conn = copy_db(&src);
        let note_id = pick_text_note(&conn);
        let bytes = b"hello file content".to_vec();

        // `PUT notes/{id}/file` (no replace): content written, `originalFileName` label set, mime lowercased.
        update_file_note(&conn, &note_id, "greeting.txt", "Text/Plain", &bytes, false).unwrap();
        let mime: String = conn.query_row("SELECT mime FROM notes WHERE noteId = ?1", params![note_id], |r| r.get(0)).unwrap();
        assert_eq!(mime, "text/plain");
        let stored: String = conn
            .query_row("SELECT b.content FROM blobs b JOIN notes n ON n.blobId = b.blobId WHERE n.noteId = ?1", params![note_id], |r| r.get(0))
            .unwrap();
        assert!(stored.contains("hello file content"), "note content must hold the upload");
        let labeled: Option<String> = conn
            .query_row(
                "SELECT value FROM attributes WHERE noteId = ?1 AND type = 'label' AND name = 'originalFileName' AND isDeleted = 0",
                params![note_id],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(labeled.as_deref(), Some("greeting.txt"));
        // A revision snapshot was taken before the overwrite.
        let revisions: i64 = conn.query_row("SELECT COUNT(*) FROM revisions WHERE noteId = ?1", params![note_id], |r| r.get(0)).unwrap();
        assert!(revisions >= 1, "a non-replace file upload must snapshot first");

        // `PUT attachments/{id}/file`: pick any surviving attachment and replace its bytes.
        let attachment: Option<(String, i64)> = conn
            .query_row(
                "SELECT attachmentId, isProtected FROM attachments WHERE ownerId = ?1 AND isDeleted = 0 AND blobId IS NOT NULL LIMIT 1",
                params![note_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap();
        if let Some((attachment_id, protected)) = attachment {
            if protected == 0 {
                let replacement = b"replacement bytes".to_vec();
                update_file_attachment(&conn, &attachment_id, "application/x-bin", &replacement).unwrap();
                let (mime, blob): (String, String) = conn
                    .query_row(
                        "SELECT mime, blobId FROM attachments WHERE attachmentId = ?1",
                        params![attachment_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(mime, "application/x-bin");
                let stored: Vec<u8> = conn.query_row("SELECT content FROM blobs WHERE blobId = ?1", params![blob], |r| r.get(0)).unwrap();
                assert_eq!(stored, replacement, "attachment blob must hold the replacement");
            }
        }
        eprintln!("file-route verification passed for note {note_id}");
    }

    /// The full note lifecycle over a copy of a real database: create (with type/mime
    /// derivation and an owned label), create *after* a sibling, rename, soft-delete
    /// (subtree + attributes), undelete through the surviving parent, delete again and
    /// erase — checking the rows and entity changes at each step.
    #[test]
    fn note_lifecycle_create_rename_delete_undelete_erase() {
        let Ok(src) = std::env::var("TRILIUM_VERIFY_SOURCE") else {
            eprintln!("TRILIUM_VERIFY_SOURCE not set; integration verification skipped");
            return;
        };
        let conn = copy_db(&src);
        let parent = pick_text_note(&conn);

        // --- create into the parent (text type derived) with an owned label ---
        let created = create_note_with_target(
            &conn,
            "into",
            None,
            NoteCreateParams {
                parent_note_id: parent.clone(),
                title: Some("Lifecycle note".to_string()),
                note_type: None,
                mime: None,
                content: "<p>hello</p>".to_string(),
                is_protected: false,
                is_expanded: false,
                prefix: None,
                note_position: None,
                note_id: None,
                template_note_id: None,
                attributes: vec![CreateAttribute {
                    attr_type: "label".to_string(),
                    name: "testLabel".to_string(),
                    value: "v1".to_string(),
                    is_inheritable: true,
                }],
                ignore_forbidden_parents: false,
            },
        )
        .unwrap();

        let (note_type, mime, stored_title): (String, String, String) = conn
            .query_row(
                "SELECT type, mime, title FROM notes WHERE noteId = ?1 AND isDeleted = 0",
                params![created.note_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(note_type, "text", "type should be derived from the parent");
        assert_eq!(mime, "text/html", "text type has the default HTML mime");
        assert_eq!(stored_title, "Lifecycle note");
        let content: String = conn
            .query_row(
                "SELECT b.content FROM blobs b JOIN notes n ON n.blobId = b.blobId WHERE n.noteId = ?1",
                params![created.note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(content, "<p>hello</p>", "creation content must be stored verbatim");
        let branch_parent: String = conn
            .query_row("SELECT parentNoteId FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0))
            .unwrap();
        assert_eq!(branch_parent, parent);

        // --- create after the sibling: position = sibling + 10 ---
        let after = create_note_with_target(
            &conn,
            "after",
            Some(&created.branch_id),
            NoteCreateParams {
                parent_note_id: parent.clone(),
                title: Some("After sibling".to_string()),
                note_type: None,
                mime: None,
                content: String::new(),
                is_protected: false,
                is_expanded: false,
                prefix: None,
                note_position: None,
                note_id: None,
                template_note_id: None,
                attributes: Vec::new(),
                ignore_forbidden_parents: false,
            },
        )
        .unwrap();
        let after_position: i64 = conn
            .query_row("SELECT notePosition FROM branches WHERE branchId = ?1", params![after.branch_id], |r| r.get(0))
            .unwrap();
        let created_position: i64 = conn
            .query_row("SELECT notePosition FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0))
            .unwrap();
        assert_eq!(after_position, created_position + 10, "after targets the sibling + 10");

        // --- rename; a title change takes a revision snapshot first ---
        change_note_title(&conn, &created.note_id, "Renamed").unwrap();
        let stored_title: String = conn
            .query_row("SELECT title FROM notes WHERE noteId = ?1 AND isDeleted = 0", params![created.note_id], |r| r.get(0))
            .unwrap();
        assert_eq!(stored_title, "Renamed");

        // --- soft delete: note/branch/owned label all marked with the batch deleteId ---
        let delete_id = "dv00000101";
        delete_note(&conn, &created.note_id, delete_id).unwrap();
        let (is_deleted, stored_delete_id): (i64, String) = conn
            .query_row(
                "SELECT isDeleted, deleteId FROM notes WHERE noteId = ?1",
                params![created.note_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(is_deleted, 1);
        assert_eq!(stored_delete_id, delete_id);
        let branch_deleted: i64 = conn
            .query_row("SELECT isDeleted FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0))
            .unwrap();
        assert_eq!(branch_deleted, 1);
        let label_deleted: i64 = conn
            .query_row(
                "SELECT isDeleted FROM attributes WHERE noteId = ?1 AND name = 'testLabel'",
                params![created.note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(label_deleted, 1, "owned attributes are soft-deleted with the note");

        // --- undelete through the surviving parent: note, branch and label back ---
        let result = undelete_note(&conn, &created.note_id, None).unwrap();
        assert!(result.undeleted);
        assert!(!result.restored_to_fallback_parent);
        let is_deleted: i64 = conn
            .query_row("SELECT isDeleted FROM notes WHERE noteId = ?1", params![created.note_id], |r| r.get(0))
            .unwrap();
        assert_eq!(is_deleted, 0, "note must be restored");
        let branch_deleted: i64 = conn
            .query_row("SELECT isDeleted FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0))
            .unwrap();
        assert_eq!(branch_deleted, 0, "branch must be restored");
        let label_deleted: i64 = conn
            .query_row(
                "SELECT isDeleted FROM attributes WHERE noteId = ?1 AND name = 'testLabel'",
                params![created.note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(label_deleted, 0, "owned label must be restored");
        let note_change_hash: String = conn
            .query_row(
                "SELECT hash FROM entity_changes WHERE entityName = 'notes' AND entityId = ?1 AND isErased = 0",
                params![created.note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!note_change_hash.ends_with("|deleted") && !note_change_hash.contains("deleted"), "restored change hash must be the live one");

        // --- delete with erase: rows physically gone, entity changes flipped to erased ---
        delete_note(&conn, &created.note_id, delete_id).unwrap();
        delete_note(&conn, &after.note_id, delete_id).unwrap();
        erase_notes_with_delete_id(&conn, delete_id).unwrap();
        let note_rows: i64 = conn.query_row("SELECT COUNT(*) FROM notes WHERE noteId = ?1", params![created.note_id], |r| r.get(0)).unwrap();
        assert_eq!(note_rows, 0, "erased note rows are gone");
        let branch_rows: i64 = conn.query_row("SELECT COUNT(*) FROM branches WHERE branchId = ?1", params![created.branch_id], |r| r.get(0)).unwrap();
        assert_eq!(branch_rows, 0, "erased branch rows are gone");
        let erased: i64 = conn
            .query_row(
                "SELECT isErased FROM entity_changes WHERE entityName = 'notes' AND entityId = ?1",
                params![created.note_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(erased, 1, "the note's entity change must be marked erased");

        // An orphaned note (parent deleted too) can only be restored under a fallback parent.
        let orphan = create_note_with_target(
            &conn,
            "into",
            None,
            NoteCreateParams {
                parent_note_id: parent.clone(),
                title: Some("Orphan".to_string()),
                note_type: None,
                mime: None,
                content: String::new(),
                is_protected: false,
                is_expanded: false,
                prefix: None,
                note_position: None,
                note_id: None,
                template_note_id: None,
                attributes: Vec::new(),
                ignore_forbidden_parents: false,
            },
        )
        .unwrap();
        delete_note(&conn, &orphan.note_id, "dv00000102").unwrap();
        // First delete the orphan's parent, so no live parent branch exists for it.
        let fallback = create_note_with_target(
            &conn,
            "into",
            None,
            NoteCreateParams {
                parent_note_id: parent.clone(),
                title: Some("Fallback home".to_string()),
                note_type: None,
                mime: None,
                content: String::new(),
                is_protected: false,
                is_expanded: false,
                prefix: None,
                note_position: None,
                note_id: None,
                template_note_id: None,
                attributes: Vec::new(),
                ignore_forbidden_parents: false,
            },
        )
        .unwrap();
        delete_note(&conn, &fallback.note_id, "dv00000103").unwrap();
        delete_note(&conn, &orphan.note_id, "dv00000102").unwrap();
        let result = undelete_note(&conn, &orphan.note_id, Some(&fallback.note_id)).unwrap();
        assert!(result.undeleted, "orphan should be restorable under the fallback parent");
        assert!(result.restored_to_fallback_parent, "the fallback parent reattachment must be reported");
        let orphan_home: String = conn
            .query_row("SELECT parentNoteId FROM branches WHERE noteId = ?1 AND isDeleted = 0", params![orphan.note_id], |r| r.get(0))
            .unwrap();
        assert_eq!(orphan_home, fallback.note_id, "orphan must be reattached under the fallback");

        eprintln!(
            "note-lifecycle verification passed (note {}, after-sibling {}, orphan {})",
            created.note_id, after.note_id, orphan.note_id
        );
    }
}