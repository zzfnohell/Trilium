//! Best-effort access to the existing Trilium SQLite database.
//!
//! The desktop app keeps its data in the Trilium data directory. The path is
//! resolved with the same priority as the real server (see apps/server
//! `services/data_dir.ts`): `TRILIUM_DATA_DIR`, a `trilium-data` folder in the
//! home dir, a platform app-data dir (`%APPDATA%` on Windows, `~/.local/share`
//! on Linux, `~/Library/Application Support` on macOS), and finally the home
//! dir again as a fallback. The real row schemas and migrations are translated
//! to Rust in a later slice; for now this module opens the existing file and
//! exposes the handful of reads the bootstrap needs.

use std::env;
use std::path::PathBuf;

use rusqlite::Connection;

pub mod tree;
pub mod write;

/// Directory name that holds the Trilium data files (matches `DIR_NAME` in the server).
const DATA_DIR_NAME: &str = "trilium-data";

/// Candidates for the database file inside the Trilium data directory.
const DB_FILE_CANDIDATES: [&str; 2] = ["document.db", "database.db"];

/// The current user's home directory: `USERPROFILE` on Windows, `HOME` elsewhere.
fn home_dir() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
}

/// OS convention for where desktop apps store their data. Mirrors
/// `getPlatformAppDataDir` in the server.
fn platform_app_data_dir() -> Option<PathBuf> {
    if env::consts::OS == "windows" {
        return env::var_os("APPDATA").map(PathBuf::from);
    }
    home_dir().map(|home| match env::consts::OS {
        "linux" => home.join(".local/share"),
        "macos" => home.join("Library/Application Support"),
        _ => return home,
    })
}

/// Resolve the Trilium data directory with the same priority as the real
/// server. Returns `None` only when no home directory is knowable.
fn data_dir() -> Option<PathBuf> {
    // Case A: explicit override.
    if let Some(dir) = env::var_os("TRILIUM_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }

    let home = home_dir()?;
    let home_trilium = home.join(DATA_DIR_NAME);

    // Case B: a `trilium-data` folder lives directly in the home dir.
    if home_trilium.exists() {
        return Some(home_trilium);
    }

    // Case C: an app-data folder is already present; put `trilium-data` under it.
    if let Some(app_data) = platform_app_data_dir() {
        let candidate = app_data.join(DATA_DIR_NAME);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // Case D: fall back to the home-dir location.
    Some(home_trilium)
}

/// Open the Trilium database if a file exists. `Ok(None)` means no data dir or
/// no known database file could be found; the caller then runs on mock data.
pub fn open() -> rusqlite::Result<Option<Connection>> {
    // `TRILIUM_DOCUMENT_PATH` names a specific database file outright.
    if let Some(path) = env::var_os("TRILIUM_DOCUMENT_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Connection::open(&path).map(Some);
        }
        return Ok(None);
    }

    let Some(dir) = data_dir() else {
        return Ok(None);
    };

    for name in DB_FILE_CANDIDATES {
        let path = dir.join(name);
        if path.exists() {
            return Connection::open(&path).map(Some);
        }
    }
    Ok(None)
}

/// One attachment row as the client's `FAttachmentRow` (superset) expects it,
/// from the `attachments` table joined with its blob for `contentLength`.
pub struct AttachmentInfo {
    pub attachment_id: String,
    pub owner_id: String,
    pub role: String,
    pub mime: String,
    pub title: String,
    pub position: i64,
    pub blob_id: Option<String>,
    pub is_protected: bool,
    pub content_length: i64,
    pub date_modified: String,
    pub utc_date_modified: String,
    pub utc_date_scheduled_for_erasure_since: Option<String>,
}

impl AttachmentInfo {
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(AttachmentInfo {
            attachment_id: row.get(0)?,
            owner_id: row.get(1)?,
            role: row.get(2)?,
            mime: row.get(3)?,
            title: row.get(4)?,
            content_length: row.get(5)?,
            position: row.get(6)?,
            blob_id: row.get(7)?,
            is_protected: row.get::<_, i64>(8)? != 0,
            date_modified: row.get(9)?,
            utc_date_modified: row.get(10)?,
            utc_date_scheduled_for_erasure_since: row.get(11)?,
        })
    }
}

/// The non-deleted attachments of a note, ordered by position — mirrors
/// `BNote.getAttachments()`.
pub fn get_note_attachments(conn: &Connection, note_id: &str) -> rusqlite::Result<Vec<AttachmentInfo>> {
    let mut stmt = conn.prepare(
        "SELECT a.attachmentId, a.ownerId, a.role, a.mime, a.title, \
                LENGTH(b.content) AS contentLength, a.position, a.blobId, a.isProtected, \
                a.dateModified, a.utcDateModified, a.utcDateScheduledForErasureSince \
         FROM attachments a JOIN blobs b USING (blobId) \
         WHERE a.ownerId = ?1 AND a.isDeleted = 0 ORDER BY a.position",
    )?;
    let rows = stmt.query_map([note_id], AttachmentInfo::from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Record that a note was recently visited (`POST /recent-notes`). `noteId` is
/// the primary key, so visiting again overwrites with the fresh path/timestamp.
pub fn add_recent_note(conn: &Connection, note_id: &str, note_path: &str, utc_date_created: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO recent_notes (noteId, notePath, utcDateCreated) VALUES (?1, ?2, ?3)",
        rusqlite::params![note_id, note_path, utc_date_created],
    )?;
    Ok(())
}

/// Delete recent-note rows older than `cut_off` (inclusive window like the real
/// route). Mirrors the original's opportunistic cleanup.
pub fn delete_old_recent_notes(conn: &Connection, cut_off_utc: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM recent_notes WHERE utcDateCreated < ?1",
        [cut_off_utc],
    )?;
    Ok(())
}

/// A note's timestamps, as the `notes/{id}/metadata` route returns them.
pub struct NoteTimestamps {
    pub date_created: String,
    pub utc_date_created: String,
    pub date_modified: String,
    pub utc_date_modified: String,
}

/// The creation/modification timestamps of a (non-deleted) note.
pub fn get_note_metadata(conn: &Connection, note_id: &str) -> Option<NoteTimestamps> {
    conn.query_row(
        "SELECT dateCreated, utcDateCreated, dateModified, utcDateModified \
         FROM notes WHERE noteId = ?1 AND isDeleted = 0",
        [note_id],
        |row| {
            Ok(NoteTimestamps {
                date_created: row.get(0)?,
                utc_date_created: row.get(1)?,
                date_modified: row.get(2)?,
                utc_date_modified: row.get(3)?,
            })
        },
    )
    .ok()
}

/// Count the relations that target `note_id` from non-search source notes —
/// mirrors `getFilteredBacklinks().length` in `note_map.ts`.
pub fn get_backlink_count(conn: &Connection, note_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) \
         FROM attributes a JOIN notes n ON a.noteId = n.noteId \
         WHERE a.type = 'relation' AND a.value = ?1 AND a.isDeleted = 0 \
           AND n.type != 'search' AND n.isDeleted = 0",
        [note_id],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

/// The `#icon` label value of a note, if it has one.
pub fn get_note_icon(conn: &Connection, note_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM attributes \
         WHERE noteId = ?1 AND type = 'label' AND name = 'icon' AND isDeleted = 0 LIMIT 1",
        [note_id],
        |row| row.get(0),
    )
    .ok()
}

/// Notes a user has recently visited (the empty-query branch of `autocomplete`),
/// newest first, excluding the active note — mirrors `getRecentNotes` in
/// `autocomplete.ts`. Returns `(note_id, note_path)`.
pub fn get_recent_notes(conn: &Connection, active_note_id: &str) -> Vec<(String, String)> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT rn.noteId, rn.notePath \
         FROM recent_notes rn JOIN notes USING (noteId) \
         WHERE notes.isDeleted = 0 AND notes.noteId != ?1 \
         ORDER BY rn.utcDateCreated DESC LIMIT 200",
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(rows) = stmt.query_map([active_note_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) {
        for row in rows.flatten() {
            out.push(row);
        }
    }
    out
}

/// Resolve a simple label search of the form `#labelA #labelB ... #!excluded`
/// into matching (non-deleted) note ids. A plain `#name` requires the note to
/// carry that label; `#!name` requires it to be absent. Notes matching multiple
/// positive labels must carry all of them. This is a small stand-in for the full
/// search engine — enough for the `#workspace #!template` workspace switcher.
pub fn search_notes_by_label_query(conn: &Connection, query: &str) -> Vec<String> {
    let (positive, mut negative): (Vec<String>, Vec<String>) = query
        .split_whitespace()
        .fold((Vec::new(), Vec::new()), |(mut pos, mut neg), token| {
            let token = token.trim().strip_prefix('#').unwrap_or(token.trim());
            if let Some(name) = token.strip_prefix('!') {
                if !name.is_empty() {
                    neg.push(name.to_string());
                }
            } else if !token.is_empty() {
                pos.push(token.to_string());
            }
            (pos, neg)
        });

    if positive.is_empty() {
        return Vec::new();
    }

    // Require the note to carry every positive label.
    let placeholders = positive.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let mut sql = format!(
        "SELECT n.noteId FROM notes n WHERE n.isDeleted = 0 AND n.noteId IN ( \
           SELECT noteId FROM attributes WHERE type = 'label' AND isDeleted = 0 \
           AND name IN ({placeholders}) \
           GROUP BY noteId HAVING COUNT(DISTINCT name) = {}",
        positive.len()
    );

    let mut params: Vec<String> = positive;
    if !negative.is_empty() {
        negative.sort();
        negative.dedup();
        let neg = negative.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        sql.push_str(&format!(
            " AND n.noteId NOT IN ( \
               SELECT noteId FROM attributes WHERE type = 'label' AND name IN ({neg}) AND isDeleted = 0)"
        ));
        params.extend(negative);
    }
    sql.push(')');

    let mut out = Vec::new();
    let params_ref: Vec<&str> = params.iter().map(String::as_str).collect();
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return out;
    };
    if let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(params_ref), |row| row.get::<_, String>(0)) {
        for note_id in rows.flatten() {
            out.push(note_id);
        }
    }
    out
}

/// Whether the named table exists. Used as a lightweight "is the database
/// initialized" check before reading rows from it.
pub fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |_| Ok(()),
    )
    .is_ok()
}

/// Read a single named option from the `options` table.
pub fn get_option(conn: &Connection, name: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM options WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .ok()
}

/// Read every option as `(name, value)` pairs. The client expects the options
/// endpoint as a flat map (`Record<string, OptionValue>`), so callers turn this
/// into a JSON object.
pub fn get_all_options(conn: &Connection) -> Vec<(String, String)> {
    let Ok(mut stmt) = conn.prepare("SELECT name, value FROM options") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))) {
        for row in rows.flatten() {
            out.push(row);
        }
    }
    out
}

/// Upsert a single option value (`options.setOption`), preserving the existing
/// `isSynced` flag when the row already exists — password options are synced.
pub fn set_option(conn: &Connection, name: &str, value: &str) -> rusqlite::Result<()> {
    let utc = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3fZ").to_string();
    conn.execute(
        "INSERT INTO options (name, value, isSynced, utcDateModified) VALUES (?1, ?2, 1, ?3) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value, utcDateModified = excluded.utcDateModified",
        rusqlite::params![name, value, utc],
    )?;
    Ok(())
}

/// The greatest `entity_change` id, optionally filtered to synced rows. Mirrors
/// the `maxEntityChangeIdAtLoad` / `maxEntityChangeSyncIdAtLoad` bootstrap values.
pub fn max_entity_change_id(conn: &Connection, synced_only: bool) -> i64 {
    let sql = if synced_only {
        "SELECT COALESCE(MAX(id), 0) FROM entity_changes WHERE isSynced = 1"
    } else {
        "SELECT COALESCE(MAX(id), 0) FROM entity_changes"
    };
    conn.query_row(sql, [], |row| row.get(0)).unwrap_or(0)
}

/// One row of `notes`, enough for the dispatcher's note routes and blob lookup.
pub struct NoteInfo {
    pub note_id: String,
    pub title: String,
    pub is_protected: bool,
    pub note_type: String,
    pub mime: String,
    pub blob_id: Option<String>,
}

/// Look up a single (non-deleted) note by id; `None` when absent or deleted.
pub fn get_note(conn: &Connection, note_id: &str) -> Option<NoteInfo> {
    conn.query_row(
        "SELECT noteId, title, isProtected, type, mime, blobId FROM notes \
         WHERE noteId = ?1 AND isDeleted = 0",
        [note_id],
        |row| {
            Ok(NoteInfo {
                note_id: row.get(0)?,
                title: row.get(1)?,
                is_protected: row.get::<_, i64>(2)? != 0,
                note_type: row.get(3)?,
                mime: row.get(4)?,
                blob_id: row.get(5)?,
            })
        },
    )
    .ok()
}

/// A note's content blob as the client's `FBlobRow` expects it.
pub struct BlobInfo {
    pub blob_id: String,
    pub content: String,
    pub content_length: i64,
    pub date_modified: String,
    pub utc_date_modified: String,
}

/// Read the blob behind a note (via `notes.blobId` -> `blobs`). `None` when the
/// note or its blob is missing.
pub fn get_note_blob(conn: &Connection, note_id: &str) -> Option<BlobInfo> {
    conn.query_row(
        "SELECT b.blobId, b.content, b.dateModified, b.utcDateModified FROM notes n \
         JOIN blobs b ON n.blobId = b.blobId \
         WHERE n.noteId = ?1 AND n.isDeleted = 0",
        [note_id],
        |row| {
            let content: Option<String> = row.get(1)?;
            let content = content.unwrap_or_default();
            let content_length = content.len() as i64;
            Ok(BlobInfo {
                blob_id: row.get(0)?,
                content,
                content_length,
                date_modified: row.get(2)?,
                utc_date_modified: row.get(3)?,
            })
        },
    )
    .ok()
}

/// Read the value of a `label`-type attribute on a note (e.g. the `appThemeBase`
/// label on the theme note). Used by the bootstrap to resolve theme handling.
pub fn get_label_value(conn: &Connection, note_id: &str, name: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM attributes WHERE noteId = ?1 AND type = 'label' AND name = ?2 AND isDeleted = 0",
        rusqlite::params![note_id, name],
        |row| row.get(0),
    )
    .ok()
}

/// Find the (first) note carrying a `label` whose value equals `value` — e.g. the
/// `#appTheme` label naming the active theme note. `None` when no such note exists.
pub fn get_note_id_by_label(conn: &Connection, name: &str, value: &str) -> Option<String> {
    conn.query_row(
        "SELECT noteId FROM attributes \
         WHERE type = 'label' AND name = ?1 AND value = ?2 AND isDeleted = 0 LIMIT 1",
        rusqlite::params![name, value],
        |row| row.get(0),
    )
    .ok()
}

/// Every note carrying a `label` (e.g. `appCss`), in the order the client's
/// `attributes.getNotesWithLabel` would collect them. Note ids only.
pub fn get_note_ids_with_label(conn: &Connection, name: &str) -> Vec<String> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT noteId FROM attributes WHERE type = 'label' AND name = ?1 AND isDeleted = 0",
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(rows) = stmt.query_map([name], |row| row.get::<_, String>(0)) {
        for note_id in rows.flatten() {
            out.push(note_id);
        }
    }
    out
}