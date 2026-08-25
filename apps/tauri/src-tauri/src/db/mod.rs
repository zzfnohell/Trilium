//! Best-effort access to the existing Trilium SQLite database.
//!
//! The desktop app keeps its data in the Trilium data directory (moved at
//! runtime by `TRILIUM_DATA_DIR`) or defaults to `~/.trilium-data`. The real
//! row schemas and migrations are translated to Rust in a later slice; for now
//! this module only proves that the existing file can be opened.

use std::env;
use std::path::PathBuf;

use rusqlite::Connection;

/// Candidates for the database file inside the Trilium data directory.
const DB_FILE_CANDIDATES: [&str; 2] = ["document.db", "database.db"];

/// Resolve the Trilium data directory from `TRILIUM_DATA_DIR`, falling back to
/// `~/.trilium-data`. Returns `None` when neither is knowable.
fn data_dir() -> Option<PathBuf> {
    env::var_os("TRILIUM_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".trilium-data")))
}

/// Open the Trilium database if a file exists. `Ok(None)` means no data dir or
/// no known database file could be found; the caller then runs on mock data.
pub fn open() -> rusqlite::Result<Option<Connection>> {
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