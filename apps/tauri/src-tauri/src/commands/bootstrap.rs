//! The `bootstrap` command — first IPC contact between the client and backend.
//!
//! It replaces the old `GET /bootstrap` request. The desktop renderer is the
//! application itself (in Electron this is the `trilium-app://` protocol, tagged
//! `isElectronRenderer`), which in the real server skips the setup/password/login
//! pre-auth gates and receives the full payload while effectively logged in. The
//! Tauri window plays that same role, so fields that depend on a web session
//! (login screen, CSRF, TOTP/SSO) are not applicable here.
//!
//! The returned JSON mirrors the full `BootstrapDefinition` the real client
//! reads into `window.glob`. Real values are read from the existing Trilium
//! database where they live; anything that cannot be known yet falls back to a
//! safe default that keeps the trusted local renderer booting.

use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::db;
use crate::messages;
use crate::AppState;

/// Fallback when the `app.version` option is missing.
const FALLBACK_VERSION: &str = "0.104.1";

/// The trusted desktop renderer always uses the desktop view (mirrors `getView`).
const DEVICE: &str = "desktop";

/// Built-in themes whose styling ships with the client. Any theme outside this
/// set is a note-served custom theme, whose CSS has to be fetched from the API.
const BUILTIN_THEMES: [&str; 6] = ["auto", "light", "dark", "next", "next-light", "next-dark"];
/// Locales rendered right-to-left, used to fill `currentLocale.rtl`.
const RTL_LOCALES: [&str; 4] = ["ar", "he", "fa", "ur"];

/// Map an OS to the `platform` names the client's bootstrap payload uses.
fn platform_name() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        "linux" => "linux",
        _ => "linux",
    }
}

/// Handles the client's first request. Stands in for `GET /bootstrap`.
#[tauri::command]
pub fn bootstrap(state: State<'_, AppState>) -> Value {
    let db_guard = state.db.lock().expect("db lock");
    let db: &Option<rusqlite::Connection> = &db_guard;

    let is_initialized = db
        .as_ref()
        .map(|conn| db::table_exists(conn, "options"))
        .unwrap_or(false);

    let options = db.as_ref().map(db::get_all_options).unwrap_or_default();
    let mut option_map = std::collections::HashMap::new();
    for (name, value) in &options {
        option_map.insert(name.clone(), value.clone());
    }
    let opt = |name: &str, fallback: &str| -> String {
        option_map.get(name).cloned().unwrap_or_else(|| fallback.to_string())
    };

    let trilium_version = opt("app.version", FALLBACK_VERSION);
    let theme = opt("theme", "next");
    // The active theme note (`#appTheme`), whose `appThemeBase` label names the
    // built-in theme family it derives from (see `getSharedBootstrapItems`).
    let theme_note_id = db
        .as_ref()
        .and_then(|conn| db::get_note_id_by_label(conn, "appTheme", &theme));
    let theme_base = theme_note_id
        .as_ref()
        .and_then(|note_id| db.as_ref().and_then(|conn| db::get_label_value(conn, note_id, "appThemeBase")))
        .map(Value::String)
        .unwrap_or(Value::Null);
    // Custom themes are served through the note-download route.
    let custom_theme_css_url = if !BUILTIN_THEMES.contains(&theme.as_str()) {
        theme_note_id.map(|note_id| Value::String(format!("api/notes/download/{note_id}")))
    } else {
        None
    };

    let instance_name = option_map
        .get("instanceName")
        .filter(|v| !v.is_empty())
        .map(|v| Value::String(v.clone()))
        .unwrap_or(Value::Null);

    // Locale id + whether it renders right-to-left, mirroring the client's Locale shape.
    let current_locale_id = opt("locale", "en");
    let is_rtl = RTL_LOCALES.contains(&current_locale_id.as_str());
    let current_locale = json!({
        "id": current_locale_id,
        "name": current_locale_id,
        "rtl": is_rtl
    });

    // CSS-injected by user notes tagged `#appCss` (order the real `getAppCssNoteIds` returns).
    let app_css_note_ids = db
        .as_ref()
        .map(|conn| db::get_note_ids_with_label(conn, "appCss"))
        .unwrap_or_default();

    // A Tauri window carries the OS native title bar by default; respect the user's option.
    let native_title_bar_visible = opt("nativeTitleBarVisible", "true") == "true";
    // Background material is not applied yet, so the capability is off regardless of the option.
    let supports_background_effects = false;

    let (max_change, max_change_synced) = match db.as_ref() {
        Some(conn) => (db::max_entity_change_id(conn, false), db::max_entity_change_id(conn, true)),
        None => (0, 0),
    };

    // The trusted desktop renderer always passes the setup/password/login gates, exactly like the
    // real server's `isElectronRenderer` path — there is no web session over a local IPC channel.
    let (has_setup, password_set, logged_in) = if is_initialized {
        (false, true, true)
    } else {
        (true, false, false)
    };

    json!({
        "dbInitialized": is_initialized,
        "syncInProgress": false,
        "hasExistingData": false,
        "setupAuthRequired": has_setup,
        "setupSecondFactorRequired": false,
        "passwordSet": password_set,
        "loggedIn": logged_in,
        "baseApiUrl": "api/",
        "assetPath": "",
        "theme": theme,
        "themeBase": theme_base,
        "customThemeCssUrl": custom_theme_css_url,
        "iconPackCss": "",
        "iconRegistry": {},
        "device": DEVICE,
        "csrfToken": "",
        "headingStyle": opt("headingStyle", "plain"),
        "layoutOrientation": opt("layoutOrientation", "vertical"),
        "platform": platform_name(),
        "isElectron": true,
        "isStandalone": false,
        "hasNativeTitleBar": native_title_bar_visible,
        "hasBackgroundEffects": supports_background_effects,
        "maxEntityChangeIdAtLoad": max_change,
        "maxEntityChangeSyncIdAtLoad": max_change_synced,
        "instanceName": instance_name,
        "appCssNoteIds": app_css_note_ids,
        "isDev": true,
        "isMainWindow": true,
        "isProtectedSessionAvailable": false,
        "triliumVersion": trilium_version,
        "appPath": "",
        "currentLocale": current_locale,
        "isRtl": is_rtl,
        "TRILIUM_SAFE_MODE": safe_mode_enabled(),
        "componentId": ""
    })
}

/// Whether the app was launched in safe mode (`TRILIUM_SAFE_MODE` set). Mirrors
/// `!!process.env.TRILIUM_SAFE_MODE` in the server bootstrap.
fn safe_mode_enabled() -> bool {
    std::env::var("TRILIUM_SAFE_MODE").map(|v| !v.is_empty()).unwrap_or(false)
}

/// Smoke-test command: emits a message over the frontend-update channel and
/// returns a trivial string so the round trip can be verified end to end.
#[tauri::command]
pub fn ping_test(app: AppHandle) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = messages::emit_to_frontend(&app, json!({ "type": "pong", "at": now }));
    "pong".to_string()
}