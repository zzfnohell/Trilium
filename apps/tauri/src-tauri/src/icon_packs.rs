//! Built-in icon-pack support for the bootstrap payload.
//!
//! The real server's `getIconConfig` builds `iconPackCss` — an inline `<style>`
//! the client injects before first paint (`loadIcons` in `index.ts`) — and
//! `iconRegistry`, the icon-picker catalogue. The baseline pack every Trilium
//! DB relies on is Boxicons: one `@font-face` for `fonts/boxicons.woff2`, a
//! `.bx` base class, and one pseudo-element rule per glyph. Without the CSS the
//! `bx bx-*` classes on tree notes, buttons and content carry no `content` or
//! `font-family`, so every icon renders as a blank placeholder.
//!
//! Custom user packs (`#iconPack` notes) are a later slice; this module mirrors
//! the built-in half of `getIconConfig` exactly, including the manifest the
//! server embeds.

use serde_json::{json, Value};

/// The same Boxicons v2 manifest trilium-core embeds at build time
/// (`services/icon_pack_boxicons-v2.json`), re-read here so the generated CSS
/// and the icon picker draw from one source of truth.
const BOXICONS_MANIFEST: &str =
    include_str!("../../../../packages/trilium-core/src/services/icon_pack_boxicons-v2.json");

const BUILTIN_PREFIX: &str = "bx";
const BUILTIN_FONT_FAMILY: &str = "boxicons";
const BUILTIN_FONT_FILE: &str = "fonts/boxicons.woff2";
const BUILTIN_FONT_FORMAT: &str = "woff2";
const BUILTIN_TITLE: &str = "Boxicons";
const BUILTIN_ICON: &str = "bx bx-package";

/// The Boxicons manifest parsed once; `None` only if the embedded JSON is
/// malformed, which would be a build-time regression caught by the server too.
fn manifest() -> &'static Value {
    static MANIFEST: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    MANIFEST.get_or_init(|| {
        serde_json::from_str(BOXICONS_MANIFEST).expect("embedded boxicons manifest is valid JSON")
    })
}

/// The stylesheet served through `iconPackCss`, matching `generateCss` for the
/// built-in pack: an `@font-face` pointing at the client's static font, the
/// `.bx` layer class, and a `::before` content rule per icon.
pub fn builtin_icon_pack_css(asset_path: &str) -> String {
    let font_url = format!("{asset_path}/{BUILTIN_FONT_FILE}");
    let mut css = format!(
        "@font-face {{\
         \n    font-family: '{BUILTIN_FONT_FAMILY}';\
         \n    font-weight: normal;\
         \n    font-style: normal;\
         \n    src: url('{font_url}') format('{BUILTIN_FONT_FORMAT}');\
         \n}}\n\n.{BUILTIN_PREFIX} {{\
         \n    font-family: '{BUILTIN_FONT_FAMILY}' !important;\
         \n    font-weight: normal;\
         \n    font-style: normal;\
         \n    font-variant: normal;\
         \n    line-height: 1;\
         \n    text-rendering: auto;\
         \n    display: inline-block;\
         \n    text-transform: none;\
         \n    -webkit-font-smoothing: antialiased;\
         \n    -moz-osx-font-smoothing: grayscale;\
         \n}}\n\n"
    );

    if let Some(icons) = manifest().get("icons").and_then(Value::as_object) {
        let mut keys: Vec<&String> = icons.keys().collect();
        keys.sort();
        for key in keys {
            if let Some(glyph) = icons[key].get("glyph").and_then(Value::as_str) {
                css.push_str(&format!(".{BUILTIN_PREFIX}.{key}::before {{ content: \"{glyph}\"; }}\n"));
            }
        }
    }

    css
}

/// The `iconRegistry` the icon picker and glyph resolver read: one source with
/// every manifest icon as `{ id: "bx <name>", terms }`.
pub fn icon_registry() -> Value {
    let icons: Vec<Value> = manifest()
        .get("icons")
        .and_then(Value::as_object)
        .map(|icons| {
            let mut keys: Vec<&String> = icons.keys().collect();
            keys.sort();
            keys.iter()
                .filter_map(|key| {
                    let terms = icons[*key].get("terms").and_then(Value::as_array)?;
                    Some(json!({
                        "id": format!("{BUILTIN_PREFIX} {key}"),
                        "terms": terms
                    }))
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "sources": [{
            "prefix": BUILTIN_PREFIX,
            "name": BUILTIN_TITLE,
            "icon": BUILTIN_ICON,
            "icons": icons
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_embeds_font_face_and_every_manifest_glyph() {
        let css = builtin_icon_pack_css("");
        assert!(css.contains("@font-face {"));
        assert!(css.contains("font-family: 'boxicons';"));
        assert!(css.contains("src: url('/fonts/boxicons.woff2') format('woff2');"));
        assert!(css.contains(".bx {"));
        assert!(css.contains("font-family: 'boxicons' !important;"));
        // One `::before` content rule per manifest icon.
        let rule_count = css.matches("::before { content:").count();
        let icon_count = manifest().get("icons").and_then(Value::as_object).unwrap().len();
        assert_eq!(rule_count, icon_count);
        // A concrete rule the UI depends on.
        assert!(css.contains(".bx.bx-file::before { content: \""));
    }

    #[test]
    fn css_uses_asset_path_for_shared_notebook_style_url() {
        let css = builtin_icon_pack_css("/app-dist");
        assert!(css.contains("src: url('/app-dist/fonts/boxicons.woff2') format('woff2');"));
    }

    #[test]
    fn registry_lists_boxicons_once_with_full_catalogue() {
        let registry = icon_registry();
        let sources = registry["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 1);
        let source = &sources[0];
        assert_eq!(source["prefix"], "bx");
        assert_eq!(source["name"], "Boxicons");
        let icons = source["icons"].as_array().unwrap();
        assert_eq!(icons.len(), 1635);
        // Keys are already prefixed (`bx-child`, `bxs-balloon`), so ids are `bx bx-child` etc.
        assert!(icons.iter().all(|icon| icon["id"].as_str().unwrap().starts_with("bx ")));
        assert!(icons.iter().all(|icon| icon["terms"].is_array()));
    }
}