#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Trilium Notes — Tauri shell (IPC-backed, 迁移步骤 2)
//
// 目标：把后端从 sidecar / HTTP 改为 Tauri 自身的 IPC，替代 Electron desktop
// 的 `window.electronApi` bridge 与 renderer<->server WebSocket：
//   - 数据面：client 用 `invoke()` 调 Rust `tauri::command`（取代内部 REST）
//   - 同步面：Rust 端用 Tauri 事件广播 WebSocket 消息（取代 ws.ts 的 WS 通道）
//   - 窗口：内嵌打包的 client（取代加载 `http://localhost:8080`），不再 spawn server
//
// 真实 client 通过 `window.electronApi` 检测它跑在桌面（utils.isElectron()）。下面的
// 初始化脚本在页面脚本之前注入这个兼容对象：`ipc.invoke` 走 Tauri IPC，`ws` 走事件，
// `window/navigation/systemIntegration` 是让 client 不崩的桩。数据面 client 的
// `server.ts.ajax` 在存在 `electronApi` 时改走 `api` 命令，同步面 client 的 `ws.ts`
// 已经支持 `electronApi.ws`。

mod commands;
mod crypto;
mod db;
mod icon_packs;
mod messages;
mod services;

use std::sync::Mutex;

use tauri::{Manager, WebviewUrl};

/// 应用级状态：持有对既有 database.db 的打开连接（若存在）。
pub struct AppState {
    pub db: Mutex<Option<rusqlite::Connection>>,
}

/// Injects the `window.electronApi` shape the Trilium client expects. `ipc.invoke`
/// and `ws` are real bridges to this Rust shell; the window/navigation/systemIntegration
/// members are no-op stubs so the client's desktop init path runs without error.
const ELECTRON_BRIDGE_JS: &str = r#"
;(function () {
    const noop = function(){};
    window.electronApi = {
        ipc: {
            invoke: function (command, args) {
                return window.__TAURI__.core.invoke(command, args);
            }
        },
        ws: {
            send: function (message) {
                return window.__TAURI__.core.invoke("ws_send", { message: message });
            },
            onMessage: function (cb) {
                window.__TAURI__.event.listen("trilium-ws-message", function (event) {
                    cb(event.payload);
                });
            }
        },
        window: {
            // The client's desktop init path reads and writes the full ElectronWindowApi.window
            // contract during startup (syncNativeWindowWithTheme, zoom, full-screen, window state).
            // Absent methods throw a synchronous TypeError there, which aborts the desktop module
            // evaluation and leaves the page stuck on the hidden body. Provide every method: writes
            // are no-ops, reads return the value that keeps the local renderer on its defaults.
            setZoomFactor: noop,
            getZoomFactor: function () { return 1.0; },
            setNativeThemeSource: noop,
            setTitleBarOverlay: noop,
            setWindowButtonPosition: noop,
            onEnterFullScreen: noop,
            onLeaveFullScreen: noop,
            isFullScreen: function () { return false; },
            setFullScreen: noop,
            minimizeWindow: noop,
            maximizeWindow: noop,
            unmaximizeWindow: noop,
            isMaximized: function () { return false; },
            closeWindow: noop,
            createExtraWindow: noop,
            isAlwaysOnTop: function () { return false; },
            setAlwaysOnTop: noop,
            toggleDevTools: noop,
            isDevToolsDocked: function () { return false; },
            setBackgroundMaterial: noop,
            setVibrancy: noop,
            reloadAllWindows: function(){ window.location.reload(); },
            restartApp: function(){ window.location.reload(); },
            toggleAllWindows: noop,
            clearCache: function () { return Promise.resolve(); },
            showWindow: noop,
            reportStartupMetric: noop,
            onGlobalShortcut: noop,
            onOpenInSameTab: noop,
            onDevToolsDockChanged: noop
        },
        navigation: {
                    clearNavigationHistory: noop,
                    // The tab history buttons call these synchronously during render; a missing
                    // method throws "is not a function" and aborts the layout. There is no real
                    // browser history in this shell — report that nothing can unwind.
                    navigationCanGoBack: function () { return false; },
                    navigationCanGoForward: function () { return false; },
                    navigationGetAllEntries: function () { return []; },
                    navigationGetActiveIndex: function () { return -1; },
                    navigationLength: function () { return 0; },
                    navigationGoToIndex: noop,
                    // `TabHistoryNavigationButtons` subscribes on mount; there is no history to
                    // notify about, so swallow the subscription and clear any listeners on teardown.
                    onDidNavigate: noop,
                    onDidNavigateInPage: noop,
                    removeDidNavigateListeners: noop
                },
                contextMenu: {
                    // The editor's native context menu wires itself to Electron's `contextMenu`.
                    // There is no native menu here, so swallow the registration request.
                    onContextMenu: noop
                },
        systemIntegration: {
            reloadTray: noop,
            reapplyLaunchOnStartup: noop
        }
    };
    // Forward renderer errors and unhandled rejections to the Rust side so they
    // surface on the terminal — without an attached devtools console, the blank
    // page case has no other way of reporting what failed.
    function fwd(kind, message) {
        try {
            window.__TAURI__.core.invoke("log_frontend_error", { kind: kind, message: String(message).slice(0, 2000) });
        } catch (e) {}
    }
    window.addEventListener("error", function (e) { fwd("error", (e && (e.message || (e.error && e.error.stack))) || "unknown error"); });
    window.addEventListener("unhandledrejection", function (e) { fwd("unhandledrejection", (e && e.reason && e.reason.stack) || (e && e.reason) || "unknown rejection"); });
    // Route the client's own reported failures (e.g. "Critical error occurred" on appContext.start)
    // to the terminal too — the toast that carries them may itself fail to render on a blank page.
    try {
        var origError = console.error.bind(console);
        console.error = function () {
            origError.apply(null, arguments);
            try { fwd("console-error", Array.prototype.map.call(arguments, String).join(" ").slice(0, 2000)); } catch (x) {}
        };
    } catch (e) {}

    // Intercept stylesheet links for `api/fonts` and `api/notes/download/{id}` — these are normally
    // fetched over HTTP, but in this shell they are loaded on a `http://tauri.localhost/api/...` URL
    // that no server answers (a native 404 the theme code would treat as a load failure and roll
    // back). Instead we fetch the bytes over IPC and serve them as a `blob:` URL. The `api/...`
    // href is never written into the DOM, so the browser never issues the doomed request — the blob
    // URL is committed once the IPC response lands, which fires the stylesheet's `load` event that
    // the client waits on. Covers the three client call sites: property `link.href = ...`
    // (`font.ts`, `theme.ts`) and jQuery `setAttribute` (`glob.ts`).
    (function () {
        var origCreate = document.createElement.bind(document);
        var apiPath = function (url) {
            if (typeof url !== 'string') return null;
            var i = url.indexOf('/api/');
            var base = i >= 0 ? url.slice(i + 5) : (url.indexOf('api/') === 0 ? url.slice(4) : null);
            if (base === null) return null;
            return base.split('?')[0]; // drop a cache-busting query like `?v=N`
        };
        var loadCss = function (link, path) {
            if (link.__triliumApiServed) return; // already diverted (or waiting) — do not re-fire
            link.__triliumApiServed = true;
            window.__TAURI__.core.invoke('get_api_resource', { path: path })
                .then(function (css) {
                    // The blob URL is not an `api/...` path, so it passes through our setAttribute.
                    var url = URL.createObjectURL(new Blob([css], { type: 'text/css' }));
                    link.setAttribute('href', url);
                })
                .catch(function (err) {
                    fwd('resource-intercept', 'failed to fetch ' + path + ': ' + String(err));
                });
        };

        document.createElement = function (tag, options) {
            var el = origCreate(tag, options);
            if (String(tag).toLowerCase() !== 'link') return el;

            var origSetAttr = el.setAttribute.bind(el);
            // The original IDL setter is captured here and re-applied for non-`api/` hrefs. The
            // client's bundled assets (e.g. `bootstrap-*.css` injected by Vite's runtime) set
            // `link.href = ...`; if we swallowed that without writing it back to the DOM, the
            // browser would never fire the stylesheet's load event and the app's await on it
            // would hang (blank window). Only `api/...` URLs are diverted to the IPC fetch.
            Object.defineProperty(el, 'href', {
                get: function () {
                    var v = el.getAttribute('href');
                    return v == null ? '' : v;
                },
                set: function (v) {
                    var p = apiPath(String(v));
                    if (p) {
                        loadCss(el, p);
                        return; // keep the DOM clean until the blob URL lands
                    }
                    origSetAttr('href', v);
                }
            });
            el.setAttribute = function (name, value) {
                if (name === 'href') {
                    var p = apiPath(String(value));
                    if (p) {
                        loadCss(el, p);
                        return; // stash nothing in the DOM yet; blob URL lands later
                    }
                }
                return origSetAttr(name, value);
            };
            return el;
        };

        // Some DOM paths build the link outside our createElement hook (jQuery's parseHTML,
        // document.createElementNS, templates) — the scheduled fire would then leave a raw
        // `…/api/…` href that the protocol can never answer. Sweep the document a few times
        // early on and divert any such link we have not already served.
        var sweep = function () {
            var links = Array.prototype.slice.call(document.querySelectorAll('link[href]'));
            for (var i = 0; i < links.length; i++) {
                var href = links[i].href || '';
                if (!(href.indexOf('/api/') >= 0)) continue;
                var path = apiPath(href);
                if (path) loadCss(links[i], path);
            }
        };
        document.addEventListener('DOMContentLoaded', function () {
            setTimeout(sweep, 0);
            setTimeout(sweep, 2000);
            setTimeout(sweep, 8000);
        });
    })();

    // Periodic renderer state dumps at a few ages — a single 4s snapshot says nothing about whether
    // the desktop module (which imports note-autocomplete etc. over the network) finishes later.
    function dumpState() {
        try {
            var kids = Array.prototype.slice.call(document.body.children || []);
            var kidDesc = kids.slice(0, 8).map(function (k) { return k.tagName + "." + (k.className || "").toString().split(" ").slice(0,3).join("."); });
            var links = Array.prototype.slice.call(document.querySelectorAll('link[rel=stylesheet]'));
            // Blob-URL stylesheets (the diverted api/fonts + note css) never expose cssRules in this
            // shell, so they are not loading failures — exclude them from the failing list.
            var failing = links.filter(function (l) { return !(l.href && l.href.indexOf('blob:') === 0) && !(l.sheet && l.sheet.cssRules && l.sheet.cssRules.length > 0); });
            fwd("state", JSON.stringify({
                readyState: document.readyState,
                bodyDisplay: document.body.style.display,
                bodyChildren: kids.length,
                kidDesc: kidDesc,
                globSet: !!(window.glob && window.glob.theme),
                links: links.length,
                failingLinks: failing.map(function (l) { return l.href; }),
                hasTree: !!document.querySelector('.tree, #left-pane, .note-tree'),
                textLen: document.body.innerText.length,
                hasCritical: !!document.querySelector('.toast-critical, .toast-persistent'),
                iconPackCssLen: (function () {
                    var styles = Array.prototype.slice.call(document.head.querySelectorAll('style'));
                    for (var i = 0; i < styles.length; i++) {
                        var t = styles[i].textContent || '';
                        if (t.indexOf("font-family: 'boxicons'") >= 0) return t.length;
                    }
                    return 0;
                })(),
                iconFontLoaded: !!(document.fonts && document.fonts.status === 'loaded' && document.fonts.check('20px boxicons')),
                sample: document.body.innerText.slice(0, 150)
            }));
        } catch (e) {}
    }
    window.setTimeout(dumpState, 3000);
    window.setTimeout(dumpState, 8000);
    window.setTimeout(dumpState, 15000);
})();
"#;

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            db: Mutex::new(db::open().or_describe()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap::bootstrap,
            commands::bootstrap::ping_test,
            commands::bootstrap::log_frontend_error,
            commands::api::api,
            commands::api::get_api_resource,
            commands::ws::ws_send
        ])
        .setup(|app| {
            // 加载打包进 tauri 的 client 目录（frontendDist），不再依赖外部 server。
            // initialization_script 在页面脚本之前注入 electronApi 桥，供 client 检测并通话。
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::App("index.html".into()),
            )
            .title("Trilium Notes — Tauri")
            .inner_size(1280.0, 840.0)
            .min_inner_size(800.0, 600.0)
            .initialization_script(ELECTRON_BRIDGE_JS)
            .build()?;

            // Dev diagnostic: confirm the real bootstrap read once the DB opens.
            {
                let state = app.state::<AppState>();
                let guard = state.db.lock().expect("db lock");
                if let Some(conn) = guard.as_ref() {
                    let version = db::get_option(conn, "app.version").unwrap_or_default();
                    let note_count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM notes WHERE isDeleted = 0", [], |r| r.get(0))
                        .unwrap_or(-1);
                    eprintln!(
                        "[trilium-tauri] db opened: app.version={version}, undeleted notes={note_count}"
                    );
                }
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error building tauri application");
}

/// Helper to turn an `open()` failure into a logged skip rather than aborting.
trait OptionOrDescribe<T> {
    fn or_describe(self) -> Option<T>;
}

impl<T, E: std::fmt::Display> OptionOrDescribe<T> for Result<Option<T>, E> {
    fn or_describe(self) -> Option<T> {
        match self {
            Ok(opt) => opt,
            Err(err) => {
                eprintln!("[trilium-tauri] could not open database: {err}; running on mock data");
                None
            }
        }
    }
}