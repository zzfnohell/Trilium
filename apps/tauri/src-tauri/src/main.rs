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
mod db;
mod messages;

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
            reloadAllWindows: function(){ window.location.reload(); },
            restartApp: function(){ window.location.reload(); },
            reportStartupMetric: noop,
            onGlobalShortcut: noop,
            onOpenInSameTab: noop,
            onEnterFullScreen: noop,
            onLeaveFullScreen: noop,
            isDevToolsDocked: function(){ return false; },
            onDevToolsDockChanged: noop
        },
        navigation: {
            clearNavigationHistory: noop
        },
        systemIntegration: {
            reloadTray: noop,
            reapplyLaunchOnStartup: noop
        }
    };
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
            commands::api::api,
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