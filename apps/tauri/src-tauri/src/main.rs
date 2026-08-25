#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Trilium Notes — Tauri shell (IPC-backed, 迁移步骤 2)
//
// 目标：把后端从 sidecar / HTTP 改为 Tauri 自身的 IPC，替代 Electron desktop
// 的 `window.electronApi` bridge 与 renderer<->server WebSocket：
//   - 数据面：client 用 `invoke()` 调 Rust `tauri::command`（取代内部 REST）
//   - 同步面：Rust 端用 Tauri 事件广播 `frontend-update`（取代 ws.ts 的 WS 通道）
//   - 窗口：内嵌打包的 client（取代加载 `http://localhost:8080`），不再 spawn server
//
// 这是垂直切片的第一块：证明 `invoke` 双向通道 + 读取既有数据文件可行。

mod commands;
mod db;
mod messages;

use std::sync::Mutex;

use tauri::WebviewUrl;

/// 应用级状态：持有对既有 database.db 的打开连接（若存在）。
pub struct AppState {
    pub db: Mutex<Option<rusqlite::Connection>>,
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            db: Mutex::new(db::open().or_describe()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap::bootstrap,
            commands::bootstrap::ping_test
        ])
        .setup(|app| {
            // 加载打包进 tauri 的 client 目录（frontendDist），不再依赖外部 server。
            let _window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::App("index.html".into()),
            )
            .title("Trilium Notes — Tauri")
            .inner_size(1280.0, 840.0)
            .min_inner_size(800.0, 600.0)
            .build()?;

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