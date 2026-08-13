#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Trilium Notes — Tauri sidecar shell (POC 迁移步骤 1)
//
// 目标：让 Tauri (Rust) 壳在启动时自动拉起 Trilium 服务器进程（sidecar），
// 等待端口就绪后再创建 webview 加载客户端，并在应用退出时回收子进程。
// 这样不再要求用户手动 `pnpm server:start`。
//
// 服务器启动策略（按优先级）：
//   1. 环境变量 TRILIUM_NO_SPAWN="1"  → 不拉起，直接加载外部已运行的服务器
//   2. 端口已可连接（已有外部 server） → 直接复用，不再拉起
//   3. 默认                          → 用 TRILIUM_SERVER_CMD（若设置）否则
//                                      `pnpm --config.verify-deps-before-run=false server:start`
//                                      在仓库根目录拉起，等待就绪后开窗

use std::{
    fs::OpenOptions,
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use tauri::{Manager, RunEvent, WebviewUrl};

/// 持有 sidecar 子进程句柄，应用退出时 kill。
struct ServerChild(Mutex<Option<Child>>);

/// 服务器监听端口：TRILIUM_PORT，默认 8080。
fn server_port() -> u16 {
    std::env::var("TRILIUM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080)
}

fn is_ready(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn wait_ready(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if is_ready(port) {
            return true;
        }
        thread::sleep(Duration::from_millis(300));
    }
    false
}

/// 仓库根目录（CARGO_MANIFEST_DIR = apps/tauri/src-tauri → 上溯 3 级）。
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../../..");
    root.canonicalize().unwrap_or(root)
}

/// 解析环境变量 TRILIUM_SERVER_CMD 得到的 (program, args)。
fn parse_server_cmd(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split_whitespace();
    let program = parts.next().unwrap_or("pnpm").to_string();
    let args = parts.map(String::from).collect();
    (program, args)
}

/// 拉起服务器子进程。返回 None 表示无需/无法拉起。
fn spawn_server(port: u16) -> Option<Child> {
    if std::env::var("TRILIUM_NO_SPAWN").is_ok() {
        println!("[trilium-tauri] TRILIUM_NO_SPAWN set, not spawning server");
        return None;
    }
    if is_ready(port) {
        println!("[trilium-tauri] server already listening on port {port}, reusing it");
        return None;
    }

    let (program, args) = match std::env::var("TRILIUM_SERVER_CMD") {
        Ok(raw) => parse_server_cmd(&raw),
        Err(_) => (
            "pnpm".to_string(),
            vec![
                "--config.verify-deps-before-run=false".to_string(),
                "server:start".to_string(),
            ],
        ),
    };
    let root = repo_root();
    // 记录服务器日志，便于排障。
    let log_path = root.join("apps/tauri/server.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();
    let stdout = match &log_file {
        Some(f) => Stdio::from(f.try_clone().expect("clone stdout")),
        None => Stdio::null(),
    };
    let stderr = match &log_file {
        Some(f) => Stdio::from(f.try_clone().expect("clone stderr")),
        None => Stdio::null(),
    };

    println!(
        "[trilium-tauri] spawning server '{program}' args={:?} cwd={}",
        args, root.display()
    );
    Command::new(&program)
        .args(&args)
        .current_dir(&root)
        .env("TRILIUM_PORT", port.to_string())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .ok()
}

fn main() {
    let app = tauri::Builder::default()
        .manage(ServerChild(Mutex::new(None)))
        .setup(|app| {
            let port = server_port();

            // 拉起 sidecar 服务器。
            let child = spawn_server(port);
            if let Some(c) = child {
                app.state::<ServerChild>().0.lock().unwrap().replace(c);
            }

            // 等待服务器就绪（即便由外部 server 提供，也能加速窗口加载）。
            if wait_ready(port, Duration::from_secs(90)) {
                println!("[trilium-tauri] server ready on port {port}");
            } else {
                eprintln!(
                    "[trilium-tauri] server not ready on port {port}; webview may show an error"
                );
            }

            // 动态创建窗口，加载本机服务器，端口可配置。
            let url = format!("http://localhost:{port}");
            let _window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External(url.parse().expect("invalid server url")),
            )
            .title("Trilium Notes — Tauri")
            .inner_size(1280.0, 840.0)
            .min_inner_size(800.0, 600.0)
            .build()?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(mut child) = app_handle.state::<ServerChild>().0.lock().unwrap().take() {
                println!("[trilium-tauri] stopping sidecar server");
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    });
}