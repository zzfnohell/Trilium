# Trilium Notes — 代码 Wiki

> 本文档对 **TriliumNext / Trilium** 分层笔记应用代码库进行结构化梳理，覆盖整体架构、模块职责、关键类与函数、依赖关系及运行方式。适用于开发者快速上手与代码导航。

---

## 目录

1. [项目概述](#1-项目概述)
2. [技术栈与总体架构](#2-技术栈与总体架构)
3. [Monorepo 目录结构](#3-monorepo-目录结构)
4. [核心数据模型：三层缓存系统](#4-核心数据模型三层缓存系统)
5. [主要应用模块职责](#5-主要应用模块职责)
6. [关键类与函数说明](#6-关键类与函数说明)
7. [同步协议](#7-同步协议)
8. [搜索系统](#8-搜索系统)
9. [API 层架构](#9-api-层架构)
10. [依赖关系](#10-依赖关系)
11. [运行方式](#11-运行方式)
12. [测试与工程规范](#12-测试与工程规范)
13. [Tauri 迁移（POC）](#13-tauri-迁移poc)

---

## 1. 项目概述

**Trilium Notes** 是一款**层级化（树状）笔记应用**，核心特性包括：

- 树形笔记组织，支持克隆（一个笔记可有多个父节点）
- 多端**同步**（服务器 / 桌面 / Standalone / 移动端）
- 富文本编辑（基于 CKEditor5）、代码编辑（CodeMirror）、Markdown、Mermaid、画布、思维导图等多种笔记类型
- 属性系统（标签 `#label` 与关联 `~relation`）
- 脚本化（前端/后端脚本）、模板、调度器（scheduler）、OCR、备份恢复
- LLM 集成（AI 聊天）、MCP 服务端
- 第三方访问的 **ETAPI**（外部 API）

- **版本**：`0.104.1`
- **许可证**：AGPL-3.0-only
- **包管理器**：pnpm（`packageManager: pnpm@11.20.0`）
- **语言**：TypeScript（monorepo）

---

## 2. 技术栈与总体架构

| 领域 | 技术选型 |
|------|----------|
| 前端 UI | Preact + jQuery widget 系统（`apps/client`） |
| 富文本编辑器 | 定制版 CKEditor5（`packages/ckeditor5`） |
| 代码编辑器 | CodeMirror（`packages/codemirror`） |
| 后端 | Node.js + Express + better-sqlite3 |
| 桌面端 | Electron（同进程内嵌 server + client） |
| Standalone | 全栈编译进浏览器（sql.js WASM + Service Worker） |
| 移动端 | Capacitor（Android + iOS）包裹 Standalone |
| 构建 | Vite + esbuild |
| 测试 | Vitest + Playwright（E2E） |

### 平台形态

同一个 **`packages/trilium-core`（核心，后端业务逻辑）** + **`apps/client`（前端 UI）** 被多种运行时复用：

```
┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   ┌─────────────────────┐
│  Server      │   │  Desktop     │   │  Standalone      │   │  Mobile (Capacitor) │
│  Node+Express│   │  Electron    │   │  Service Worker  │   │  WebView + 本地Worker│
│  better-sqlite│   │ 同进程内嵌    │   │  sql.js (WASM)   │   │  = Standalone 包装   │
└──────┬───────┘   └──────┬───────┘   └────────┬─────────┘   └──────────┬──────────┘
       │                  │                    │                        │
       └──────────────────┴───────┐    ┌───────┘                        │
                                  ▼    ▼                                ▼
                     ┌────────────────────────────────────────────┐
                     │   @triliumnext/core  (业务核心, 跨运行时)    │
                     │   becca / services / search / sync / routes │
                     └────────────────────────────────────────────┘
```

**关键约束**：`core` 在不同运行时（Node / 浏览器 worker）运行，因此：
- core 中**禁止**使用 Node 内建模块（`path`、`fs`、`process.env` 等），改用平台无关替代或 `PlatformProvider`。
- 前端（client）**不依赖 core**，只通过 REST/WebSocket 访问后端，共享类型放 `@triliumnext/commons`。

---

## 3. Monorepo 目录结构

```
Trilium/
├── apps/                        # 具体应用
│   ├── client/                  # Preact 前端（server/desktop/standalone 共用）
│   ├── server/                  # Node.js 后端（Express + better-sqlite3）
│   ├── desktop/                 # Electron 桌面端
│   ├── standalone/              # 浏览器内全栈版（WASM + SW）
│   ├── standalone-desktop/      # Standalone 桌面变体
│   ├── mobile/                  # Capacitor 移动端（Android/iOS）
│   ├── web-clipper/             # 浏览器剪藏扩展
│   ├── website/                 # 项目官网
│   ├── build-docs/              # 生成 Script API 文档（TypeDoc）
│   ├── db-compare/              # 数据库对比工具
│   ├── dump-db/                 # 数据库导出工具
│   ├── edit-docs/               # 用户文档编辑工具
│   └── icon-pack-builder/       # 图标包构建工具
├── packages/
│   ├── trilium-core/            # 核心业务逻辑（实体、服务、SQL、同步、搜索）
│   ├── commons/                 # client/server 共享类型与工具
│   ├── ckeditor5/               # 定制富文本编辑器 bundle
│   ├── codemirror/              # 代码编辑器集成
│   ├── highlightjs/             # 语法高亮
│   ├── share-theme/             # 分享/发布笔记主题
│   ├── pdfjs-viewer/            # PDF 查看器（vendored from pdf.js）
│   ├── splitjs/                 # 面板分割
│   ├── trilium-e2e/             # 共享 Playwright E2E 测试
│   └── turndown-plugin-gfm/     # HTML→Markdown 转换插件
├── scripts/                     # 构建/发布/工具脚本（tsx/mts）
├── docs/                        # 用户指南、开发者指南、发布说明
├── patches/                     # pnpm 补丁
└── 顶层配置：package.json / pnpm-workspace.yaml / tsconfig.base.json / flake.nix 等
```

---

## 4. 核心数据模型：三层缓存系统

所有数据访问都经过缓存层，**禁止绕过缓存直接写数据库**（缓存方法会生成同步所需的 `EntityChange` 记录）。

| 缓存层 | 位置 | 运行端 | 说明 |
|--------|------|--------|------|
| **Becca** | `packages/trilium-core/src/becca/` | 服务端 | 服务端实体缓存，`becca.notes[noteId]` |
| **Froca** | `apps/client/src/services/froca.ts` | 客户端 | 通过 WebSocket 同步的客户端镜像，`froca.getNote()` |
| **Shaca** | `apps/server/src/share/shaca/` | 分享端 | 为分享/发布笔记优化的缓存 |

### 核心实体（`packages/trilium-core/src/becca/entities/`）

所有实体继承 `AbstractBeccaEntity<T>`，内置变更追踪、哈希生成与日期管理：

| 类 | 数据表 | 职责 |
|----|--------|------|
| `BNote` | notes | 笔记，含内容与元数据 |
| `BBranch` | branches | 树的多父节点关系（克隆支持） |
| `BAttribute` | attributes | 键值属性（标签与关联） |
| `BRevision` | revisions | 版本历史 |
| `BOption` | options | 应用配置 |
| `BBlob` | blobs | 二进制内容存储 |
| `BAttachment` | attachments | 附件 |
| `BEtapiToken` | etapi_tokens | ETAPI 访问令牌 |
| `BRecentNote` | recent_notes | 最近笔记 |

---

## 5. 主要应用模块职责

### 5.1 `apps/server` — 后端

Node.js + Express + better-sqlite3。对外提供 REST/WebSocket API，并托管静态资源。

- **启动链**：`main.ts`（读配置→打开数据库→`initializeCore()`）→ `www.ts`（`startTriliumServer()`：启动 HTTP/HTTPS、绑定 WebSocket、注册 OCR/LLM 扩展）→ `app.ts`（`buildApp()`：组装 Express 中间件与路由）。
- **关键中间件**（`app.ts`）：CORS / compression / helmet / `express.json`（500mb 限制）/ cookieParser / `desktopNetworkAccessGate` / MCP / sessionParser / OIDC。
- **路由注册**：`routes/routes.ts` 的 `register()` 挂载页面路由、`/api/*`、ETAPI、分享路由、OCR、LLM Chat 等。
- **配置**：`config.ini`（`services/config.ts` 读取），支持 `TRILIUM_*` 环境变量。
- **分享**：`share/`（Shaca 缓存 + 分享路由）。
- **提供者实现**：`*_provider.ts`（sql / crypto / zip / log / platform / cls 等），注入给 core 的 `initializeCore()`。

### 5.2 `apps/client` — 前端

Preact + jQuery widget 系统。被 server、desktop、standalone 共用。

- **入口**：`index.ts` → `desktop.ts`（初始化）。
- **Froca**：`services/froca.ts`，客户端只读缓存，通过 WebSocket 增量同步。
- **WS 通信**：`services/ws.ts`。
- **Widget 体系**：`widgets/`，`BasicWidget` / `TypedBasicWidget` / `NoteContextAwareWidget` / `RightPanelWidget`；类型专用 widget 在 `widgets/type_widgets/`。
- **复用组件**：`widgets/react/`（`NoItems`、`ActionButton`、`FormTextBox`、`FormSelect`、`Table`、`Calendar`、`Dropdown`、`Badge`、`Collapsible`、`ColorPicker` 等）。
- **服务**：`services/`（search、tree、theme、options、clipboard、sync、import、i18n、llm_chat 等）。
- **国际化**：`translations/`，仅向 `en/translation.json` 添加新 key。

### 5.3 `packages/trilium-core` — 业务核心

被 server、desktop、standalone 共享（**不**被 client 使用）。核心目录：

- `becca/` — 服务端实体缓存与实体类。
- `services/` — SQL、同步、搜索、脚本、调度、属性继承、LLM、导入导出等。
- `routes/` — 共享 API 路由定义（由各平台注入路由辅助实现）。
- 入口 `initializeCore()`：以依赖注入方式初始化日志、备份、平台、加密、SQL、schema、zip、消息、请求、帮助、图像、配置等。

### 5.4 `apps/desktop` — Electron 桌面端

- 入口：`main.ts`；窗口管理：`services/window.ts`。
- **安全**：`nodeIntegration` 关闭、`contextIsolation` 开启；preload 通过 `contextBridge.exposeInMainWorld("electronApi", ...)` 暴露白名单 API（`ElectronApi` 接口在 `packages/commons`）。
- 渲染进程通过 `trilium-app://` 自定义协议访问 API（`protocol.ts` → 主进程内嵌 Express）。
- 平台实现：`platform_provider.ts`。

### 5.5 `apps/standalone` — 浏览器内全栈

- `main.ts`：注册 Service Worker、Leader Election（`claimLeadership` 决定哪个 tab 打开数据库）、iOS Capacitor 拦截器、`startLocalServerWorker()`。
- `sw.ts`：Service Worker 将 `/api`、`/sync`、`/bootstrap`、`/search` 请求路由到本地 worker。
- 核心逻辑编译为 WASM（sql.js），数据存 OPFS。

### 5.6 `apps/mobile` — 移动端

Capacitor WebView 包裹 Standalone。无网络后端：
- **Android**：`androidScheme: "https"` → 走 Service Worker 路由。
- **iOS**：`capacitor://` 不能注册 SW → 走 `main.ts` 的 fetch/XHR 拦截器（`iosScheme: "https"` 是 no-op，勿删 iOS 拦截路径）。

### 5.7 其他应用

- `apps/web-clipper`：浏览器剪藏扩展（wxt）。
- `apps/website`：官网。
- `apps/build-docs`：生成 Script API 文档（TypeDoc）。
- `apps/db-compare` / `dump-db` / `edit-docs` / `icon-pack-builder`：辅助工具。

---

## 6. 关键类与函数说明

### 6.1 核心初始化 — `initializeCore()`

`packages/trilium-core/src/index.ts`。集中注入平台依赖并初始化各服务，调用顺序：

```
initConfig → initPlatform → initLog → initBackup → enterSetupMode
→ initTranslations → initCrypto → initZipProvider → initZipExportProviderFactory
→ initContext(CLS) → initSql → initSchema → initImageProvider → initDemoArchive
→ Object.assign(appInfo, extraAppInfo) → initMessaging → initRequest
→ initInAppHelp
```

### 6.2 平台抽象 — `services/platform.ts`

`PlatformProvider` 接口 + `initPlatform()`/`getPlatform()`。提供 `crash()`、`getEnv()`、`isElectron/isMac/isWindows`。实现位于各应用（server/desktop/standalone 的 `*_provider`）。

### 6.3 Becca 缓存 — `becca/becca-interface.ts`

`class Becca`，核心字段与方法：
- 容器：`notes`、`branches`、`childParentToBranch`、`attributes`、`attributeIndex`、`options`、`etapiTokens`。
- **搜索优化**：`flatTextIndex`（预建并行数组，加速 5 万+ 笔记的全文扫描），支持增量更新（`dirtyFlatTextNoteIds`）。
- 访问器：`getNote/getNoteOrThrow/getBranch/getAttribute/getOption` 等，以及 `getAllNoteSet()`（缓存 NoteSet）、`getFlatTextIndex()`。

### 6.4 实体基类 — `abstract_becca_entity.ts`

`AbstractBeccaEntity<T>`：提供 `getOwnedAttribute()`、`getAttribute()`（含继承）、`isContentAvailable()`、`getTitleOrProtected()`、内容加解密、变更追踪与哈希生成。

### 6.5 服务器启动 — `main.ts` → `www.ts` → `app.ts`

- `startApplication()`（server `main.ts`）：恢复中断的数据库还原 → 打开数据库（支持 `TRILIUM_INTEGRATION_TEST=memory` 内存库）→ `initializeCore()` → `startTriliumServer()`。
- `startTriliumServer()`（`www.ts`）：版本检查（Node ≥ 20）→ 构建 app → HTTP(S) 监听 → 绑定 WS → 启动 OCR/LLM 扩展 → `markAppReady()`。
- `buildApp()`（`app.ts`）：组装 Express 中间件与路由，并启动同步定时器、一致性检查、调度器、清理定时器。

### 6.6 客户端缓存 — `services/froca.ts`

`class FrocaImpl`：`loadInitialTree()` 拉取 `/api/tree`，`addResp()` 增量更新 `notes/branches/attributes/attachments`。实体类为 `FNote/FBranch/FAttribute/FBlob/FAttachment`。

### 6.7 路由辅助 — `routes/build_shared_api_routes()`

`core/routes/` 定义共享 API 路由，server 在 `routes.ts` 中注入具体实现（`route/asyncRoute/apiRoute`、认证中间件等）。

---

## 7. 同步协议

由 `packages/trilium-core/src/services/sync.ts`、`syncMutexService`、`syncUpdateService` 实现。每次实体修改都会创建 `EntityChange` 记录驱动同步：

1. **登录**：HMAC 认证（文档密钥 + 时间戳）。
2. **Push Changes → Pull Changes → 再 Push**（冲突解决）。
3. **内容哈希校验** + 重试循环。

相关模块：`sync_options.ts`、`sync_update.ts`、`sync_mutex.ts`、`entity_changes.ts`、`consistency_checks.ts`、`content_hash.ts`。

---

## 8. 搜索系统

`packages/trilium-core/src/services/search/`，基于**表达式**、**内存评分**（无法在 SQL 层做 LIMIT/OFFSET 而保持评分）。

- 词法/解析：`lex.ts` → `parse.ts` → `handle_parens.ts`。
- 表达式实现：`expressions/`（`and` / `or` / `not` / `label_comparison` / `attribute_exists` / `ancestor` / `descendant_of` / `child_of` / `parent_of` / `note_content_fulltext` / `ocr_content` / `order_by_and_limit` 等）。
- 结果：`search_result.ts`、`note_set.ts`（NoteSet）、`search_context.ts`、`value_extractor.ts`。
- 性能：Becca 的 `flatTextIndex` 预建扁平文本并行数组加速全文扫描。

---

## 9. API 层架构

| API | 位置 | 认证 | 说明 |
|-----|------|------|------|
| **内部 API** | `apps/server/src/routes/api/` | 信任前端 + session | REST 端点，给前端用 |
| **ETAPI** | `apps/server/src/etapi/` | Basic Auth 令牌（`etapi_tokens`）| 第三方外部 API，需保持向后兼容 |
| **WebSocket** | `core/services/ws.ts` | session | 实时同步 |
| **MCP** | `apps/server/src/routes/mcp.ts` | 每次请求 ETAPI token | `/mcp` 端点，需 server 运行 |
| **分享** | `apps/server/src/share/` | 分享链接 | 公开笔记发布 |

---

## 10. 依赖关系

### 包依赖方向

```
apps/client ──独立── ✗ (@triliumnext/core)
apps/client ──types──> @triliumnext/commons
apps/server ──> @triliumnext/core ──> @triliumnext/commons
apps/desktop ──> @triliumnext/core + apps/server + apps/client
apps/standalone ──> @triliumnext/core + apps/client（编译为 WASM）
apps/mobile ──> apps/standalone
packages/ckeditor5 / codemirror / highlightjs / pdfjs-viewer ──> apps/client
```

**关键规则**：
- `apps/client` **不 import** `@triliumnext/core`（零依赖），只通过 `@triliumnext/commons` 共享类型。
- 共享类型放 `@triliumnext/commons/src/lib/`。
- 添加到 core 的依赖会进入 server/desktop/standalone 的 bundle，**不会**进入 client。

### 平台注入关系（依赖反转）

`core` 通过 `initializeCore({...})` 接收各平台实现（provider），实现 **依赖注入**：

```
core 需要的接口            server 提供            desktop 提供
─────────────────────    ──────────────────     ─────────────────
PlatformProvider         ServerPlatformProvider  ElectronPlatformProvider
SqlServiceParams         BetterSqlite3Provider   同 server
CryptoProvider           NodejsCryptoProvider    同 server
ZipProvider              NodejsZipProvider        同 server
LogService               ServerLogService          ...
ExecutionContext(CLS)    ClsHookedExecutionContext  ...
MessagingProvider        WebSocketMessagingProvider ...
RequestProvider          NodeRequestProvider        ...
ImageProvider            serverImageProvider         ...
BackupService            ServerBackupService         ...
```

---

## 11. 运行方式

### 环境准备

```bash
# 启用 corepack 并安装依赖
corepack enable && pnpm install
```

### 常用命令（根 package.json）

| 命令 | 说明 |
|------|------|
| `pnpm server:start` | 开发服务器，`http://localhost:8080` |
| `pnpm desktop:start` | Electron 桌面开发 |
| `pnpm standalone:start` | Standalone 客户端开发 |
| `pnpm mobile:sync` | 移动端同步 |
| `pnpm client:build` / `server:build` / `desktop:build` | 构建 |
| `pnpm typecheck` | 全项目 TS 类型检查 |
| `pnpm test:all` | 全部测试（CI 用） |

### 环境变量 / 配置

- 配置以 `config.ini` 为主（`TRILIUM_*` 环境变量覆盖），如 `TRILIUM_DATA_DIR`、`TRILIUM_PORT`、`TRILIUM_HOST`。
- 服务器需 Node.js ≥ 20。
- 数据目录：见 `services/data_dir.ts`（`TRILIUM_DATA_DIR`）。

### 生产技术栈注意

- 生产构建时 server 被绑定为 CJS，**不要**用 `import.meta.url` / 相对 `__dirname` 定位资源，用 `RESOURCE_DIR`（`services/resource_dir.ts`）。
- 桌面端启动若遇 `ELECTRON_RUN_AS_NODE` 崩溃，先 `Remove-Item Env:ELECTRON_RUN_AS_NODE`。

---

## 12. 测试与工程规范

- **Server 测试**（`apps/server/spec/`）：Vitest，必须顺序执行（共享数据库），forks 池，最多 6 workers。
- **Client 测试**（`apps/client/src/`）：Vitest + happy-dom，可并行。
- **Core 测试**（`packages/trilium-core/src/**/*.spec.ts`）：无独立 runner，由 server 和 standalone 两套 suite 共同包含运行（node+better-sqlite3 与 happy-dom+sql.js 两套平台）。
- **E2E**：Playwright（`packages/trilium-e2e/` 共享）。
- **推荐**：`pnpm --filter <pkg> test <path-or-pattern>` 跑最窄覆盖；**不要**跑全量 `test:all` / ESLint（会 OOM 且代价高）。

### 国际化（i18n）要点

- 客户端：`import { t } from "../services/i18n"`，key 在 `en/translation.json`（只加英文）。
- 服务端/Electron 主进程/core：`import { t } from "i18next"`，key 在 `apps/server/src/assets/translations/en/server.json`。
- 富文本编辑器（ckeditor5）：不用 i18next key，直接传英文文本作为 message id，再在 `translation.json` 的 `"text-editor": { "ck": { ... } }` 添加英文条目。

### 代码风格

- 4 空格缩进、分号、双引号、行宽 ≤ 100、Unix 换行。
- **禁止** TS 非空断言 `!`，改用时用 `?.` / `??` / 显式判空 / `*OrThrow` 访问器。
- 前端组件优先复用 `widgets/react/` 现有组件，避免原生标记与内联样式。

---

## 13. Tauri 迁移（POC）

> 本节记录将桌面端壳从 **Electron** 迁移到 **Tauri（Rust）** 的可行性分析、POC 验证结果与迁移清单。当前为 POC 阶段，Electron 仍是正式桌面端。

### 13.1 背景与核心障碍

Tauri 的**主进程是 Rust**，不是 Node。而当前 Electron 桌面端把**整个 Node 服务器跑在 Electron 主进程里**：`apps/desktop/src/main.ts` 调用 `initializeCore()` + `startTriliumServer()`，再通过自定义 `trilium-app://` 协议 + 庞大的 `electronApi` IPC 桥（`apps/desktop/src/preload.ts`）供渲染进程调用。因此「把 Electron 换成 Tauri」**不是 drop-in 改动**。

### 13.2 候选路线

| 路线 | 说明 | 代价 / 风险 |
|------|------|-------------|
| **A. Sidecar 内嵌 Node server（推荐）** | Tauri 壳把现有 server 打包为 sidecar 二进制，webview 加载 `http://localhost:PORT` | 复用 100% 核心逻辑；仍需 Node 运行时（体积大）；需把 `electronApi` 全部能力用 `#[tauri::command]` + `invoke()` 重写 |
| **B. webview 直连 standalone(WASM)** | 完全去掉 Node，webview 加载 standalone 构建 | 体积最小；但 WebKitGTK/WKWebView 对 Service Worker、原生文件、拼写支持参差，风险最高 |
| **C. Rust 重写后端** | —— | 工作量巨大，排除 |

### 13.3 POC 验证结果（本机）

| 验证项 | 结果 | 说明 |
|--------|------|------|
| Tauri Rust 壳编译/链接 | ✅ | tauri 2.11.5 + wry + webview2，`Finished dev profile` |
| 服务器返回客户端页面 | ✅ | `curl http://localhost:8080/` → HTTP 200，返回 vite 客户端 HTML |
| Tauri exe 启动 | ⚠️ | 进程能启动，但**被工具沙箱拦截**（应用数据目录 `AppData\Local\com.triliumnext.notes.poc` 写入受限），属环境限制，非应用缺陷 |
| sidecar 自动拉起服务器 | ✅ | `main.rs` 启动时 `spawn_server()` 自动执行 `pnpm server:start`，server.log 确认 `tsx watch src/main.ts` 被拉起，端口就绪后开窗 |

**结论**：Sidecar 路线在**编译层完全可行**。GUI 弹窗验证需在沙箱外运行（`pnpm tauri:start`）。

### 13.4 POC 已创建文件

```
apps/tauri/
├── package.json                 # @triliumnext/tauri，脚本 dev/build/check
├── frontend/index.html          # frontendDist 兜底页
└── src-tauri/
    ├── Cargo.toml               # tauri v2 依赖
    ├── build.rs                 # tauri-build
    ├── tauri.conf.json          # 无静态窗口，窗口由 main.rs 动态创建
    ├── icons/                   # 复用 server 的 icon.ico + client 的 icon.png
    └── src/main.rs              # 启动时拉起 sidecar 服务器，等待就绪后开窗加载 localhost
```

根脚本：`pnpm tauri:start` / `pnpm tauri:build`（调用 `cargo`）。

**sidecar 启动策略**（`src/main.rs`）：按优先级 ① `TRILIUM_NO_SPAWN=1` 不拉起 → ② 端口已可连接则复用外部 server → ③ 默认执行 `pnpm --config.verify-deps-before-run=false server:start` 拉起并等待端口就绪后开窗；应用退出时 kill 子进程。服务器日志写入 `apps/tauri/server.log`。

**本地运行方式**：

```bash
# 无需手动起服务器——Tauri 壳会自动拉起并等待就绪后弹窗
pnpm tauri:start
```

### 13.5 迁移清单（POC 通过后）

1. **sidecar**：将 `apps/server` bundle 打成独立可执行文件，由 `tauri-plugin-shell` 拉起并透传 `TRILIUM_*` 环境变量与数据目录。
2. **桥接重写（高成本项优先评估）**：把 `apps/desktop/src/preload.ts` 的 `ElectronApi`（window / clipboard / shell / 打印 / PDF 预览 / 托盘 / 对话框 / 单实例锁 / 拼写检查 / 备份口令 / OneNote）用 `#[tauri::command]` + `invoke()` 对等实现；前端 `window.electronApi` 改为按运行时动态选取（Electron 或 `window.__TAURI__`）。
3. **共享接口**：`ElectronApi` 类型已在 `@triliumnext/commons`，前端可复用；新增 `TauriApi` 对齐同名方法。
4. **webview 内核差异**：`trilium-app://` 自定义协议的 referer / CSP 需适配；`desktop_network_gate` 的 loopback 判定需复用。
5. **打包/CI**：用 tauri-bundler 替代 electron-forge（squirrel / flatpak / dmg），新增 `tauri:build` workflow（参考 `mobile.yml`）。

### 13.6 风险地图

- 打印 / PDF 预览、`webContents` 剪贴板、拼写检查是 Electron 独占能力，Tauri 插件覆盖不全（**high**）。
- 前端 `isElectron()` / `window.electronApi` 判断点需抽象（high）。
- 自定义协议与 CSP 改造（medium）。
- 三种 webview 内核（WebView2 / WKWebView / WebKitGTK）行为差异（medium）。

---

## 附录：进一步阅读

- [docs/README.md](docs/README.md) — 顶层文档入口
- [CLAUDE.md](CLAUDE.md) — 仓库级开发向导（本 Wiki 的权威来源）
- `docs/Developer Guide/` — 开发者指南（数据库迁移、新增选项、国际化、MCP 等）
- `docs/User Guide/` — 用户指南（通过 `pnpm edit-docs:edit-docs` 编辑）