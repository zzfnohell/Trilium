# Trilium → Tauri (Rust) 后端迁移计划

> 目标：用 Rust/Tauri 替代 Electron + Node 后端。架构：Rust 后端与前端通过 Tauri IPC
> 通信；`window.electronApi` 桥接模拟 Electron API 让现有 Preact 前端无需大改运行；
> 前端 REST 请求经 IPC 分发到 Rust 侧实现的各 API 路由（对齐原 Node 后端行为）。

## 迁移步骤总览

### ✅ 已完成并提交（在 main 上）

| 步骤                    | 内容                                                                              | 提交                                                                                  | <br />       |
| --------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | :----------- |
| 1. 垂直切片链路打通           | bootstrap → 树载荷 → 笔记内容，IPC 全通                                                   | `9cdb721544` `1b019e695b`                                                           | <br />       |
| 2. 同步写路径              | `PUT notes/{id}/data`：blob 去重、EntityChange、Revision、内联附件提取、远程图片下载、附件孤儿清理        | `603f82cb65`                                                                        | <br />       |
| 3. 启动白屏修复             | link.href 劫持脚本三处根因修复；`window`/`navigation`/`contextMenu` 桥接补齐                   | `3fc4538247`                                                                        | <br />       |
| 4. 启动期路由补齐 + toast 清零 | `recent-notes`、`tree/load`、`autocomplete`、`search/{q}`、\`notes/{id}/attachments | metadata`、`note-map/{id}/backlink-count`、`keyboard-*`、`script/*`、`system-checks\` 等 | `4ead618d92` |
| 5. 资源拦截               | `api/fonts`、`api/notes/download/{cssId}` 经 IPC 转 blob URL 注入；stylesheet 拦截器     | `ad50d695ef` `6562c916f1`                                                           | <br />       |

验证基线：界面正常渲染笔记树与正文，`hasTree:true`、`hasCritical:false`、`failingLinks:[]`、
启动日志无 `log-error` / `frontend-unhandledrejection` toast。

### 🔄 进行中：受保护笔记加密/解密（本步骤，未提交）

目标：对齐 `packages/trilium-core` 的受保护笔记链路 —— scrypt 派生密钥、AES-128-CBC
数据加密、会话登录/登出、受保护内容的读（解密/掩码）与写（加密）、protect 动作。

#### 已完成（工作区未提交）

- `Cargo.toml`：新增 `scrypt` / `aes` / `block-modes` 依赖。

- `src/crypto.rs`（新）：`data_encryption`/`scrypt`/`password_encryption` 纯函数镜像
  —— `pad16`、`scrypt_derive`(N=16384,r=8,p=1)、`encrypt_bytes`（4 字节 SHA1 摘要前缀 +
  随机 16 字节 IV + AES-128-CBC + PKCS7 → base64(iv‖ct)）、`decrypt`（16/13 字节 IV 兼容、
  摘要校验、`#510` 非密文恢复）、`constant_time_eq`；含单测（往返/密钥截断/13 字节 IV/摘要
  不匹配/非密文/前缀哈希互异）。

- `src/services/protected_session.rs`（新）：进程级会话状态（数据密钥 Mutex）+ 密码服务
  —— `process_content`（锁定返回空串、解锁解密、旧数据原样恢复）、`title_or_mask`
  （锁定 `[protected]`、解锁解密标题）、`verify_password`/`get_data_key`/`set_password`/
  `change_password`/`reset_password`。

- `src/db/mod.rs`：`set_option`（options 行 upsert，保留 `isSynced`）。

- `src/main.rs`：注册 `mod crypto; mod services;`。

- `src/commands/api.rs`（部分）：

  - `dispatch` 接入 `POST login/protected`、`login/protected/touch`、`logout/protected`（含
    WS `protectedSessionLogin`/`protectedSessionLogout` 事件）、`password/change`、`password/reset`、
    `PUT notes/{id}/protect/{flag}`（草稿，待重写）。

  - 读路径保护感知：`get_blob`（解密或空串）、`get_note` / `get_attachments`（标题掩码/解密）。

#### 待完成

- [ ] `db/write.rs`：`update_note_data` 支持受保护笔记 —— 写事务内加密内容、blobId 用
  `_ENCRYPTED_` 前缀哈希（`getUnencryptedContentForHashCalculation`）；`save_attachment`
  / `copy_attachment` 保护感知（copy 沿用源附件 isProtected）；暴露 `random_string`。

- [ ] `db/write.rs`：`protect_note(noteId, protect, subtree)` —— 翻转笔记/revisions/attachments
  的 `isProtected`，内容重加密写新 blob、旧 blob 无引用则清除，`textRepresentation` 同步
  重加密，逐条写 EntityChange。

- [ ] `commands/api.rs`：把 protect 路由改为薄 handler（调用 `write::protect_note` + WS
  `taskSucceeded` toast），删除草稿里的临时辅助函数。

- [ ] `commands/api.rs`：`get_options` 过滤密码/密钥选项 + 输出 `isPasswordSet`（对齐
  `options.ts` 的 readable 过滤）；`get_autocomplete` / `title_path` 标题掩码。

- [ ] `db/tree.rs`：`build_response` 笔记标题掩码/解密。

- [ ] 编译验证：`cargo check`；跑 `crypto.rs` 单测；用真实数据库（保护过笔记的 document.db）
  端到端验证登录 → 读取解密 → 保存加密 → 登出后掩码。

### ⏳ 待办（后续步骤）

- 附件 CRUD 路由：`POST/GET notes/{id}/attachments`、`GET|PUT|DELETE attachments/{id}...`、
  `convert-to-note`、`rename`、`blob`、`notes/{id}/attachments/upload`。

- `saveRevision` 附件版本管理：revision 快照连同附件一起版本化。

- 附件图片资源：`api/attachments/{id}/image/{name}` `<img>` 拦截（当前 shell 中图片不渲染）、
  受保护附件 blob 的解密返回、`getAttachmentImageInfo`。

- 其他零碎：`password` 选项读写口的对齐、notes 新建/改名/删除等写路由、保护会话超时自动锁定。

## 当前工作区状态（本步骤进行中）

未提交改动（不 push，用户确认后才 commit）：

```
 M apps/tauri/src-tauri/Cargo.toml
 M apps/tauri/src-tauri/src/commands/api.rs
 M apps/tauri/src-tauri/src/db/mod.rs
 M apps/tauri/src-tauri/src/main.rs
?? apps/tauri/src-tauri/src/crypto.rs
?? apps/tauri/src-tauri/src/services/         # mod.rs + protected_session.rs
```

注意：`api.rs` 中 protect 路由草稿块与 `get_blob_for_write`/`update_attachment`/`update_note_content_and_hash`
引用 `write::` 尚未存在的辅助函数，属待重写内容，编译前必须清理。

## 约定

- 提交直接在 `main` 上（仓库规则），用户明确要求时才 commit；不 push 到任何远端。

- 运行：`cargo run`（cwd=apps/tauri/src-tauri）；`client/dist` 是构建产物，需求重建时
  手动 `vite build`。

- 关键排障记录（白屏根因、拦截脚本三处 bug、`get_api_resource` 命令名）见项目记忆，勿回退。

