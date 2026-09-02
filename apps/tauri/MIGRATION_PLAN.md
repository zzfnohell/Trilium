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

### ✅ 受保护笔记加密/解密（本步骤，已实现，未提交）

对齐 `packages/trilium-core` 的受保护笔记链路：scrypt 派生密钥、AES-128-CBC 数据加密、
会话登录/登出、受保护内容的读（解密/掩码）与写（加密）、protect 动作。`cargo check` 零警告、
9 项单测全绿（含写路径集成测试）。

#### 实现内容

- `Cargo.toml`：新增 `scrypt` / `aes` / `cbc` 依赖。

- `src/crypto.rs`（新）：`data_encryption`/`scrypt`/`password_encryption` 纯函数镜像
  —— `pad16`、`scrypt_derive`(N=16384,r=8,p=1)、`encrypt_bytes`（4 字节 SHA1 摘要前缀 +
  随机 16 字节 IV + AES-128-CBC + PKCS7 → base64(iv‖ct)）、`decrypt`（16/13 字节 IV 兼容、
  摘要校验、`#510` 非密文恢复）、`constant_time_eq`；单测覆盖往返/密钥截断/13 字节 IV/
  摘要不匹配/错误密钥/非密文/前缀哈希互异。

- `src/services/protected_session.rs`（新）：进程级会话状态（数据密钥 Mutex）+ 密码服务
  —— `process_content`、`title_or_mask`、`decrypt_bytes`、`verify_password`/`get_data_key`/
  `set_password`/`change_password`/`reset_password`。

- `src/db/write.rs`：`update_note_data` 支持受保护笔记（事务内加密内容 + `_ENCRYPTED_`
  前缀 blobId 哈希；无会话时按"not available"400 拒绝）；`save_attachment` 保护感知（内容
  加密 + title 加密存储）；`copy_attachment` 沿用源附件保护状态；`protect_note` 整树翻转
  笔记/revisions/attachments 的 `isProtected`（内容、标题、textRepresentation 一并重加密，
  逐实体写 EntityChange）。`random_string`/`blob_id_for` 导出。

- `src/commands/api.rs`：`POST login/protected`、`logout/protected`、`login/protected/touch`
  （含 WS `protectedSessionLogin`/`protectedSessionLogout`）、`password/change`、`password/reset`、
  `PUT notes/{id}/protect/{0|1}`（薄 handler + WS `taskSucceeded` toast）；读路径保护感知：
  `get_blob`（解密或空串）、`get_note`/`get_attachments`/`get_autocomplete`/`title_path` 标题
  掩码/解密；`get_options` 过滤密码与 LLM 密钥、输出 `isPasswordSet` / `is*KeySet`。

- `src/db/tree.rs`：`build_response` 标题掩码/解密。

#### 待验证（手动）

- 在有受保护笔记 + 已知密码的真实数据库中端到端验证：登录 → 树/标题解密 → 读取解密 →
  编辑保存加密 → 登出后标题`[protected]`、内容空串；protect 按钮翻转子树。

### ⏳ 待办（后续步骤）

- 附件 CRUD 路由：`POST/GET notes/{id}/attachments`、`GET|PUT|DELETE attachments/{id}...`、
  `convert-to-note`、`rename`、`blob`、`notes/{id}/attachments/upload`。

- `saveRevision` 附件版本管理：revision 快照连同附件一起版本化。

- 附件图片资源：`api/attachments/{id}/image/{name}` `<img>` 拦截（当前 shell 中图片不渲染）、
  受保护附件 blob 的解密返回、`getAttachmentImageInfo`。

- 其他零碎：`password` 选项读写口的对齐、notes 新建/改名/删除等写路由、保护会话超时自动锁定。

## 当前工作区状态

未提交改动（不 push，用户确认后才 commit）：

```
 M apps/tauri/src-tauri/Cargo.toml
 M apps/tauri/src-tauri/src/commands/api.rs
 M apps/tauri/src-tauri/src/db/mod.rs          # set_option + 删 get_note_title
 M apps/tauri/src-tauri/src/db/tree.rs         # 标题掩码
 M apps/tauri/src-tauri/src/db/write.rs        # 保护写路径 + protect_note
 M apps/tauri/src-tauri/src/main.rs
?? apps/tauri/src-tauri/src/crypto.rs
?? apps/tauri/src-tauri/src/services/         # mod.rs + protected_session.rs
?? apps/tauri/src-tauri/MIGRATION_PLAN.md       # 本计划（含 .gitattributes 修复记录）
```

已提交：`471d7296d9`（.gitattributes 补丁 LF 修复）。

## 约定

- 提交直接在 `main` 上（仓库规则），用户明确要求时才 commit；不 push 到任何远端。

- 运行：`cargo run`（cwd=apps/tauri/src-tauri）；`client/dist` 是构建产物，需求重建时
  手动 `vite build`。

- 关键排障记录（白屏根因、拦截脚本三处 bug、`get_api_resource` 命令名）见项目记忆，勿回退。

