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

### ✅ 附件 CRUD（本步骤，已实现，未提交）

对齐 `attachments.ts` 的 JSON 附件路由，`cargo check` 零警告、10 项测试全绿：

- dispatch 新增：`GET attachments/{id}`、`GET attachments/{id}/all`、`GET attachments/{id}/blob`、
  `GET attachments/{id}/image-info`、`POST notes/{id}/attachments`（`matchBy=title` 支持，content
  base64）、`PUT attachments/{id}/rename`、`DELETE attachments/{id}`。

- `db/write.rs`：`save_attachment_route`（匹配后仅重存内容、forceSave 语义、新建走既有
  `save_attachment`）、`rename_attachment`（受保护标题加密、空标题 400）、`delete_attachment`
  （markAsDeleted 软删 + `|deleted` hash）；公共 `attachment_hash_value`。

- `db/mod.rs`：`get_attachment`、`get_attachment_blob`、`get_attachment_content`（解密）。

- `commands/api.rs`：附件序列化抽公共 `attachment_row_value`；`image-info` 轻量
  `inspect_image_geometry`（PNG/GIF/JPEG/BMP 尺寸 + 格式，测试覆盖）。

未纳入本步：multipart 上传（`server.upload` 走原生 `$.ajax`，shell 无 HTTP 层）、`convert-to-note`
（依赖 notes 新建基建）、附件 `<img>` 资源服务 —— 见待办。

### ✅ Multipart 上传 + convert-to-note（本步骤，已实现，未提交）

对齐 `attachments.ts` / `files.ts` / `image.ts` 的 multipart 路由与 `BAttachment.convertToNote`，
`cargo check` 零警告、13 项测试全绿（对其 `TRILIUM_VERIFY_SOURCE` 真实库跑通 4 项集成测试）：

- **客户端** **`services/server.ts`**：`upload()` 在桌面 shell（`isDesktopShell()`）下改走 IPC ——
  `readFileAsBase64` 把 `File` 编码为 base64 载荷 `{ fileName, mimeType, content }` 经 `api`
  命令发送；jQuery FormData 分支保留给浏览器（standalone/web）构建。

- **`db/write.rs`**（新写函数）：

  - `create_new_note` 基建：notes 行 + branches 行（`parent_note_id_note_id` 命名）+ 实体变更 +
    `copy_child_attributes`（`child:` 前缀属性复制，`child:template` 类型不匹配时跳过）+ `set_note_label`。

  - `save_uploaded_attachment`（`POST notes/{id}/attachments/upload`）：`is_accepted_image_mime`
    决定 `image`（`save_image_attachment`）还是 `file` 附件分支，image 分支回 `api/attachments/{id}/image/{title}`。

  - `update_file_note`（`PUT notes/{id}/file`，`?replace=1` 跳过 `saveRevision`）、
    `update_file_attachment`（`PUT attachments/{id}/file`，先给 owner 记 revision）、
    `update_image_note`（`PUT images/{id}`，检测格式写 mime）——均走 `store_note_content`
    （blob 去重 + 换 blobId + 旧 blob 清理）与 `stored` 后链路扫描。

  - `convert_attachment_to_note`：role→note 类型映射（image/favicon→image、file→file）、受保护
    会话门禁、新建笔记 + `markAsDeleted` + 文本父笔记内容改写（image URL→`api/images/{newId}/`、
    引用链接→`#root/{newId}`）+ `post_process_links` 侧效应。

  - `save_links` 抽取 `collect_content_links` 供 convert 的扫描复用（不触发图片下载）。

  - 修复：`save_note` 写全字段（mime/isProtected/…）；`read_clear_bytes` 兼容 TEXT/BLOB 存储。

- **`commands/api.rs`**：PUT 分发新增 `notes/{id}/file`、`attachments/{id}/file`、`images/{id}`；
  POST 新增 `notes/{id}/attachments/upload`、`attachments/{id}/convert-to-note`；
  `parse_upload_payload` 解析 IPC 载荷；convert 响应 `{ note, branch }` 对齐 `ConvertAttachmentToNoteResponse`。

未纳入本步：附件 `<img>` 资源服务（`api/attachments/{id}/image/{name}` 拦截，convert 后的图片
当前在 shell 中不渲染）、`saveRevision` 附件版本管理 —— 见待办。

### ⏳ 待办（后续步骤）

- notes 写路由基建：`createNewNote`（已有内部基建，公开路由未接）、改名、删除/撤销删除。

- 附件图片资源：`api/attachments/{id}/image/{name}` `<img>` 拦截（当前 shell 中图片不渲染，
  convert 成 image note 后 `api/images/{id}/` 同样需拦截）、`image-info` 全量字段、`getAttachmentImageInfo` 配套。

- `saveRevision` 附件版本管理：revision 快照连同附件一起版本化。

- 其他零碎：保护会话超时自动锁定、deleted-notes 读路由。

## 当前工作区状态

未提交改动（不 push，用户确认后才 commit）：

```
 M apps/tauri/src-tauri/src/commands/api.rs   # 附件路由 + image-info + 公共序列化 + 测试
 M apps/tauri/src-tauri/src/db/mod.rs         # get_attachment / blob / content
 M apps/tauri/src-tauri/src/db/write.rs       # save/rename/delete_attachment
 M apps/tauri/MIGRATION_PLAN.md
```

已提交：`93884c5e9e`（受保护笔记）、`471d7296d9`（.gitattributes LF 修复）。

## 约定

- 提交直接在 `main` 上（仓库规则），用户明确要求时才 commit；不 push 到任何远端。

- 运行：`cargo run`（cwd=apps/tauri/src-tauri）；`client/dist` 是构建产物，需求重建时
  手动 `vite build`。

- 关键排障记录（白屏根因、拦截脚本三处 bug、`get_api_resource` 命令名）见项目记忆，勿回退。

