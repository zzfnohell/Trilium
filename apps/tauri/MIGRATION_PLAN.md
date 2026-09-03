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

### ✅ 受保护笔记加密/解密（已提交 `93884c5e9e`，前置 `c5917b1cc8`）

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

### ✅ 附件 CRUD（已提交 `93884c5e9e` / `1f6c330c24` 线，含后续 `cba58ecaac`、`b88c672df8`）

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

### ✅ Multipart 上传 + convert-to-note（已提交 `1f6c330c24`）

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

### ✅ 图标修复（本步骤，未提交）

bootstrap 负载中 `iconPackCss`/`iconRegistry` 原为空串/空对象，`loadIcons()` 注入的是空 `<style>`，
所有 `bx bx-*` 图标类没有 `@font-face`/`content` 规则 → 树/按钮/内容图标全部空白。已在 Rust 侧
补齐，对齐 `getIconConfig` 的内置 Boxicons 半部：

- `src/icon_packs.rs`（新）：`include_str!` 内嵌 trilium-core 的 `icon_pack_boxicons-v2.json`
  （1635 图标），`builtin_icon_pack_css(assetPath)` 按 `generateCss` 生成 `@font-face`
  （`src: url('…/fonts/boxicons.woff2')`）+ `.bx` 基类 + 每个图标的 `::before` content 规则；
  `icon_registry()` 按 `generateIconRegistry` 输出 `{ sources: [{prefix:"bx", name, icon, icons}] }`。

- `commands/bootstrap.rs`：`iconPackCss: builtin_icon_pack_css("")`、`iconRegistry: icon_registry()`。

- `main.rs`：state dump 增加 `iconPackCssLen`（含 boxicons 的 `<style>` 字数）与 `iconFontLoaded`
  （`document.fonts.check('20px boxicons')`）两个诊断字段。

验证：`cargo test` 3 项单测全绿（CSS 含 @font-face/全部 icon 规则、assetPath 拼接、registry 全量）；
实机启动 state dump `iconPackCssLen:72128`、`iconFontLoaded:true`、`failingLinks:[]`、`hasCritical:false`。

### ✅ 附件图片资源服务（本步骤，未提交）

附件/图片资源的 `api/` URL 之前无任何服务：`<img src="api/attachments/{id}/image/...">`、
convert 成 image note 后的 `api/images/{id}/...` 在 shell 中全部裂图，自定义图标包的字体路径
`api/attachments/download/{id}` 也不存在。已对齐 `packages/trilium-core/src/routes/api/` 的
`returnAttachedImage` / `downloadAttachment` / `returnImageInt`：

- `commands/api.rs`：新 `get_api_media` IPC 命令 + 纯函数 `resolve_media_resource(conn, path)`，
  解析 `attachments/{id}/image/{name}`（role 必须 `image`）、`attachments/{id}/download` 与
  `attachments/download/{id}`（图标包字体、下载）、`images/{noteId}/{name}`（note type 限
  image/canvas/mermaid/mindMap/spreadsheet）。二进制经 `db::write::read_clear_bytes`
  （TEXT/BLOB 通吃、受保护时按会话解密/锁定返回空）读为字节，base64 过 IPC + 真实 mime。

- `db/write.rs`：`read_clear_bytes` 转 `pub`（读附件/图片 note blob 复用）。

- `main.rs`：`ELECTRON_BRIDGE_JS` 新增媒体拦截 —— MutationObserver（childList + `src`
  属性 + 初始扫描）把 `<img>`/`video`/`audio` 的 `/api/` src 经 `get_api_media` 换成
  `blob:` URL（带真实 mime），失败（如锁定中的受保护图）静默去掉 src。

- 测试：`media_routes_serve_attachment_images_and_image_notes` 集成测试（`TRILIUM_VERIFY_SOURCE`
  真实库副本插入 PNG 附件/image note 夹具，验证三臂 + 双 download 拼写 + 角色/类型门禁 +
  无效路径）。`cargo test` 19 项全绿。

仍受限：自定义图标包字体是 CSS 内 `url(api/attachments/download/{id})` 里的浏览器字体请求，
DOM 钩子拦不到（非 link/img 元素），需要 await 用户真造一个 `#iconPack` 后再定方案。

### ✅ `options/user-themes` 路由补齐（已提交 `f3a1548961`）

`appearance.tsx` / `theme.ts` 启动即请求 `GET /options/user-themes`，之前被 dispatch 的通用
`options/{name}` 臂吞掉，报 `Option 'user-themes' not found`（404）。已按
`packages/trilium-core/src/routes/api/options.ts` 的 `getUserThemes` 对齐：

- `commands/api.rs`：dispatch 在 `["options", name]` 之前新增 `["options", "user-themes"]` 臂；
  `get_user_themes` 列出所有带 `#appTheme` 标签的笔记（`val`=owned `appTheme` 值，缺省时用标题
  slug 化，`[^a-z0-9]`→`-`），附 `title`（受保护掩码）、`noteId`、可选 `icon`/`appThemeBase`。

- 测试：`slugify_title_matches_the_js_rule`（纯函数）+ `user_themes_lists_apptheme_notes`
  （`TRILIUM_VERIFY_SOURCE` 真实库副本插入夹具主题笔记验证字段）。`cargo test` 18 项全绿
  （含对真实 `document.db` 副本跑通的集成项）。

### ✅ notes 写路由基建（本步骤，未提交）

对齐 `routes/api/notes.ts` 的创建/改名/删除/撤销删除四组路由，`cargo check` 零警告、
`cargo test` 20 项全绿（新增 `note_lifecycle_create_rename_delete_undelete_erase`
真实库副本集成测试）：

- **dispatch（`commands/api.rs`）**：

  - `POST notes/{parentNoteId}/children?target=into|after|before&targetBranchId=…`
    → `create_note_route`：解析 body 为 `NoteCreateParams`，返回 `{ note, branch }`。

  - `PUT notes/{noteId}/title` → `change_title_route`（`noteService.changeTitle`）。

  - `PUT notes/{noteId}/undelete` → `undelete_note_route`（回 `{ undeleted,
    restoredToFallbackParent }`，body `fallbackParentNoteId` 可选）。

  - `DELETE notes/{noteId}?taskId&eraseNotes&last` → `delete_note_route`
    （生成 deleteId、软删、可选立即擦除、`last=true` 时发 WS `taskSucceeded`）。

  - 序列化抽公共 `note_row_value` / `branch_row_value`（完整 pojo，标题按保护会话
    解密/掩码），`convert-to-note` 响应一并复用。

- **`db/write.rs`**：

  - `create_note_with_target`：父笔记校验（launcher/`_lbRoot`/`_hidden`/`_lbTpl`/
    `_help`/`_options` 禁建）、type/mime 派生（无 type 继承 code 父类型+mime，否则
    text/text/html；模板 mime 继承优先于类型默认）、默认标题 "New note"
    （`titleTemplate` 模板求值未复刻）、`after`/`before` 兄弟位次平移 +
    `note_reordering` 变更、模板支持（`~template` 关系、二进制模板内容复制、
    非 image 附件复制）、body `attributes` 原子写入、`child:` 属性复制
    （父级 `child:template` 被显式模板压制）、创建后内容链接扫描。

  - `create_new_note` 拆出 `create_note_entity`（低频、供 convert 与路由共用）。

  - `change_note_title`：受保护会话门禁、标题变化才记 revision、受保护标题加密落盘。

  - `delete_note` + `delete_branch_recursively`（`BBranch.deleteBranch` 级联：本分支→
    弱分支→子分支→owned 属性→target 关系→附件→笔记本身，共享同一 deleteId；
    root/hoisted 拒绝、强父分支存在时仅删分支）。

  - `erase_notes_with_delete_id`（`erase.ts` 镜像：物理删 notes/branches/attributes/
    attachments + 被删笔记的 revisions，entity\_changes 置 `isErased`，清孤儿 blob）。

  - `undelete_note` + `undelete_branch` + `restore_note_and_descendants`：经存活父分支
    恢复或经 fallback 父重挂孤儿；仅恢复匹配同一 deleteId 的批次；保存恢复行的
    原值（仅 `isDeleted` 归零，等价 `entity.save()`）。

未纳入本步：`sort-children`、`duplicate`、`convert-format`、revision 子路由、
`titleTemplate` 求值、删除前预览（`delete-notes-preview`）。

### ⏳ 待办（后续步骤）

- `saveRevision` 附件版本管理：revision 快照连同附件一起版本化。

- 自定义图标包（`#iconPack` 笔记）与 task-state 图标 CSS：当前只有内置 Boxicons 包；
  `icon_packs.rs` 尚未读自定义包的 JSON manifest/字体附件，`generateTaskStateCss`（`_taskStates`
  子树 → `--task-state-glyph` 规则）也未生成。字体 URL `api/attachments/download/{attachmentId}`
  路由已实现（见上），但 CSS 内 `url(...)` 的浏览器字体请求 DOM 钩子拦不到，需另想办法。

- 附件 `image-info` 全量字段与 `getAttachmentImageInfo` 客户端配套。

- 其他零碎：保护会话超时自动锁定、deleted-notes 读路由。

## 当前工作区状态

未提交改动（不 push，用户确认后才 commit）：

```
 M apps/tauri/src-tauri/src/commands/api.rs         # notes 四组写路由 dispatch + note/branch pojo 序列化
 M apps/tauri/src-tauri/src/db/write.rs             # create_note_with_target / change_note_title / delete_note / undelete_note / erase
 M apps/tauri/MIGRATION_PLAN.md
```

已提交：`93884c5e9e`（受保护笔记）、`1f6c330c24`（multipart+convert）、`cba58ecaac`、`b88c672df8`、
`f3a1548961`（options/user-themes）、`f9c3e5731b`（Boxicons 图标包）、`4dac3a65e9`（附件图片媒体路由）、`471d7296d9`（.gitattributes LF 修复）等。

## 约定

- 提交直接在 `main` 上（仓库规则），用户明确要求时才 commit；不 push 到任何远端。

- 运行：`cargo run`（cwd=apps/tauri/src-tauri）；`client/dist` 是构建产物，需求重建时
  手动 `vite build`。

- 关键排障记录（白屏根因、拦截脚本三处 bug、`get_api_resource` 命令名）见项目记忆，勿回退。

