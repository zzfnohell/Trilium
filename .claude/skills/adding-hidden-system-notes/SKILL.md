---
name: adding-hidden-system-notes
description: Use when adding a hidden system note to Trilium's _hidden subtree — system notes with deterministic _-prefixed IDs so every sync instance builds the same tree. Covers buildHiddenSubtreeDefinition and the HiddenSubtreeItem fields, enforceAttributes/enforceBranches/enforceDeleted, launcher-bar entries, and templates.
---

# Adding hidden system notes

The `_hidden` subtree holds system notes with deterministic `_`-prefixed IDs so every sync instance builds the same tree; `checkHiddenSubtree()` creates them at startup.

Add the `HiddenSubtreeItem` (from `@triliumnext/commons`) to `buildHiddenSubtreeDefinition()` in `packages/trilium-core/src/services/hidden_subtree.ts`:

- `id` (starts with `_`), `title` (key under `"hidden-subtree"` in `server.json`), `type`, `icon` (`bx-name`, no `bx ` prefix), `attributes`, `children`, `content`
- `enforceAttributes` / `enforceBranches` / `enforceDeleted: true` keep attributes, placement and removals in sync.

Launcher-bar entries: `hidden_subtree_launcherbar.ts`; templates: `hidden_subtree_templates.ts`.
