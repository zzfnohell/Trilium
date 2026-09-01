---
name: creating-a-new-option
description: Use when adding a new user-facing option to Trilium — a synced preference users can change in Settings (never localStorage). Covers the OptionDefinitions type, the defaultOptions entry, the ALLOWED_OPTIONS whitelist, the settings-pane control plus its English key, and the React read/write hooks.
---

# Creating a new option

Trilium preferences are synced options — **no `localStorage`**. To add one:

1. Type in `OptionDefinitions`, `packages/commons/src/lib/options_interface.ts`.
2. Default in `defaultOptions`, `packages/trilium-core/src/services/options_init.ts`.
3. **Whitelist it in `ALLOWED_OPTIONS`**, `packages/trilium-core/src/routes/api/options.ts` — otherwise the API rejects writes with "Option 'X' is not allowed to be changed".
4. A control in the matching settings pane (`apps/client/src/widgets/type_widgets/options/*.tsx`) plus its English key.
5. Read/write via `useTriliumOption` / `useTriliumOptionBool` / `useTriliumOptionInt` / `useTriliumOptionJson`.

Details: `docs/Developer Guide/Developer Guide/Concepts/Options/Creating a new option.md`.
