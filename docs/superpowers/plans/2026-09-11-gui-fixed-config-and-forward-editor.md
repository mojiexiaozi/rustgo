# GUI Fixed Configuration and Unified Forward Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Windows GUI use an executable-relative configuration, connect automatically, and edit tunnels and P2P routes in one typed list.

**Architecture:** Add a testable GUI configuration module for path resolution, default creation, serialization, and atomic validated writes. Keep the existing rustgo-config schema, project its tunnel/export/forward vectors into a GUI-only tagged entry model, and let `GuiApp` coordinate startup and reconnection after successful saves.

**Tech Stack:** Rust 2024, eframe/egui, clap, rustgo-config, tempfile tests

**Spec:** `docs/superpowers/specs/2026-09-11-gui-fixed-config-and-forward-editor-design.md`

## Global Constraints

- The fixed GUI configuration is `client.toml` beside the running executable.
- The headless `rustgoc` CLI and the TOML schema remain unchanged.
- Invalid edits never replace the configuration file or interrupt the current connection.
- The unified type dropdown contains exactly TCP tunnel, UDP tunnel, P2P export, and P2P forward.

---

### Task 1: Fixed configuration lifecycle

**Files:**
- Create: `crates/rustgoc-gui/src/configuration.rs`
- Modify: `crates/rustgoc-gui/src/main.rs`
- Test: `crates/rustgoc-gui/src/configuration.rs`

**Interfaces:**
- Produces: `config_path_for_executable(&Path) -> Result<PathBuf>`, `load_or_create(&Path) -> Result<ClientConfig>`, and `save_validated(&Path, &ClientConfig) -> Result<()>`.
- Consumes: `rustgo_config::load_client`, `ClientConfig::validate`, and existing configuration structs.

- [ ] **Step 1: Write failing lifecycle tests** for executable-relative resolution, valid missing-file generation, existing-file preservation, and invalid-save preservation.
- [ ] **Step 2: Run `cargo test -p rustgoc-gui configuration::tests`** and confirm the new interfaces are missing.
- [ ] **Step 3: Implement path resolution, default TOML generation, complete TOML serialization, and sibling temporary-file replacement.** Serialize client identity/trust fields, telemetry, global P2P, tunnels, exports, and forwards with TOML-safe string escaping.
- [ ] **Step 4: Run `cargo test -p rustgoc-gui configuration::tests`** and confirm all lifecycle tests pass.
- [ ] **Step 5: Commit** with `feat(gui): add fixed configuration lifecycle`.

### Task 2: Automatic startup and simplified connection panel

**Files:**
- Modify: `crates/rustgoc-gui/src/main.rs`
- Modify: `crates/rustgoc-gui/src/ui/connection.rs`
- Test: `crates/rustgoc-gui/src/main.rs`
- Test: `crates/rustgoc-gui/src/ui/connection.rs`

**Interfaces:**
- Consumes: Task 1 lifecycle functions.
- Produces: startup decision state and a read-only `ConnectionPanel::show` that emits reconnect/disconnect actions.

- [ ] **Step 1: Write failing tests** proving GUI path selection ignores the current directory and startup requests a connection once after a ready configuration is loaded.
- [ ] **Step 2: Run the focused GUI tests** and confirm failure under the current CLI-selected/manual-connect behavior.
- [ ] **Step 3: Remove the GUI `-c` option, retain `--selfcheck` against the fixed path, load/create during `GuiApp::new`, and trigger connection on the first update.**
- [ ] **Step 4: Replace the editable endpoint and Connect button with configured endpoint text plus reconnect/disconnect actions.**
- [ ] **Step 5: Run `cargo test -p rustgoc-gui`** and commit with `feat(gui): connect automatically from fixed config`.

### Task 3: Unified tunnel and P2P editor

**Files:**
- Create: `crates/rustgoc-gui/src/ui/forwarding.rs`
- Modify: `crates/rustgoc-gui/src/ui/mod.rs`
- Modify: `crates/rustgoc-gui/src/main.rs`
- Modify: `crates/rustgoc-gui/src/ui/config.rs`
- Test: `crates/rustgoc-gui/src/ui/forwarding.rs`

**Interfaces:**
- Produces: `ForwardEntryKind`, `ForwardEntry`, `entries_from_config`, `replace_config_entries`, and `ForwardingPanel::show`.
- Consumes: `TunnelConfig`, `ExportConfig`, `ForwardConfig`, `P2pConfig`, runtime tunnel rows, and `P2PViewModel`.

- [ ] **Step 1: Write failing conversion tests** covering all four dropdown types and round trips that preserve ordering within each TOML collection.
- [ ] **Step 2: Run `cargo test -p rustgoc-gui ui::forwarding::tests`** and confirm the model is absent.
- [ ] **Step 3: Implement the tagged editor model and exact conversions.** Tunnel kinds carry name/local address/remote port; exports carry name/protocol/local address/allowed peers; forwards carry name/peer/export/listen address.
- [ ] **Step 4: Implement the `转发` page** with global P2P settings, runtime tunnel/path summaries, unified editable rows, removal, and an add form whose fields follow the selected kind.
- [ ] **Step 5: Replace separate Tunnels and P2P tabs and remove duplicate tunnel editing from the configuration page.**
- [ ] **Step 6: Run `cargo test -p rustgoc-gui`** and commit with `feat(gui): unify tunnel and p2p editing`.

### Task 4: Save, apply, and end-to-end verification

**Files:**
- Modify: `crates/rustgoc-gui/src/ui/config.rs`
- Modify: `crates/rustgoc-gui/src/ui/forwarding.rs`
- Modify: `crates/rustgoc-gui/src/main.rs`
- Test: `crates/rustgoc-gui/src/ui/config.rs`

**Interfaces:**
- Consumes: Task 1 `save_validated` and Task 3 entry replacement.
- Produces: a shared candidate configuration and one `Save and Apply` event handled by `GuiApp`.

- [ ] **Step 1: Write failing tests** proving invalid candidates preserve the previous file and valid server/forwarding edits round trip through `rustgo_config::load_client`.
- [ ] **Step 2: Run the focused tests** and confirm current partial serializer loses P2P data.
- [ ] **Step 3: Make settings and forwarding views edit the same in-memory candidate.** Remove Load/Reload/path controls and expose one Save and Apply action.
- [ ] **Step 4: On successful save, update the displayed endpoint, disconnect, and reconnect from the persisted configuration; on failure retain the runtime and show the validation/write error.**
- [ ] **Step 5: Run `cargo fmt --all -- --check`, `cargo test -p rustgoc-gui`, and `cargo clippy -p rustgoc-gui --all-targets -- -D warnings`.**
- [ ] **Step 6: Build the release GUI, launch it beside a copied fixed configuration, and verify automatic connection plus four-type editor visibility.**
- [ ] **Step 7: Commit** with `feat(gui): apply configuration transactionally`.
