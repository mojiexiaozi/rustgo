# Server Managed Tunnels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Manage tunnels, exports and forwards from the server dashboard, including durable offline changes.

**Architecture:** Exchange validated JSON configuration inside bounded versioned control messages after authentication and before resource registration. Persist desired snapshots with revisions in a dedicated SQLite store. Apply mutations by terminating the affected generation and reconciling before the next registration; rebuild client P2P resources per generation.

**Tech Stack:** Rust, Tokio, serde, SQLite/rusqlite, Axum, vanilla JavaScript, egui.

**Spec:** docs/superpowers/specs/2026-09-15-server-managed-tunnels-design.md

## Global Constraints

- All tunnels, exports and forwards are included; no new tunnel kinds.
- Empty snapshots are authoritative and must never trigger reimport.
- Server identity binding is authenticated and stable; no identity from payload is trusted.
- Existing clients negotiate down; remote control requires the new version.
- Changes can interrupt other tunnels of the affected client; communicate this in the UI.
- Existing credentials and P2P policies remain local.
- No silent success on bind errors, offline state, or stale revision acknowledgements.

## Task 1: Shared snapshot contract and versioned protocol

Files: `crates/rustgo-config/src/managed.rs`, config lib/model/p2p serialization derives; protocol message/frame/state/version and tests.

Interfaces: `ManagedConfiguration { tunnels: Vec<TunnelConfig>, exports: Vec<ExportConfig>, forwards: Vec<ForwardConfig>, p2p_enabled: bool }`, `from_client(&ClientConfig)`, `apply_to(&self, &mut ClientConfig) -> Result<(), ValidationError>`, `validate(&self) -> Result<(), ValidationError>`. JSON bytes capped at 65536. Messages `ManagedConfigRequest { configuration: BoundedBytes<65536> }`, `ManagedConfigSnapshot { revision: u64, configuration: Option<BoundedBytes<65536>> }`, `ManagedConfigReport { revision: u64, results: BoundedBytes<65536> }`. Snapshot None means management disabled. `ProtocolVersion::V0_4` and `supports_managed_configuration()` gate exchange. Report JSON is an array of `{kind,name,state,error}` (kind tunnel/export/forward; state ready/failed/pending).

- [ ] Add failing codec roundtrip, old-version state rejection, direction, bounds and invalid snapshot tests; run `cargo test -p rustgo-protocol -p rustgo-config`.
```rust
assert!(!ProtocolVersion::V0_3.supports_managed_configuration());
assert!(ProtocolVersion::V0_4.supports_managed_configuration());
```
- [ ] Implement serde data contracts and validation (existing name/address/port/ACL rules); snapshot apply replaces only three collections and requires locally enabled P2P when needed.
- [ ] Encode/decode new message IDs and allow request/snapshot only during authenticated pre-registration, report only client-to-server active.
- [ ] Re-run focused tests and commit task files.

## Task 2: Durable server store

Files: `crates/rustgos/src/managed.rs`, `crates/rustgos/src/managed/tests.rs`.

Interfaces: `ManagedStore::open(&Path)`, `sync(identity: &str, name: &str, configuration: &ManagedConfiguration) -> Result<ManagedSnapshot, ManagedError>`, `get(name: &str) -> Result<Option<ManagedSnapshot>, ManagedError>`, `replace(name: &str, expected_revision: u64, configuration: &ManagedConfiguration) -> Result<ManagedSnapshot, ManagedError>`, `report(identity: &str, revision: u64, results: serde_json::Value) -> Result<(), ManagedError>`. Snapshot includes name, revision, configuration, applied_revision and results. Errors distinguish invalid, conflict, not found and storage failures. Root integrates module registration.

- [ ] Write regression proving an empty saved snapshot survives database reopen and a later nonempty sync; run its test to observe failure.
```rust
let imported = store.sync("static:key", "node", &initial)?;
store.replace("node", imported.revision, &empty)?;
assert!(store.sync("static:key", "node", &initial)?.configuration.tunnels.is_empty());
```
- [ ] Implement bounded durable transactional import/update and stale-report rejection. Keep identity separate from display name; a different identity cannot inherit an old name's snapshot.
- [ ] Test conflicts, stale reports, rename, same-name replacement and invalid input; commit only owned files.

## Task 3: Server control and authenticated management API

Files: server config/load validation, `crates/rustgos/src/app.rs`, `control.rs`, `web/mod.rs`, `web/api.rs`, new `web/managed.rs`, server integration tests.

- [ ] Add tests for authenticated snapshot exchange and unauthenticated/CSRF write rejection.
- [ ] Open dedicated store from optional `[managed_tunnels] database_path` configuration independent of enrollment. Resolve dynamic stable internal ID or static public-key fingerprint from authenticated identity; update name mapping only after verified auth.
- [ ] Exchange snapshot before registration; reject oversized/invalid JSON and registration not matching the desired snapshot. Persist per-item report only for the bound identity and revision.
- [ ] Implement GET `/api/v1/clients/{name}/tunnels` and POST same path using `{expected_revision, action:"add"|"delete", kind:"tunnel"|"export"|"forward", item|name}`. Validate candidate snapshot transactionally, then terminate only the affected client's generation.
- [ ] Add online and supported indicators; storage errors return unavailable, conflicts return 409. Ensure disabled/deleted identities cannot expose stale snapshots through name reuse.
- [ ] Run server tests and commit server integration.

## Task 4: Client reconciliation and GUI ownership

Files: `crates/rustgoc/src/control.rs`, `app.rs`, `session.rs`, `orchestration.rs`, new `managed.rs`; GUI runtime/state/config/forwarding panels and tests.

- [ ] Add a real handshake test proving a server empty snapshot overrides nonempty local tunnels before registration.
- [ ] Send initial snapshot post-auth, validate received snapshot against local P2P policy and apply before tunnel registration. Make effective config accessible to generation startup.
- [ ] Recreate export registry and P2P runtime for each generation and await shutdown before reuse; report actual per-item readiness/failure once generation setup completes. CLI and GUI use this same code.
- [ ] Expose managed ownership and effective collections through ClientStatus; GUI refreshes rows and disables local writes to managed collections.
- [ ] Test reconnect removal and runtime cleanup, run client/GUI tests, commit owned changes.

## Task 5: Dashboard controls and end-to-end delivery

Files: `crates/rustgos/web/app.js`, `index.html`, styles and JS tests; `tests/e2e` relevant fixtures; deployment notes.

- [ ] Test three-kind rendering, delete names, pending/failed display and revision request payloads.
- [ ] Add detail table, type-specific forms, ACL explanation, deletion action and interruption notice. Fetch managed detail separately from existing names-only inventory.
- [ ] Exercise TCP/UDP forwarding and export/forward lifecycle, offline add/delete, process restart, port conflicts and old-client downgrade using real processes.
- [ ] Run fmt, clippy, relevant workspace tests and release builds; obtain code review and address findings.
- [ ] Deploy with existing backup/rollback workflow, update local GUI and verify live all-kind inventory and a reversible test tunnel lifecycle. Record exact verification and remaining limitations.

## Execution rulings

- Continue in the existing `codex/approval-closeout-20260914` development checkout; user has repeatedly authorized continuing this workspace. Do not move production client assets or unrelated untracked files.
- Execute without another workflow-choice prompt because the user has approved the design and requested continuation. Use focused agents for isolated task files and root for integration.
- New management storage is opt-in via server configuration; production deployment enables it. A configured storage failure fails closed. Old servers continue to work by version negotiation.
- Review ruling: capability metadata is structurally separate from collection validity. Local P2P-disabled configurations can report preserved collections; additions require enabled capability, and application validates actual local policy.
- Review ruling: configuration rejection reports are also accepted after authenticated snapshot delivery and before registration. They must match the bound revision and contain only failed item results; no listeners are registered. This exposes local-policy failures without widening unauthenticated access.
