# Rustgo Enrollment Client Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the GUI enrollment placeholder with a shared, testable client foundation that classifies identity state, parses one-time enrollment keys, and persists recoverable pending enrollment state.

**Architecture:** `rustgo-config` owns backward-compatible identity configuration, while `rustgoc` owns enrollment key parsing, startup classification, and pending-state persistence. The GUI consumes those public APIs and never parses secrets or infers enrollment state from generic crypto errors.

**Tech Stack:** Rust 2024, serde/TOML, rustgo-config, rustgo-crypto, rustgoc, eframe/egui.

**Spec:** `docs/superpowers/specs/2026-09-04-rustgo-chinese-web-gui-enrollment-design.md`

## Global Constraints

- Existing client configurations without `identity_mode` remain compatible.
- Explicit static mode with a missing key is a configuration error.
- Dynamic mode with a missing or invalid key requires re-enrollment.
- Enrollment secrets never appear in `Debug`, errors, logs, configuration, or pending metadata.
- Pending metadata and candidate keys use atomic replacement and survive process restart.
- This slice does not implement server token issuance or token consumption.

---

### Task 1: Backward-compatible identity configuration

**Files:**
- Modify: `crates/rustgo-config/src/model.rs`
- Modify: `crates/rustgo-config/src/lib.rs`
- Modify: `crates/rustgo-config/src/validate.rs`
- Test: `crates/rustgo-config/tests/config.rs`

**Interfaces:**
- Produces: `IdentityMode::{Static, Dynamic}` and `ClientSection.identity_mode: Option<IdentityMode>`.
- Consumes: existing `load_client` and `ClientConfig::validate` behavior.

- [ ] **Step 1: Write failing compatibility tests**

Add tests proving an omitted mode remains `None`, `identity_mode = "static"` parses as `Static`, and `identity_mode = "dynamic"` parses as `Dynamic`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p rustgo-config --test config identity_mode`

Expected: compilation fails because `IdentityMode` and `identity_mode` do not exist.

- [ ] **Step 3: Implement the model and validation changes**

Add a lowercase-deserialized enum and optional field. Preserve all existing validation for legacy and static configurations; allow the startup classifier to handle dynamic key absence.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p rustgo-config --test config identity_mode`

Expected: all identity-mode tests pass.

### Task 2: Enrollment key parser

**Files:**
- Create: `crates/rustgoc/src/enrollment/key.rs`
- Create: `crates/rustgoc/src/enrollment/mod.rs`
- Modify: `crates/rustgoc/src/lib.rs`
- Test: `crates/rustgoc/tests/enrollment.rs`

**Interfaces:**
- Produces: `EnrollmentKey::parse(&str) -> Result<EnrollmentKey, EnrollmentError>`.
- Produces accessors for version, canonical `host:port`, 32-byte certificate fingerprint, purpose, and opaque token bytes.
- Never produces a secret-bearing `Debug` representation.

- [ ] **Step 1: Write failing parser tests**

Cover a valid versioned key plus rejection of empty, oversized, malformed-base64, unsupported-version, invalid-address, invalid-fingerprint, invalid-purpose, bad-checksum, and trailing-data inputs. Assert that `Debug` and every error omit the original token.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p rustgoc --test enrollment enrollment_key`

Expected: compilation fails because the enrollment API does not exist.

- [ ] **Step 3: Implement the bounded parser**

Use a fixed textual prefix and URL-safe base64 payload with explicit field lengths. Validate the non-secret checksum before exposing parsed metadata, cap encoded and decoded sizes, and zero temporary secret buffers where supported.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p rustgoc --test enrollment enrollment_key`

Expected: all parser tests pass without printing secret material.

### Task 3: Shared startup classification

**Files:**
- Create: `crates/rustgoc/src/enrollment/state.rs`
- Modify: `crates/rustgoc/src/enrollment/mod.rs`
- Test: `crates/rustgoc/tests/enrollment.rs`

**Interfaces:**
- Produces: `EnrollmentState::{Ready, RegistrationRequired, ReRegistrationRequired, EnrollmentPending, ReEnrollmentPending}`.
- Produces: `classify_enrollment_state(config: &ClientConfig, config_path: &Path) -> Result<EnrollmentState, EnrollmentError>`.

- [ ] **Step 1: Write failing state-matrix tests**

Cover the exact startup order from the spec: valid re-enrollment pending, valid enrollment pending, explicit dynamic missing/corrupt key, explicit static missing key, legacy valid key, and legacy missing key.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p rustgoc --test enrollment startup_state`

Expected: compilation fails because the classifier does not exist.

- [ ] **Step 3: Implement minimal classification**

Inspect metadata before the final private-key path, validate candidate-key correspondence, and return a stable error for malformed or unsafe pending state. Do not translate network or authentication failures into enrollment states.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p rustgoc --test enrollment startup_state`

Expected: the complete state matrix passes.

### Task 4: Atomic pending-state persistence

**Files:**
- Create: `crates/rustgoc/src/enrollment/pending.rs`
- Modify: `crates/rustgoc/src/enrollment/mod.rs`
- Test: `crates/rustgoc/tests/enrollment.rs`

**Interfaces:**
- Produces: `PendingEnrollment::create(...)`, `PendingEnrollment::load(...)`, and `PendingEnrollment::promote(...)`.
- Consumes: `rustgo_crypto::generate_key_file` and the parsed key's non-secret server metadata.

- [ ] **Step 1: Write failing persistence tests**

Use a temporary directory to prove candidate key and metadata are created, the token is absent from every file, malformed metadata fails closed, reload restores the same public key and request ID, and promotion installs the final key while removing pending metadata.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p rustgoc --test enrollment pending`

Expected: compilation fails because pending persistence APIs do not exist.

- [ ] **Step 3: Implement atomic persistence**

Write candidate key first, write versioned TOML metadata to a sibling temporary file, flush files, atomically rename them, and restrict permissions on supported platforms. Promotion must never overwrite an unrelated final key.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p rustgoc --test enrollment pending`

Expected: persistence and recovery tests pass.

### Task 5: GUI integration and slice verification

**Files:**
- Modify: `crates/rustgoc-gui/src/main.rs`
- Delete: `crates/rustgoc-gui/src/state/enrollment.rs`
- Modify: `crates/rustgoc-gui/src/state/mod.rs`
- Modify: `crates/rustgoc-gui/src/ui/enrollment.rs`
- Test: `crates/rustgoc-gui/src/ui/enrollment.rs`

**Interfaces:**
- Consumes: `rustgoc::classify_enrollment_state`, `EnrollmentKey::parse`, and `PendingEnrollment::create`.
- Produces: GUI validation and pending creation ready for the later server-registration transport task.

- [ ] **Step 1: Write failing GUI behavior tests**

Extract a small submit-result presenter and test that malformed keys show a stable Chinese error, accepted keys clear the input immediately, and no rendered message contains the entered secret.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p rustgoc-gui enrollment`

Expected: tests fail because the GUI still uses its local error-based state and placeholder submit handler.

- [ ] **Step 3: Replace the placeholder integration**

Classify state before constructing `ClientApp`, render first/re-enrollment consistently, parse submitted keys through `rustgoc`, persist pending state, clear the secret, and report that the local registration request is prepared. Do not claim server registration succeeded in this slice.

- [ ] **Step 4: Run focused and regression verification**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p rustgo-config -p rustgoc -p rustgoc-gui`

Run: `cargo clippy -p rustgo-config -p rustgoc -p rustgoc-gui --all-targets -- -D warnings`

Expected: all commands pass with no warnings.
