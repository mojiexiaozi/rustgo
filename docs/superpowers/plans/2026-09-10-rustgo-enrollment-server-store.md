# Rustgo Enrollment Server Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independent SQLite authority that creates dynamic clients, issues one-time enrollment keys, and atomically consumes them with idempotent replay semantics.

**Architecture:** The bounded enrollment-key wire encoding moves to `rustgo-protocol` so client and server share one implementation. A synchronous `rustgos::enrollment::DynamicClientStore` owns a private SQLite connection behind a mutex; every mutating operation uses an immediate transaction and the database remains authoritative.

**Tech Stack:** Rust 2024, rusqlite bundled SQLite, SHA-256, OS randomness, constant-time comparisons, serde-free bounded binary token format.

**Spec:** `docs/superpowers/specs/2026-09-04-rustgo-chinese-web-gui-enrollment-design.md`

## Global Constraints

- Enrollment plaintext is returned only from successful issuance and is never persisted or logged.
- Dynamic client IDs are 1–64 UTF-8 bytes and contain only ASCII letters, digits, dot, underscore, or hyphen; uniqueness is ASCII case-insensitive.
- Device public keys are unique and never selected by display ID during authentication.
- Token consumption and public-key binding are one SQLite transaction.
- Failed validation never consumes a token.
- Same target, public key, and request ID may replay the original success; all other replays fail.
- This slice does not add Web routes or TLS enrollment messages.

---

### Task 1: Shared enrollment-key codec

**Files:**
- Create: `crates/rustgo-protocol/src/enrollment.rs`
- Modify: `crates/rustgo-protocol/src/lib.rs`
- Modify: `crates/rustgoc/src/enrollment/key.rs`
- Test: `crates/rustgo-protocol/tests/enrollment.rs`

**Interfaces:**
- Produces: `EnrollmentKeyMaterial::encode() -> String` and `EnrollmentKeyMaterial::decode(&str) -> Result<Self, EnrollmentKeyCodecError>`.
- Produces: `EnrollmentPurpose::{Enroll, ReEnroll}`.
- `Debug` redacts fingerprint and token bytes.

- [x] Write codec tests covering round trip, exact bounds, checksum mutation, unsupported version, invalid address, purpose, and trailing bytes.
- [x] Run `cargo test -p rustgo-protocol --test enrollment` and verify the missing API causes RED.
- [x] Move the existing bounded parser and add encoding with OS-generated token supplied by the caller.
- [x] Adapt `rustgoc::EnrollmentKey` as a thin wrapper and run protocol plus client enrollment tests GREEN.

### Task 2: SQLite authority and dynamic-client creation

**Files:**
- Create: `crates/rustgos/src/enrollment/mod.rs`
- Create: `crates/rustgos/src/enrollment/store.rs`
- Modify: `crates/rustgos/src/lib.rs`
- Modify: `crates/rustgos/Cargo.toml`
- Test: `crates/rustgos/tests/enrollment_store.rs`

**Interfaces:**
- Produces: `DynamicClientStore::open(path, EnrollmentStoreLimits) -> Result<Self, EnrollmentStoreError>`.
- Produces: `create_client(display_id) -> Result<DynamicClient, EnrollmentStoreError>`.
- `DynamicClient` exposes opaque internal ID, display ID, enabled state, revision, and bound/unbound state.

- [x] Write tests for schema bootstrap, persistence after reopen, ID normalization, case-insensitive collision, invalid IDs, and active-client capacity.
- [x] Run the focused test and verify RED from the missing store API.
- [x] Implement schema version 1 with `dynamic_clients`, `enrollment_tokens`, and unique normalized-ID/public-key indexes.
- [x] Implement validation and transactional creation, then run the focused tests GREEN.

### Task 3: One-time token issuance

**Files:**
- Modify: `crates/rustgos/src/enrollment/store.rs`
- Test: `crates/rustgos/tests/enrollment_store.rs`

**Interfaces:**
- Produces: `issue_token(internal_id, purpose, server_addr, fingerprint, ttl, expected_revision) -> Result<IssuedEnrollmentKey, EnrollmentStoreError>`.
- `IssuedEnrollmentKey` exposes plaintext once through ownership and redacts it from `Debug`.

- [x] Write tests proving plaintext decodes through the shared codec, database bytes do not contain plaintext/token, reissue revokes an older unconsumed token, and revision mismatch returns conflict.
- [x] Run focused issuance tests and verify RED.
- [x] Generate 32-byte token plus 16-byte salt, store `SHA256(salt || complete_encoded_key)`, persist metadata, and return the encoded key only in the result.
- [x] Run issuance tests GREEN.

### Task 4: Atomic consumption, concurrency, and replay

**Files:**
- Modify: `crates/rustgos/src/enrollment/store.rs`
- Test: `crates/rustgos/tests/enrollment_store.rs`

**Interfaces:**
- Produces: `consume_token(encoded_key, public_key, request_id, now) -> Result<EnrollmentResult, EnrollmentStoreError>`.
- `EnrollmentResult` returns the current display ID and credential revision.

- [x] Write tests for success, wrong token, expiry, purpose mismatch, already-bound client, public-key collision, disabled client, exact idempotent replay, mismatched replay, and two-thread concurrent consumption.
- [x] Run focused consumption tests and verify RED.
- [x] Use an immediate transaction, bounded candidate lookup, constant-time hash comparison, revision CAS, public-key bind, token consume, and replay fields in one commit.
- [x] Run all store tests GREEN and reopen the database to verify durability.

### Task 5: Verification

**Files:**
- Modify: `docs/superpowers/plans/2026-09-10-rustgo-enrollment-server-store.md`

**Interfaces:**
- Consumes all preceding APIs.
- Produces a verified server storage foundation for later Web and TLS integration.

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test -p rustgo-protocol --test enrollment`.
- [x] Run `cargo test -p rustgoc --test enrollment`.
- [x] Run `cargo test -p rustgos --test enrollment_store`.
- [x] Run `cargo clippy -p rustgo-protocol -p rustgoc -p rustgos --all-targets -- -D warnings`.
- [x] Record the unrelated `rustgo-observability/sqlite_history` workspace-gate failures without changing that crate in this slice.

Verification note (2026-09-10): all focused enrollment gates above pass. The pre-existing
workspace gate remains blocked by 41 `rustgo-observability/tests/sqlite_history.rs`
failures (`Elapsed`/`Unavailable`), reproduced both normally and single-threaded before
this server-store slice; no observability files were changed here.
