# Rustgo Dynamic Enrollment Completion Master Plan

**Goal:** Finish the production dynamic-enrollment feature across server storage, Web management, TLS protocol, client runtime, CLI, GUI, authentication, and operations.

## 1. Web operation idempotency (complete)

- [x] Bind operation IDs to administrator sessions and endpoints.
- [x] Bound retained operation state and concurrent in-flight operations.
- [x] Return stable secret-unavailable results after successful secret responses are lost.
- [x] Reject operation-ID reuse with different request bodies.

## 2. Complete Web management API (complete)

- [x] Resolve dynamic clients by validated display ID without exposing internal IDs.
- [x] Add enrollment-token and reenrollment-token endpoints.
- [x] Add rename and enable/disable endpoints with revision CAS.
- [x] Add tombstone-delete endpoint with revision CAS.
- [x] Merge dynamic records into safe list/detail presentation DTOs.
- [x] Add stable 401/403/409/422/503 mappings and bounded bodies.

## 3. Production configuration and startup (complete)

- [x] Add enrollment database path, public enrollment address, limits, and TTL configuration with compatible defaults.
- [x] Resolve paths and validate all new bounds.
- [x] Compute the pin from the actual leaf certificate DER.
- [x] Open/migrate the authority fail-closed without breaking static-only configurations.
- [x] Inject enrollment management into the production Web server.
- [x] Reject static/dynamic display-ID and public-key collisions.

## 4. Versioned enrollment TLS protocol (complete)

- [x] Add bounded request/result/error messages without changing legacy handshake bytes.
- [x] Add fingerprint-pinned TLS client construction.
- [x] Add server enrollment dispatch before normal authentication.
- [x] Apply connection, read, write, transaction, and attempt-rate limits.
- [x] Map storage failures to stable non-enumerating public errors.

## 5. Client enrollment runtime (complete)

- [x] Generate and persist candidate identity plus request ID before network submission.
- [x] Submit initial and re-enrollment requests through the shared client state machine.
- [x] Recover from response loss using pending-key dynamic authentication.
- [x] Atomically promote the candidate key and update pinned dynamic configuration.
- [x] Preserve recoverable pending state on every failure boundary.

## 6. Dynamic authentication and session lifecycle (complete)

- [x] Authenticate dynamic identities by public key and signature, never by display ID.
- [x] Project current display IDs from the authority on every new authentication.
- [x] Keep legacy static authentication wire-compatible.
- [x] Terminate active sessions immediately on disable, delete, or successful re-enrollment.
- [x] Propagate rename revisions to active clients and observability projections.

## 7. CLI and GUI completion (complete)

- [x] Add secure interactive, stdin, and environment enrollment-key input to CLI.
- [x] Add explicit CLI re-enroll flow with destructive-key confirmation.
- [x] Connect GUI enrollment submission to the real shared runtime.
- [x] Show precise pending, failure, recovery, and completion stages.
- [x] Require GUI confirmation before replacing an existing private key.

## 8. Chinese Web client management UI (complete)

- [x] Add dynamic client creation and one-time secret display.
- [x] Add rename, enable/disable, reissue, re-enroll, and delete controls.
- [x] Keep secrets only in current page memory and clear them on navigation.
- [x] Add Chinese validation, conflict, unavailable, and confirmation states.

## 9. Operational hardening and final verification

- [x] Add bounded audit records without secrets and retention cleanup.
- [x] Add tombstone retention and bounded purge behavior.
- [x] Add database health reporting and fail-closed dynamic-auth behavior.
- [x] Run focused protocol, server, client, CLI, GUI, Web, and process tests.
- [x] Run formatting, Clippy, diff checks, and the workspace gate.
- [x] Document the known unrelated observability failure if it remains.

Final verification on 2026-09-11:

- `cargo test -p rustgo-protocol`, `cargo test -p rustgo-config`,
  `cargo test -p rustgos`, `cargo test -p rustgoc`, and
  `cargo test -p rustgoc-gui` passed, including enrollment, Web, GUI, and
  multi-process TCP/UDP tests.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `git diff --check` passed.
- The first `cargo test --workspace` run exposed 41 Windows-only failures in
  `rustgo-observability/tests/sqlite_history.rs`. The full random ownership nonce
  appeared in nested private-store and active-database file names, causing durable
  temporary files and SQLite sidecars to exceed the traditional Windows path limit.
  Windows path components now retain 128 random bits while markers and database
  ownership proofs retain the full 256-bit nonce. The SQLite suite subsequently
  passed 53/53 and a fresh `cargo test --workspace --quiet` passed in full.

Progress at creation: storage authority, token issuance/consumption, lifecycle schema,
CSRF, and atomic Web client creation are complete and covered by focused tests.
