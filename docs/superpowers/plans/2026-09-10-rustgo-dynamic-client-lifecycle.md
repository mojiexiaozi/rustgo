# Rustgo Dynamic Client Lifecycle Plan

**Goal:** Complete the authoritative dynamic-client lifecycle before exposing it through Web management routes.

**Architecture:** Upgrade the enrollment database transactionally to schema v2. Keep all rename, enable, disable, and tombstone rules inside `DynamicClientStore`; Web and authentication integrations will consume these APIs later.

## Task 1: Schema v2 and read model

- [x] Add tombstone state and timestamps through a transactional schema migration.
- [x] List active authoritative client records while hiding tombstones by default.
- [x] Verify v1 databases reopen and migrate without losing clients or tokens.

## Task 2: CAS lifecycle mutations

- [x] Rename with display-ID validation, case-insensitive uniqueness, and revision CAS.
- [x] Disable and enable with revision CAS and active-client capacity enforcement.
- [x] Revoke outstanding tokens when disabling.
- [x] Tombstone deletion with revision CAS and token revocation.
- [x] Reject mutation, issuance, and consumption for tombstoned clients.

## Task 3: Verification

- [x] Run focused lifecycle and enrollment-store tests.
- [x] Run formatting and Clippy for the affected crates.
- [x] Record the existing unrelated observability workspace failure.

Verification note (2026-09-10): `rustgos` enrollment-store tests pass 13/13 and
Clippy passes with warnings denied. The existing unrelated observability workspace
failure remains unchanged.
