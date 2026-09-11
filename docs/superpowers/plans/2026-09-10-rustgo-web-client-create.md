# Rustgo Web Dynamic Client Creation Plan

**Goal:** Expose the first CSRF-protected dynamic-client management write path.

- [x] Add explicit enrollment-management dependency injection.
- [x] Add bounded JSON `POST /api/v1/clients` handling.
- [x] Return display fields, revision, and the one-time enrollment key without internal identity or public key data.
- [x] Map validation, conflict, capacity, and unavailable failures to stable HTTP categories.
- [x] Keep synchronous SQLite work off the async Web executor.
- [x] Verify the shared codec decodes the returned key and the authoritative store contains the client.
- [x] Create the client and first enrollment token in one SQLite transaction.

Follow-up requirements before production enablement:

- Persist session-scoped operation idempotency outcomes.
- Add enrollment database path and public enrollment address configuration.
- Derive the pinned fingerprint from the actual leaf certificate DER at startup.
