# Enrollment by administrator approval

Approved requirements: clients automatically request access or replacement keys; the server creates/binds the client only on approval. Management exposes approval, rejection, and deletion, without manual client creation or key issuance.

- [x] Persist bounded, expiring requests and bind keys atomically on approval. Preserve optimistic revision checks, static identity isolation and idempotent polling.
- [x] Transport requests over configured TLS trust. Keep candidate keys and request IDs across restart; promote only after approval.
- [x] Show native waiting/retry state and automatic polling. Provide a replacement-key request action.
- [x] Show pending requests with public-key fingerprints and approve/reject actions in management; retain deletion only for clients.
- [x] Verify store lifecycle, network registration, authenticated management APIs, UI tests and release builds.

Existing unrelated working changes and the previous layout fix must be preserved. No remote deployment or running-process interruption.

Implementation verified: signed public-key requests over verified TLS; valid keys and request IDs reused across restart; expired pending requests renew without key rotation; approval is idempotent. CLI uses executable-adjacent client.toml and waits without a key. Explicit rotation preserves the current key until approval.

Validation: approval store and TLS/CLI integration tests, enrollment recovery tests, authenticated/CSRF API tests, browser management tests, CLI configuration tests, GUI/client/server library tests passed. All six logging process tests passed after migrating the fixed client config path. P2P and peer-process test targets compile. Windows release and Linux x86_64 cross-build succeeded; Linux binaries were not runtime-tested. Isolated deployment package excludes private keys; no remote deployment performed.

2026-09-14 closeout: fixed GUI approval recovery, hidden-window completion and credential path resolution; refreshed documentation, Compose and E2E entrypoints. Windows P2P process tests now run successfully. Windows release smoke passed and binaries/checksums were refreshed. See [closeout evidence](../implementation-notes/2026-09-14-release-closeout.md) for exact test scope and Linux limitations.
