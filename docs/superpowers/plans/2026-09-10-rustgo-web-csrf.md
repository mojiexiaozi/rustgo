# Rustgo Web CSRF Foundation Plan

**Goal:** Add a session-bound CSRF credential before enabling dashboard write APIs.

## Tasks

- [x] Derive a 256-bit CSRF credential from each authenticated session without exposing the session cookie.
- [x] Return the credential on successful login and authenticated dashboard loads.
- [x] Validate credentials in constant time and reject malformed, expired, evicted, or logged-out sessions.
- [x] Verify rotation across logins, idle expiry, logout invalidation, response cache policy, and Clippy.
