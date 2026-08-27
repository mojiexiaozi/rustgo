# Task 7 Report: Client control lifecycle and tunnel registration

## Status and commit

- Status: complete for the Task 7 client control-plane scope.
- Commit: `feat: add client control and reconnect lifecycle` (the commit containing this report).
- Worktree: `C:\Users\kimi\Desktop\projects\rustgo\.worktrees\v0.1`.
- Branch: `codex/rustgo-v0.1`.

## Approved cross-task rulings

The parent task approved two minimal corrections required to make the already-designed components usable together:

1. `ClientSection` now requires `certificate_authority_file: PathBuf`. It is resolved relative to the client TOML, `check` requires the file to exist, and runtime TLS trusts only that explicit CA file. There is no system-root or insecure fallback. Task 11 will update operator examples/documentation.
2. `ClientHello` now carries `heartbeat_interval_secs: u32`. Client configuration rejects zero and values above `u32::MAX`. Before challenge generation or signature verification, Rustgos requires `0 < client interval < server heartbeat timeout`; incompatibility returns stable `INCOMPATIBLE_HEARTBEAT` and closes the attempt. V0.1 is unpublished, so the protocol remains version 1.0.

## Requirement mapping

| Requirement | Implementation and evidence |
| --- | --- |
| Load local security state before network | `ControlClient::from_config` validates the client model, loads the Ed25519 private key, and constructs the TLS 1.3 client from the explicit CA and server name. Only `connect` opens a socket. The binary builds `ClientApp` before entering `run`. |
| Strict TLS -> hello -> challenge -> authenticate -> register order | `ControlClient::connect_inner` drives the existing `ClientHandshakeState`, checks every negotiated frame version, signs the exact canonical challenge/session/version/name transcript, and cannot construct/send registration until `AuthResult.accepted=true`. |
| Complete configured identity and tunnel projection | Hello contains configured name, SHA-256 fingerprint bytes, and bounded heartbeat interval. Registration deterministically assigns nonzero IDs in configuration order and maps both TCP and UDP definitions. |
| Preserve each success/failure result | `RegisteredTunnel` is an immutable public value with private fields/getters. Result correlation requires exactly one known result per configured ID, preserves configuration identity/local target, and retains `accepted` plus typed error independently for every tunnel. |
| Current-generation-only active state | `ClientStatus` contains at most one `ActiveGeneration`. Generation numbers are allocated only after authentication and complete registration. Any control exit replaces status with disconnected before child cancellation/join can block, so stale results are never presented as current. |
| Heartbeat liveness | The client emits sequenced heartbeats and accepts only ordered acknowledgements from the negotiated version. Two intervals without valid server activity end the generation. Rustgos now echoes each validated heartbeat under its bounded heartbeat timeout; a real `ServerApp` integration test holds one generation active across three exchanges. |
| Jittered capped reconnect and stable reset | `ClientApp` consumes the existing injectable `Backoff`. Paused-time TLS tests observe maximum-jitter delays of 120 ms, 200 ms, 200 ms, then prove a five-second authenticated generation resets the next delay to 120 ms. Every later generation submits the full configured tunnel list again. |
| Generation-owned child seam | `ChildSessionSupervisor::run_child` receives a redacted `ChildSessionContext` containing the exact generation/session ID, one typed TCP/UDP request, and a child cancellation token. Task 8/9 can implement payload/data TLS behind this seam without moving ownership out of the control generation. |
| Cancel and join before new generation | Every child future is owned by a `JoinSet`. On heartbeat loss, protocol/I/O failure, or shutdown, status clears, the generation token is cancelled, and every child is joined before `run_generation` returns. `ClientApp` cannot enter backoff or connect a new generation before that return. |
| Ctrl+C and runtime wiring | `ClientApp::run` pins `run_until`, converts Ctrl+C into cancellation, then awaits runtime convergence. Cancellation wins over connect and backoff sleeps. The lifecycle regression additionally holds an active child after cancellation and proves the app does not finish until that child is released and joined. The no-subcommand CLI now enters this runtime; `check` remains local. |
| Relay-only scope | No NAT, peer discovery, hole punching, QUIC P2P, or direct path was introduced. Task 8/9 remain responsible only for V0.1 relay payloads behind the child seam. |

## RED / GREEN evidence

### 1. Explicit CA and heartbeat compatibility ruling

RED commands:

```text
cargo test -p rustgo-config --test config --no-fail-fast
cargo test -p rustgo-protocol --test state --no-fail-fast
cargo test -p rustgos --test control heartbeat_interval_must_be_strictly_below_server_timeout_before_challenge -- --exact --nocapture
```

Observed failures were the missing `ClientSection.certificate_authority_file`, missing `ClientHello.heartbeat_interval_secs`, and missing `ProtocolErrorCode::INCOMPATIBLE_HEARTBEAT`. GREEN added config-relative CA resolution/reference checking, bounded wire conversion, the stable error code, and the pre-challenge server runtime check. The focused suites passed 14 config tests, 9 state tests, and the real TLS compatibility test.

### 2. Scripted TLS handshake and per-tunnel results

RED command:

```text
cargo test -p rustgoc --test control --no-fail-fast
```

The first compile failed because the Rustgoc library, `ControlClient`, `ControlSession`, `RegisteredTunnel`, and the CA config field did not exist. GREEN used a real generated CA/server certificate and actual `TlsServer` to verify hello name/fingerprint/interval, exact Ed25519 transcript verification, authentication before registration, full TCP+UDP registration, and one rejected plus one accepted result. A separate rejection test proves no registration is sent after failed authentication.

### 3. Reconnect, generation, cancellation, and shutdown

RED initially failed on missing `ClientApp`, `ClientStatus`, `SessionGeneration`, and `ChildSessionSupervisor`. GREEN paused-time tests exercise real TLS sessions while injecting maximum jitter and a Tokio-backed `BackoffClock`:

- failed connections wait 120 ms, 200 ms, and 200 ms at the cap;
- a stable authenticated generation resets the next delay to 120 ms;
- both generations register `ssh` and `game` again;
- missing heartbeat acknowledgements clear active state, cancel TCP and UDP children, and prevent generation 2 until both children join;
- generation/session ID reach each child through `ChildSessionContext` while Debug redacts the session ID;
- shutdown during an active generation cancels its child and does not finish until the child joins;
- shutdown while connecting/retrying interrupts the retry loop.

The paused TLS fixtures use a manual-time guard only while awaiting real socket readiness. The guard is aborted and joined before every explicit `advance`, preventing Tokio's idle auto-advance from racing the real socket without blocking deliberate clock movement.

### 4. Real server heartbeat and CLI runtime

The real `ServerApp` heartbeat test first failed after two seconds because Rustgos validated but did not acknowledge heartbeats. GREEN echoes the validated sequence under a bounded write timeout; one client generation remains active across three real one-second exchanges.

The CLI RED test observed exit 0 with invalid identity material because `LocalCommandHandler::run` was still a stub. GREEN constructs `ClientApp`, creates the Tokio runtime, and awaits Ctrl+C-aware execution; the same fixture now fails closed before network startup.

### 5. Bounded stalled handshake

The stalled scripted TLS server test first failed to compile because `ClientError::HandshakeTimeout` did not exist. GREEN places one ten-second bound over TCP/TLS/version/auth/registration setup, returning the typed timeout so one silent peer cannot block reconnection forever.

## Generation, cancellation, and reconnect invariants

1. A generation ID is allocated only after TLS, negotiated hello/challenge authentication, `AuthResult.accepted`, complete registration send, and structurally valid per-tunnel results.
2. `ClientStatus.active` belongs to exactly that generation and its immutable result array. Failed connection attempts consume no generation ID.
3. On every active-session terminal path, status becomes disconnected before the generation cancellation token fires.
4. The generation owns every child future. Cancellation is broadcast once; all `JoinSet` entries are joined. A new generation cannot begin while any prior child remains.
5. Backoff is advanced only after a complete failed attempt/generation. `mark_connected` occurs only for an authenticated, registered generation; reset occurs only when that generation reaches the configured stable threshold.
6. Reconnection always rebuilds registration from the authoritative `ClientConfig`; no prior active/result projection is reused.
7. Ctrl+C cancels in-flight connect, active generation, or sleep, then awaits the same child-join path before returning.
8. The session ID is available only to the child supervisor context and is redacted from Debug/status. Active UI/status does not expose it.

## Final verification

Final commands are run after the report and implementation are formatted:

```text
cargo test -p rustgoc --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

Observed result: every command exited 0. Rustgoc passed 15 tests, including 7 control tests. The workspace passed 134 tests; all doc tests passed. Formatting was clean, workspace/all-target Clippy emitted no warnings with warnings denied, and `git diff --check` reported no whitespace errors.

## Self-review

- Reviewed the complete control/app/session ownership chain rather than only callback observations. The TLS scripts use real framing, rustls sockets, and Ed25519 verification.
- Checked every terminal path: connect error, auth rejection, malformed state/version/result, heartbeat timeout, EOF/I/O, child panic, external cancellation, and retry sleep cancellation.
- Checked that status clearing precedes potentially blocking child join and that the next `connect` occurs only after the join loop.
- Checked bounded/nonwrapping counters for tunnel IDs, generation IDs, heartbeat sequences, frame buffering, handshake duration, heartbeat deadline, and existing backoff cap.
- Checked diagnostics: key material is held by the redacted `DeviceKeypair`; session IDs are redacted; challenge/signature/application payloads are not logged.
- Because this task explicitly prohibited subagents, the requested review was performed as an inline requirement/security/concurrency self-review rather than dispatching the code-review skill's reviewer agent.

## Concerns and deferred boundaries

- `NoopChildSessionSupervisor` deliberately owns placeholder children until generation cancellation. Tasks 8/9 must replace it with concrete TCP/UDP relay children while preserving the same cancellation token and join contract.
- The ten-second setup timeout and default 1-second-to-60-second reconnect policy are bounded runtime defaults, not TOML fields. Operator-tunable additions would require a deliberate strict-schema update.
- Client liveness uses two missed heartbeat intervals; server admission independently guarantees its configured timeout is strictly greater than the announced interval. Either side closing the control socket still invalidates the generation immediately.
- Task 11 must add `certificate_authority_file` to published examples/operator documentation as already ruled.
- TCP/UDP payload forwarding is intentionally absent until Tasks 8/9. P2P remains V0.2-only.

---

## Review fix round 1 (2026-08-28)

### Status and commits

- Status: all four open review findings are resolved and covered by regression tests.
- Base implementation: `be358bd feat: add client control and reconnect lifecycle`.
- Follow-up: `fix: harden client liveness and reconnect boundaries` (the follow-up commit containing this appendix).

### Finding-to-fix mapping

| Finding | Fix and evidence |
| --- | --- |
| Business traffic masked heartbeat loss | `last_heartbeat_acknowledgement` advances only after a Heartbeat frame passes negotiated-version and monotonic sequence checks. `OpenTcpStream` and `OpenUdpChannel` no longer count as liveness. A paused-time real-TLS test delivers business frames every 500 ms without acknowledging heartbeats and observes generation 1 become inactive and all spawned children receive cancellation at the two-interval deadline. |
| Backpressured active write blocked shutdown | Active heartbeat writes run inside a biased shutdown select and a one-heartbeat-interval timeout. On every control-loop exit, the framed control stream is dropped before status invalidation and child cancellation/join. A capacity-one duplex control peer deterministically blocks `write_all`; cancellation completes the generation within the bounded assertion and the peer observes EOF. |
| Child drain incorrectly contributed to stability | `Backoff::mark_disconnected` freezes stability at control loss. `ClientApp` calls it in the same synchronous inactive callback that clears current-generation status, before child cancellation/join. A real-TLS paused-time regression primes backoff to its cap, holds a child for ten seconds after a short generation disconnects, and proves reconnect still waits 200 ms rather than resetting to 120 ms. A transport unit test independently advances its injected clock by 100 seconds after disconnect and proves that time cannot reset attempts. |
| Wire projection failed only after networking | Shared `ClientConfig::validate` now uses protocol-owned `MAX_CLIENT_NAME_BYTES`, `MAX_TUNNEL_NAME_BYTES`, and `MAX_TUNNELS`; client and tunnel names are measured in UTF-8 bytes, heartbeat and ports retain their bounded checks, and tunnel count is rejected above 64. The same name bound is applied to server authorized-client entries. A CLI test gives both `check` and default run a 65-tunnel config, requires the configuration error, and proves a reserved listener accepted no socket. |

### RED / GREEN evidence

#### 1. Heartbeat acknowledgement authority

RED:

```text
cargo test -p rustgoc --test control business_frames_cannot_mask_missing_heartbeat_acknowledgements -- --exact --nocapture
```

The new test failed at `status.borrow().active().is_none()`: three valid `OpenTcpStream` frames kept the old generation active without any Heartbeat acknowledgement. GREEN moved the liveness timestamp update into the validated Heartbeat arm only. The new test plus the existing heartbeat-loss and real-server heartbeat tests all pass.

#### 2. Shutdown-safe bounded active writes

RED:

```text
cargo test -p rustgoc --lib shutdown_interrupts_a_backpressured_active_control_write -- --nocapture
```

The capacity-one peer caused the old heartbeat `write_all` to remain pending; the 100 ms shutdown assertion expired. GREEN introduced an internal boxed async control-I/O boundary for deterministic testing, supervises active writes with shutdown plus timeout, and drops that stream before child teardown. The regression passes and observes partial output followed by EOF.

#### 3. Frozen generation duration

RED:

```text
cargo test -p rustgo-transport --test backoff time_after_disconnect_cannot_make_a_short_connection_stable -- --exact --nocapture
cargo test -p rustgoc --test control slow_child_drain_does_not_turn_a_short_generation_into_a_stable_one -- --exact --nocapture
```

The transport test first failed to compile because `mark_disconnected` did not exist. After adding the clock-freeze primitive but before wiring it into `ClientApp`, the real-TLS lifecycle test reconnected at 120 ms: ten seconds of blocked child drain had reset the old backoff. GREEN invokes the freeze in the inactive callback before join; the test now observes no reconnect at 120 ms and the capped reconnect at 200 ms.

#### 4. Pre-network wire bounds

RED:

```text
cargo test -p rustgo-config --test config client_and_tunnel_name_limits_count_utf8_bytes -- --exact --nocapture
cargo test -p rustgo-config --test config client_rejects_more_tunnels_than_the_wire_can_encode -- --exact --nocapture
cargo test -p rustgoc --test cli_config wire_overflow_is_rejected_by_check_and_run_before_opening_a_socket -- --exact --nocapture
```

The configuration tests accepted both a 129-byte/43-character multibyte name and 65 tunnels; CLI `check` also exited successfully. GREEN centralizes the protocol constants in shared validation. Both CLI modes now report `invalid configuration`, and the nonblocking reserved listener reports `WouldBlock` after both invocations.

### Updated generation, cancellation, and reconnect invariants

1. Only an in-range, strictly newer Heartbeat acknowledgement for a sequence already sent by this generation advances client liveness. Business control messages have no liveness authority.
2. Every active control write is bounded by both the generation shutdown token and a finite timeout. Cancellation is biased when simultaneously ready.
3. A terminal control loop relinquishes its control stream before any child drain can wait; no defunct generation retains that transport while its children converge.
4. The inactive callback freezes backoff duration and clears `ClientStatus.active` synchronously before child cancellation. Child cancellation/join latency is excluded from connection stability.
5. All children remain generation-owned and are still fully joined before backoff sleep or the next socket attempt; no fix weakened generation isolation.
6. Client identity/tunnel projection is guaranteed wire-encodable during shared config load. `check` and run therefore fail before file parsing or socket creation for these bounds.
7. Registration order and per-tunnel result correlation are unchanged; every reconnect still performs TLS -> hello -> challenge/signature -> auth -> full register.
8. Ctrl+C cancels connect, active read/write, or backoff sleep and then uses the same stream-drop plus child cancel/join convergence path.

### Verification after the fixes

Commands executed from `C:\Users\kimi\Desktop\projects\rustgo\.worktrees\v0.1`:

```text
cargo fmt --all -- --check
cargo test -p rustgoc --no-fail-fast
cargo test -p rustgo-config --no-fail-fast
cargo test -p rustgo-protocol --no-fail-fast
cargo test -p rustgo-transport --test backoff --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

All commands exited 0. Rustgoc passed 19 tests: one control-session unit test, five CLI-config tests, one CLI smoke test, nine real/scripted TLS control tests, and three key-generation tests. Rustgo-config passed 16 tests, rustgo-protocol passed 28, and the focused transport backoff suite passed 6. The workspace passed 141 tests total with all doc tests passing. Workspace/all-target Clippy emitted no warnings with warnings denied.

### Fix-round self-review and residual concerns

- Reviewed every active terminal branch: shutdown during receive, shutdown during backpressured write, write timeout, heartbeat timeout, EOF/protocol failure, and child join failure all pass through stream drop, inactive callback, child cancellation, and full join.
- Verified that an accepted Heartbeat updates liveness only after both version and sequence validation; malformed, replayed, future, and non-Heartbeat frames cannot extend the deadline.
- Verified the backoff clock is frozen before any await in child teardown. Existing callers that omit `mark_disconnected` retain prior `next_delay` behavior; `ClientApp` always marks both boundaries.
- The active write timeout is intentionally the configured heartbeat interval, providing a finite bound without adding a new V0.1 configuration field. Handshake writes remain covered by the existing ten-second whole-handshake timeout.
- The internal boxed I/O seam is private and exists to exercise blocking stream semantics; it does not expose or add a payload transport and does not alter TLS use in production.
- Concrete TCP/UDP payload children remain Task 8/9 work. P2P remains excluded.
