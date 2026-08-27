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
