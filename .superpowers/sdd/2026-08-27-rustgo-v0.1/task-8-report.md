# Task 8 Report: End-to-end TCP relay

## Status and commit

- Status: complete for the Task 8 real end-to-end TCP relay scope.
- Commit: `feat: relay fixed-port TCP tunnels` (the commit containing this report).
- Worktree: `C:\Users\kimi\Desktop\projects\rustgo\.worktrees\v0.1`.
- Branch: `codex/rustgo-v0.1`.

## Same-listener protocol ruling

Rustgos already had one TLS listener whose post-handshake path assumed every
connection was a control session. Task 8 keeps that single listener and adds the
smallest explicit encrypted dispatcher:

1. every accepted socket completes the existing TLS 1.3-only handshake;
2. Rustgos reads one bounded protocol frame from the encrypted stream;
3. `ClientHello` enters the existing control authentication lifecycle;
4. new stable message ID 13, `DataChannelBind`, enters the data-channel binding
   path;
5. any other first frame, wrong version, unsupported flags, oversized frame, or
   extra buffered bytes is rejected before relay bytes are exposed.

`DataChannelBind` carries the bounded client name, server-issued session ID,
explicit TCP/UDP kind, tunnel ID, target ID, and one-time binding token. It is
general enough for Task 9's future UDP dispatcher, but this task implements only
the TCP runtime. No plaintext port, UDP forwarding, P2P path, or payload on the
control channel was added.

## Requirement mapping

| Requirement | Implementation and evidence |
| --- | --- |
| Real process echo | The `rustgo-e2e` workspace crate generates a CA/server certificate and device key, writes strict server/client TOML, spawns the real `rustgos` and `rustgoc` binaries, waits for an explicit registration-ready event, and verifies exact payload echo through the public port. |
| Fixed listener ownership | Authorized registration binds one `TcpListenerTask` per accepted TCP tunnel. The `ControlSessionGuard` owns every lease; control loss cancels the session runtime, closes listeners, cancels pending opens and active copy tasks, joins listener work, then releases registry ownership. |
| Port conflict isolation | Each registration bind produces its own `TunnelResult`; one occupied port is rejected while an unrelated tunnel remains registered and relays successfully. |
| Per-tunnel server limit | Each listener has a `Semaphore(max_tcp_connections_per_tunnel)`. Admission is nonblocking and excess public connections close immediately; releasing one stream permits a replacement. |
| Unpredictable bounded opens | Each public connection receives a nonzero `OsRng` `u64` connection ID with a bounded 16-attempt collision loop, a bounded expiring one-time token, one pending rendezvous, and a binding-TTL timeout. |
| Dedicated TLS data connection | Every `OpenTcpStream` causes Rustgoc to connect to the local target and establish a separate TLS connection to the same Rustgos listener. The first encrypted frame is `DataChannelBind`; only after full redemption and a bounded readiness acknowledgement can raw stream copy begin. |
| Failure isolation | Local refusal, setup timeout, invalid readiness, concurrency rejection, and relay error report/close only the affected connection ID. The control generation and unrelated tunnels remain active. |
| Client resource bounds | Rustgoc has a hard 4096 active-TCP semaphore, a short-lived four-handshake semaphore compatible with the server's default per-peer TLS admission, a 10-second whole setup timeout, a bounded 1024-entry child-to-control queue, and a 300-second copy idle timeout. |
| Server resource bounds | Public relays are bounded by the configured per-tunnel semaphore; pending bindings use the existing per-control bounded store and TTL; control outbound commands use a bounded 1024-entry queue; data readiness writes have cancellation plus a 10-second hard timeout. |
| Streaming/backpressure | Both relay halves use `copy_bidirectional_bounded`, whose fixed buffers, progress-aware idle timer, partial-write handling, cancellation, and half-close behavior are retained. The E2E test validates 16 MiB chunkwise without a whole-transfer receive buffer and validates a deliberately slow consumer without byte loss. |
| Half-close | A public `Shutdown::Write` reaches the local service as EOF while the reverse response remains readable to completion. |
| Restart recovery | Killing only the owned Rustgos child makes the existing Rustgoc generation reconnect; the same fixed public mapping is restored and relays a second payload. |
| Process hygiene | Fixtures retain ports until immediately before the intended process bind, keep direct `Child` handles, kill/wait only those owned children, drain both log pipes, and join their reader threads. No global process-name cleanup is used. |

## RED / GREEN evidence

### 1. First real-process relay

RED:

```text
cargo test -p rustgo-e2e --test tcp tcp_echo -- --nocapture
```

The first run timed out waiting for the required explicit
`event=registration_ready` marker because the real binaries had no Task 8 relay
readiness path. After adding the marker and the initial relay, the test exposed a
Windows fixture defect: a socket accepted from the nonblocking test listener
remained nonblocking and could close on `WouldBlock`. The fixture now explicitly
restores blocking mode on accepted local sockets. Ten repeated echo runs then
passed before the matrix was expanded.

GREEN uses the real TLS server/client processes and the real local TCP service;
there is no callback-only or in-process relay substitute.

### 2. Explicit encrypted data first frame

RED protocol tests first failed because message ID 13 and `DataChannelBind` did
not exist:

```text
cargo test -p rustgo-protocol tls_data_channel_has_an_explicit_first_frame_message_id
cargo test -p rustgo-protocol data_channel_bind_first_frame_decodes_from_its_stable_wire_shape
```

GREEN adds the stable ID, per-message payload bound, explicit numeric channel
kind, exact postcard shape test, normal codec round trip, and same-listener
post-TLS dispatch.

### 3. Concurrency and TLS admission

The first eight-way E2E concurrency run failed exactly four TLS data handshakes.
Debug evidence showed Rustgos correctly enforcing its four concurrent TLS
handshakes per peer while Rustgoc attempted all eight simultaneously. GREEN adds
a client short-lived four-permit TLS-handshake semaphore; the permit is released
after setup while the independent data stream continues under the 4096 active
stream bound. Ten repeated concurrency runs passed.

### 4. Complete binding and tunnel-kind isolation

The data dispatcher regression uses real TLS stream pairs and verifies unknown,
reused, wrong-client, wrong-session, wrong-kind, and wrong-target submissions.
For a recognized token, redemption removes it before checking every presented
field, so a failed presentation cannot be retried with corrected fields. The
existing transport TTL regression covers expired tokens.

A later RED unit test sent `OpenUdpChannel` for an accepted TCP tunnel and showed
that the client supervisor admitted it by ID alone. GREEN now requires both the
accepted tunnel ID and its configured protocol before spawning a TCP/UDP child.

### 5. Cancellation while acknowledging data readiness

Self-review found that a redeemed TLS data stream could remain in a
backpressured server readiness write after its control owner disconnected. The
new deterministic duplex regression first failed to compile because no
cancellation-aware acknowledgement helper or cancellation error existed.
GREEN carries the owning session cancellation token in the structurally
authenticated channel and selects cancellation before a readiness write that is
also capped at ten seconds.

## Data-channel security self-review

1. TLS completes before any binding fields are read. The only server entry point
   for runtime redemption requires a concrete rustls server stream.
2. The encrypted first frame has a stable type, zero supported flags, a declared
   per-message maximum, bounded inner strings/bytes, and exact deserialization.
3. The dispatcher rejects wrong version and any already-buffered bytes, so an
   unauthenticated peer cannot smuggle raw payload behind the binding frame.
4. The registry finds the control-owned token store and calls `redeem` while
   holding that store's mutex. Recognition and removal cannot race another data
   connection; a known token is consumed before identity/session/kind/target
   validation.
5. Delivery requires both successful token redemption and an exact pending TCP
   rendezvous. The server sends only a framed readiness acknowledgement before
   transferring stream ownership; the client reads exactly that frame without
   swallowing coalesced application bytes.
6. Tokens, session IDs, keys, and application bytes are never logged. Connection
   IDs, tunnel names, peers, and bounded error categories are the only relay
   diagnostics.
7. The control channel carries `OpenTcpStream`, heartbeat, and failure readiness
   metadata only. Application bytes exist only on the dedicated TLS data stream.

## Ownership and resource-bound self-review

- Ownership tree: server control guard -> session runtime -> listener tasks ->
  per-public-connection tasks -> pending rendezvous/dedicated TLS stream. Client
  generation -> child `JoinSet` -> local socket/dedicated TLS stream.
- Every terminal control path invalidates/cancels the same generation owner.
  Listener tasks stop accepting, active copies observe cancellation, child tasks
  are joined, and a later generation cannot reuse stale session state.
- Per-tunnel server permits and global client permits live for the entire relay;
  TLS handshake permits live only for setup. RAII releases all three on every
  return, error, panic-abort, or cancellation path.
- Pending public sockets wait no longer than the binding TTL. Local/TLS setup is
  bounded by ten seconds; readiness output is bounded by cancellation/ten
  seconds; established copies are bounded by cancellation and 300 seconds
  without byte progress.
- Listener, pending-token, active-client, tunnel, child-control queue, control
  command queue, frame, setup, handshake, and active-copy resources all have
  explicit finite limits. Copying remains streaming and does not size a buffer
  from untrusted payload length.
- Because this task prohibited subagents, the requested code review was
  performed as an inline protocol/security/ownership/concurrency self-review.

## End-to-end matrix

`tests/e2e/tests/tcp.rs` contains ten real-process tests:

1. exact TCP echo;
2. eight isolated concurrent connections;
3. per-tunnel limit rejection and permit recovery;
4. chunk-validated 16 MiB streaming;
5. slow-reader backpressure without byte loss;
6. public-to-local half-close with reverse response;
7. local refusal isolated from a healthy tunnel;
8. public-port conflict isolated from a healthy tunnel;
9. control disconnect closing the listener and an active stream;
10. server restart, client reconnect, fixed-port restoration, and second echo.

## Final verification

Commands to be run on the final report and implementation tree:

```text
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo test -p rustgo-protocol -p rustgo-transport -p rustgos -p rustgoc --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

Final observed result: every command exited 0. The dedicated process suite
passed 10/10 tests. The focused protocol/transport/server/client run passed 126
tests, including the TLS binding and copy suites plus 29 Rustgos and 22 Rustgoc
tests. The complete workspace passed 158 tests and every doc test. Formatting
was clean, workspace/all-target Clippy emitted no warnings with warnings denied,
and `git diff --check` reported no whitespace errors (only Git's existing
Windows LF-to-CRLF checkout notices).

## Concerns and deferred boundaries

- Client TCP active/setup/idle limits are deliberate hard runtime constants in
  V0.1 rather than new TOML fields. Making them operator-tunable requires a
  later strict-schema design change.
- Data-token owner discovery currently scans a finite snapshot bounded by
  `max_clients`. This avoids trusting attacker-supplied identity fields and
  preserves consume-on-invalid-presentation semantics, but a future high-scale
  server should add a bounded opaque-token owner index to make dispatch O(1).
- Windows cannot atomically hand a reserved ephemeral listening socket to a
  separately spawned Rust binary. The fixture holds reservations until the
  immediately preceding process bind and uses fixed addresses thereafter,
  reducing but not mathematically eliminating that OS-level release/bind race.
- A failed local setup removes the pending public rendezvous immediately, while
  its already-issued one-time token remains bounded in the control-owned store
  until TTL pruning. Repeated failures cannot grow memory beyond the store cap,
  but can temporarily consume that bounded capacity.
- UDP relay/data dispatch and all P2P behavior remain intentionally absent and
  are not inferred from the generalized `DataChannelKind` wire field.

---

## Review fix round 1 (2026-08-28)

### Status and commit

- Status: all four review findings are addressed with regression evidence.
- Base implementation: `e5d5105 feat: relay fixed-port TCP tunnels`.
- Follow-up: `fix: harden TCP relay ownership and backpressure` (the follow-up
  commit containing this appendix).

### Finding-to-fix mapping

| Finding | Fix and evidence |
| --- | --- |
| Unredeemed opens exhausted the shared binding store | The session now protects the binding store and pending TCP map with one mutex. Every `PendingTcp` retains its exact channel kind and token. Control-send failure, client rejection, pending timeout, control cancellation, and listener shutdown remove the rendezvous and revoke that exact unredeemed token in one critical section; a token already redeemed is a no-op. Revocation requires the owning store, exact token, and exact channel kind. |
| Slow local dials occupied all TLS setup slots | Rustgoc now has an independent 64-entry local-connect admission pool and five-second local-connect timeout. Only after local connect succeeds does it acquire one of four TLS setup permits. That permit covers server TCP/TLS connect, encrypted binding first frame, and exact readiness acknowledgement. The existing ten-second outer setup timeout and generation cancellation still cap permit waits plus both stages together. |
| Tunnel-results write failure skipped ordered guard shutdown | After authentication, one owned control wrapper handles registration, result write, active control, external cancellation, and every returned error. It always cancels the runtime, joins TCP listener/relay tasks, drops all listener leases and guarded data streams, then releases registry identity exactly once. Server accept failure and ordinary shutdown also converge through session cancellation and full `JoinSet` drain. |
| Large-stream/backpressure E2E assertions were too weak | The 16 MiB producer now writes one chunk and waits behind a gate; the consumer must receive that chunk before the producer may send the remainder or half-close. The slow-consumer test uses 32 MiB, constrains both public receive and local echo socket buffers, holds a reader gate closed, and requires the producer completion channel to remain empty until that gate opens; it then verifies every byte and both thread completions. |

### RED / GREEN evidence

#### 1. Exact token revocation and shared-capacity recovery

RED:

```text
cargo test -p rustgo-transport --test tls binding_revocation_requires_the_owning_store_exact_kind_and_token -- --exact --nocapture
cargo test -p rustgo-e2e --test tcp local_refusal_closes_only_that_connection -- --exact --nocapture
```

The transport test failed to compile because `ChannelBindingStore::revoke` did
not exist. The real-process test configured two tunnels with a ten-token shared
capacity, drove twelve fast local refusals, then tried the healthy tunnel. The
old runtime reset the healthy connection after the leaked refusal tokens filled
the store.

GREEN adds exact conditional revocation and stores each issued token beside its
pending destination. The E2E sequence now exceeds the configured capacity and
the unrelated healthy tunnel still echoes exactly. A second binding store and a
wrong channel kind cannot revoke the owner's token; correct redemption remains
possible until the owner revokes it, and repeated/already-redeemed revocation is
a no-op.

#### 2. Independent local-connect and TLS admission

RED:

```text
cargo test -p rustgoc four_slow_local_connects_do_not_block_one_healthy_tls_setup -- --nocapture
```

The regression first failed to compile because no ordered two-stage admission
function existed. It launches four never-completing local-connect futures with a
four-entry TLS pool, then runs one healthy local+data setup under a 100 ms bound.
If a TLS permit is acquired before local completion, the four slow futures own
all permits and the healthy setup times out.

GREEN runs the same production `setup_with_admission` path used by TCP children.
All four slow local attempts consume only entries in the separate 64-entry local
pool; the healthy setup acquires a TLS permit and completes. Aborting the slow
tasks drops their RAII permits. The outer child select still gives generation
cancellation priority and caps the complete setup at ten seconds.

#### 3. Registration-reply failure cleanup ordering

RED:

```text
cargo test -p rustgos tunnel_results_write_failure_joins_listener_before_releasing_identity -- --nocapture
```

The deterministic unit regression first failed to compile because there was no
owned post-authentication lifecycle wrapper. Its scripted stream supplies a
valid registration frame, fails every results write with `BrokenPipe`, and then
requires both registry count zero and immediate rebinding of the created port.

A companion real TLS test sends registration, closes with zero linger to make
the reply fail, waits for identity release, immediately reconnects with the
same identity, and registers the same fixed port. The old runtime could pass
this real race when Tokio happened to process the listener abort quickly, which
is why the deterministic ownership regression is the ordering authority.

GREEN moves registration receive/bind/result send and the active loop under one
owned wrapper. It selects external cancellation without dropping the guard,
then always awaits the idempotent guard shutdown. `shutdown` cancels pending and
active work, joins TCP listeners, drops TCP/UDP leases and guarded streams, and
only then removes the exact registry identity. A `released` bit prevents the
destructor from repeating cleanup.

#### 4. Observable streaming and backpressure

The new 16 MiB early-progress gate passed: one echoed chunk arrives while the
producer is deliberately blocked before the remainder and before EOF. A relay
that accumulates the whole request would deadlock until the socket timeout.

The first strengthened 32 MiB backpressure run failed its evidence assertion:
Windows localhost auto-tuned buffers allowed the producer to complete while the
reader gate was closed. GREEN explicitly constrains the public receive buffer
and both local echo socket buffers to 16 KiB. With the same 32 MiB fixed-chunk
stream, the completion channel remains empty for the closed-gate interval, then
the producer and consumer both complete after opening the gate with no changed
or missing byte.

### Updated security, ownership, and limit invariants

1. Token issue, pending publication, correct redemption, pending removal, and
   exact revocation serialize under one per-control-session mutex.
2. `cancel_pending(connection_id)` can reach only the authenticated control
   session's own map and revokes only the token recorded for that exact channel;
   attacker-supplied identity fields cannot select another session for revoke.
3. Every known-token presentation remains consume-before-validate. Later timeout
   or cancellation sees the token already absent and performs a harmless no-op.
4. Local connect, TLS data setup, and active relay have separate RAII bounds:
   64 local attempts, four TLS setups, and 4096 total TCP child tasks. Individual
   local/data timeouts sit inside the ten-second whole-setup and generation
   cancellation boundary.
5. Once a guard can own a listener, no ordinary result, protocol error, control
   EOF, heartbeat timeout, reply-write error, app shutdown, or accept-loop error
   releases its identity through a bare destructor path. Cleanup completes
   before release; the destructor remains only a panic/runtime-destruction
   fail-safe that cancels and aborts.
6. The E2E fixture retains no whole-transfer buffers. Its only 32 MiB state is a
   byte count; producer and consumer each reuse one 16 KiB chunk.

### Fix-round verification

Commands to be run on the final follow-up tree:

```text
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo test -p rustgos -p rustgoc --no-fail-fast
cargo test -p rustgo-transport --test tls --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

Final observed result on the follow-up tree:

- TCP E2E: 10 passed, including the shared-capacity refusal recovery, early
  16 MiB progress, gated 32 MiB backpressure, half-close, concurrency, local
  isolation, port conflict, cleanup, and restart scenarios.
- `rustgos` + `rustgoc`: 73 passed.
- Transport TLS suite: 14 passed.
- Full workspace: 162 passed, 0 failed.
- Format check, workspace/all-target Clippy with warnings denied, and
  `git diff --check`: passed.

### Residual concerns

- The original bounded linear scan for data-token owner discovery remains; an
  opaque-token owner index is still the appropriate future high-scale change.
- Local/TLS/whole-setup/idle limits remain V0.1 hard runtime constants rather
  than strict-schema TOML fields.
- The E2E port allocator still minimizes, but cannot eliminate, Windows'
  cross-process release/bind race.
- Panic or wholesale Tokio-runtime destruction cannot asynchronously join from
  `Drop`; the fallback cancels and aborts. All normal server lifecycle and error
  paths now retain the future and use ordered async shutdown.
- UDP relay and P2P remain outside Task 8.

## Review fix round 2 (2026-08-28)

Status: causal backpressure evidence replaces the round-1 timed/buffer-sized
proxy. This section supersedes the round-1 backpressure paragraph and its
32 MiB wording; no runtime behavior changed.

### Evidence gap and causal test protocol

The old regression held the public reader for 500 ms and checked only that the
producer completion channel was empty. A slow machine could satisfy that check
without socket backpressure, while successful `SO_RCVBUF`/`SO_SNDBUF` calls did
not prove the effective end-to-end capacity. Those socket-size overrides and
the direct `socket2` test dependency are now removed.

The replacement retains real `rustgos` and `rustgoc` processes and uses one
single-threaded gated local echo target:

1. The public peer sends a distinct handshake through the relay and receives a
   distinct local-target acknowledgement. The target then reports that its
   application read gate is closed.
2. A nonblocking public producer reports thread start and at least one 16 KiB
   chunk of progress. It writes without a predetermined transfer size until a
   real socket write returns `WouldBlock`, recording the exact byte offset as a
   saturation barrier.
3. While the target remains in its gate-command loop, a non-consuming socket
   `peek` must observe queued payload at the local endpoint. Thus the full
   public-to-relay-to-local path has data waiting, while target application
   reads have not started. The public consumer remains active throughout, so
   reverse-direction reader starvation cannot create the forward blockage.
4. The test explicitly permits the producer to retry. Its next terminal event
   must be a second actual `WouldBlock`, not completion. A second gated `peek`
   confirms the only local read gate is still closed.
5. Still before opening the local gate, the producer arms a finite completion
   target 8 MiB beyond its second saturation offset and resumes independently.
   Its next event must be another real `WouldBlock`, not completion, and the
   target must still observe queued payload without reading it. At this point
   the local read gate is the only remaining release condition.
6. The test opens that gate without sending any further producer command. The
   producer finishes, half-closes, and the consumer validates every echoed byte
   and the exact producer/consumer totals.

Fixed sleeps remain only as one-millisecond nonblocking retry backoff; they are
not assertions. Deadlines bound failure duration but do not establish the
backpressure condition.

### RED / GREEN evidence

RED 1 used the final target/control protocol with a deliberate one-byte read in
the supposedly closed gate. The real-process test failed in 0.53 seconds with:

```text
Error: "local target consumed payload while its read gate was closed"
```

RED 2 changed the closed-gate assertion to require an observable queued byte
before the non-consuming `peek` implementation existed. It failed in 0.50
seconds with:

```text
Error: "no payload was queued at the closed local read gate"
```

GREEN removed the deliberate read and implemented the non-consuming local
socket observation. The targeted real-process regression passed in 0.56
seconds. The complete TCP E2E suite then passed 10/10 in 25.40 seconds.

RED 3 armed the producer's finite completion target while the local gate was
still closed but, before the new drain-blocked barrier existed, the test timed
out after eight seconds and the compiler reported that
`BlockedWhileDraining` was never constructed. GREEN emits that barrier only
from an actual nonblocking `WouldBlock` branch. The targeted regression then
passed in 0.54 seconds; no producer command is sent after the local gate opens.

### Fix-round-2 verification

Commands on the final follow-up tree:

```text
cargo test -p rustgo-e2e --test tcp slow_reader_applies_backpressure_without_losing_bytes -- --exact --nocapture
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

Final observed result:

- Targeted causal backpressure regression: 1 passed in 0.55 seconds after the
  final single-gate tightening and Clippy-equivalent refactor.
- Complete real-process TCP E2E: 10 passed in 25.23 seconds; the workspace
  rerun also passed all 10 in 25.59 seconds.
- Full workspace: 162 passed, 0 failed.
- Format check, workspace/all-target Clippy with warnings denied, and
  `git diff --check`: passed.

### Round-2 residual concerns

- Nonblocking retry loops use one-millisecond backoff to avoid busy-spinning;
  correctness is derived from socket results and channel ordering, not elapsed
  sleep duration.
- The dynamic producer has a 512 MiB no-saturation safety ceiling. Reaching it
  fails the test instead of accepting an unproven platform socket path.
- The earlier runtime and Windows port-allocation concerns remain unchanged.
