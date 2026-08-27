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
