# Task 9 Report: End-to-end bounded UDP relay

## Status and commit

- Status: complete for the real, bounded, relay-only UDP scope, with the local
  socket topology ruling documented below.
- Commit: `feat: relay bounded UDP tunnels` (the commit containing this report).
- Worktree: `C:\Users\kimi\Desktop\projects\rustgo\.worktrees\v0.1`.
- Branch: `codex/rustgo-v0.1`.

## Datagram and local-socket topology ruling

Each accepted UDP tunnel owns exactly one long-lived authenticated TLS data
channel per control generation. The channel multiplexes all of that tunnel's
temporary external flows and preserves one UDP datagram as one `UdpDatagram`
frame in each direction.

The Task 9 brief also says to create one local UDP socket per tunnel generation.
Taken literally, that conflicts with its required generic reordered-reply test:
all replies from one configured local target arrive on the same socket with the
same source address, and UDP supplies no session ID or application correlation
field. A proxy cannot know which external source should receive an arbitrarily
reordered reply without interpreting application payload. The implementation
therefore uses one connected local UDP socket per active server-issued flow
session, owned by one tunnel-generation task. Distinct local source ports retain
the necessary generic reply association. The table, tasks, sockets, and queues
remain hard bounded, while the tunnel still has one TLS data channel and one
generation owner. Serializing requests, assuming FIFO replies, or inspecting
application payload would have violated the stronger correctness requirements.

## Requirement mapping

| Requirement | Implementation and evidence |
| --- | --- |
| Real process relay | `tests/e2e/tests/udp.rs` launches the real `rustgos` and `rustgoc` binaries, real TLS/device authentication, and real local UDP services. It verifies exact source port/address and byte-for-byte datagram replies. |
| Datagram boundaries | Every receive produces exactly one fixed-metadata `UdpDatagram` frame; every valid frame produces exactly one UDP send. Zero-length datagrams are successful datagrams, never treated as stream EOF. E2E covers lengths 0, 1, 1472, and 65507. |
| Persistent authenticated channel | One server listener task issues one random nonzero channel ID plus one-time binding token. The client opens one TLS data connection, sends the exact `DataChannelBind`, waits for an exact framed `OpenUdpChannel` acknowledgement, then reuses that stream for all flows. |
| Server flow identity | A `FlowTable` belongs to one tunnel; its key adds canonical external source and the listener's bound public destination. Thus tunnel identity is structural and the full logical key is tunnel + source + destination. |
| Session IDs | Each new flow gets a nonzero `OsRng` `u64`; allocation checks active collisions and fails after 16 attempts. The active map has the configured per-tunnel capacity and rejects new flow work without waiting. |
| Idle expiry | Server and client use periodic delayed ticks and inspect at most the configured batch. Sweep order is an intrusive O(1) doubly linked ring stored in the session maps, so arbitrary removal and each inspected entry are constant work and every active session has exactly one sweep node. |
| Queue and payload bounds | Server TLS output, client TLS output, and each local-flow input are bounded Tokio channels. All producers use `try_send`; full queues drop and count instead of waiting or allocating. Frame readers use the protocol maximum; the server separately applies the configured payload maximum without poisoning the persistent channel. |
| Bidirectional TLS progress | TLS streams are split. Dedicated bounded writer tasks cannot block the reader path or control heartbeat; writer completion/error is observed by the main relay loop. Cancellation interrupts blocked writes and UDP sends. A continuous-public-flood E2E proves reverse replies remain live. |
| Address families | Wire metadata encodes explicit V4/V6 families and network-order ports. IPv4-mapped IPv6 addresses canonicalize to native IPv4 on both sides; unit regressions cover identity equivalence. |
| Generation ownership | The data token is issued by and redeemed from one authenticated control runtime. The client child receives that generation's session ID/token and is cancelled and joined before a later generation starts. Old streams cannot be delivered into a new runtime or flow table. |
| Cleanup/reconnect | Control loss cancels listener/data children, clears flow maps and bounded queues, logs zero live counts, and releases the fixed public port. Real-process tests kill either client or server, assert cleanup, restart, and echo through the restored mapping. |
| Failure isolation | Unknown/mismatched session replies and configured oversize frames are dropped and counted. A local-flow task failure removes only that session. Tunnel IDs and per-tunnel listeners/tables prevent cross-tunnel routing. |
| Relay only | Application traffic is public UDP -> Rustgos -> authenticated TLS -> Rustgoc -> configured local UDP target, and back. No discovery, NAT traversal, hole punching, QUIC P2P, or direct peer path was added. |

## RED / GREEN evidence

### 1. First real-process UDP echo

RED:

```text
cargo test -p rustgo-e2e --test udp udp_echo -- --nocapture
```

The original real binaries registered the UDP tunnel but had no relay. The
first zero-byte datagram timed out on Windows with OS error 10060. This was also
the boundary that prevented treating `recv_from(...)=0` like TCP EOF.

GREEN uses the existing stable 31-byte big-endian UDP metadata followed by raw
payload and passes 0, 1, MTU-sized, and maximum-size datagrams through real
processes without coalescing or splitting.

### 2. Bounded idle sweep and rollback

The first idle-limit E2E filled a one-session table and correctly logged the
session-limit drop, but failed waiting for an observable bounded idle sweep.
GREEN adds validated runtime idle/sweep limits and internal-only process hooks
gated by `RUSTGO_INTERNAL_TESTING=1`; the test observes one-entry sweep expiry
and successful capacity reuse.

Self-review then exposed a real bound violation: queue-full rollback removed a
map entry but left its ID in the sweep deque. The server regression failed with
one stale sweep node after the active count returned to zero; the matching
client regression likewise found a retained node. An intermediate `retain`
fix bounded memory but made one removal O(all sessions). Final GREEN uses O(1)
prev/next links, covers rollback, sole and middle removal, uniqueness through
capacity, and one-batch sweep behavior on both sides.

### 3. Configured reverse oversize without channel poisoning

The first reverse-oversize E2E made a 17-byte local reply against a configured
16-byte limit. The server frame reader was incorrectly configured to only 47
payload bytes total and terminated the TLS channel on the 48-byte protocol-valid
frame before the configured-limit policy could drop it. The test timed out
waiting for the oversize drop event.

GREEN always parses up to the stable protocol maximum, then applies the lower
server configuration as a datagram policy. It logs/counts the drop and relays a
subsequent valid datagram on the same channel. Public oversize follows the same
drop-and-recover contract, including Windows `WSAEMSGSIZE` handling.

### 4. Queue saturation and bidirectional progress

The queue test sets an internal one-entry TLS output queue plus a bounded writer
delay, floods 256 datagrams, observes `reason="data_queue_full"`, drains, and
then receives a fresh exact echo. Teardown proves `drops_queue` is nonzero and
the live queue count is zero.

The TLS reader and writer were separated before enabling the hot path. A later
self-review added writer-task completion to each main loop; otherwise one
failed writer could leave a reader alive while all later datagrams accumulated
only up to the queue and were dropped forever. Cancellation is selected ahead
of blocked writes/sends. The continuous public flood regression receives a
marked reverse reply within its fixed deadline.

## Session, queue, and ownership invariants

1. A server session exists in exactly two maps (`FlowKey -> id`, `id -> entry`)
   and exactly once in the O(1) sweep chain. Insert publishes all three; remove
   unlinks all three; cleanup clears head, tail, and both maps.
2. A flow key is scoped by one listener task and contains canonical source plus
   bound destination. A reverse frame must match tunnel ID, unpredictable
   session ID, and the exact canonical recipient before `send_to`.
3. A newly inserted server flow is rolled back if its first frame cannot enter
   the bounded TLS queue. Queue saturation therefore cannot consume session
   capacity through rejected work.
4. Server sessions never exceed `max_udp_sessions_per_tunnel`. Client sessions
   are defensively capped at the strict configuration model's 1,000,000 hard
   ceiling; the authenticated server's normally lower configured table is the
   authoritative allocator.
5. Server TLS output defaults to 1024 entries and is runtime-capped at 65536;
   client TLS output is 1024 and each flow input is 64. Every queue counter is
   incremented before nonblocking admission and decremented on receive,
   rejection, drain, or final cleanup.
6. Drop counters are monotonic atomics. The first and power-of-two drops emit a
   warning, preventing log amplification. Cleanup emits sessions, queues, and
   per-reason totals without identity tokens or application payload.
7. The control owner issues and revokes pending UDP tokens in the same bounded
   store/mutex as TCP. Redemption consumes the exact one-time token before
   delivery. Only the matching authenticated session cancellation token reaches
   the listener and data stream.
8. A generation is removed from client status before its children are cancelled
   and joined. The next generation is not admitted until that join finishes, so
   stale data tasks cannot overlap a fresh owner.

Because this task explicitly prohibited subagents, the requested review was an
inline protocol/security/ownership/concurrency self-review. It found and fixed
the sweep-chain and writer-lifecycle defects described above.

## Drop and metrics evidence

- Session overflow waits for `reason="session_limit"`; teardown requires
  `drops_sessions != 0`, `sessions=0`, and `queue=0`.
- Queue overflow waits for `reason="data_queue_full"`; teardown requires
  `drops_queue != 0`, `sessions=0`, and `queue=0`.
- Configured oversize waits for `reason="oversize_public"` or
  `reason="oversize_data_frame"`; teardown requires `drops_oversize != 0`.
- Client teardown requires `sessions=0`, `queue=0`, and `local_queue=0` for the
  old generation before restart traffic is accepted.
- Unknown/mismatched reverse sessions have a separate `drops_invalid` counter;
  no invalid frame can create a client target or select an arbitrary recipient.

## Real-process E2E matrix

`tests/e2e/tests/udp.rs` contains ten tests:

1. exact 0/1/1472/65507-byte echo and public reply source;
2. two external source ports with deliberately reordered local replies and one
   persistent tunnel TLS channel;
3. session-limit drop, one-entry bounded idle sweep, and capacity reuse;
4. one-entry output queue saturation, counted drop, and recovery;
5. configured public oversize drop without channel poisoning;
6. configured local-reply oversize drop without channel poisoning;
7. two simultaneous UDP tunnels with tagged isolation;
8. client disconnect, zero-count server cleanup, and fresh-client restoration;
9. server restart, stale generation zero-count client cleanup, and restoration;
10. continuous public flood while a distinct reverse reply remains live.

## Final verification

Observed on the final implementation and report tree:

```text
cargo test -p rustgo-e2e --test udp -- --nocapture
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo test -p rustgo-protocol -p rustgo-transport -p rustgos -p rustgoc --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

- UDP real-process E2E: 10 passed, 0 failed.
- TCP real-process regression: 10 passed, 0 failed.
- Focused protocol/transport/server/client run: 138 passed, 0 failed.
- Full workspace: 180 passed, 0 failed; every doc test passed.
- Format check and workspace/all-target Clippy with warnings denied exited 0.
- `git diff --check` reported no whitespace errors (Git emitted only the
  repository's existing Windows LF-to-CRLF checkout notices).

## Concerns and deferred boundaries

- The brief's literal single-local-socket phrase is intentionally resolved as
  per-flow connected sockets under one generation owner, for the generic
  reordered-reply reason documented above. This should be made explicit in the
  next normative spec revision.
- `max_udp_payload_bytes` is server configuration and is not present in the
  stable `OpenUdpChannel` shape. Rustgoc defensively enforces the 65507 protocol
  maximum; Rustgos authoritatively drops a reverse frame above the configured
  lower maximum. Early client-side rejection of the lower value would require
  a future negotiated control-field change.
- If only an established UDP data TLS connection fails while its control
  generation remains healthy, this V0.1 listener cleans the channel and waits
  for the control generation to reconnect rather than proactively negotiating
  another data channel. Process/control disconnect and server restart recovery
  are covered; independent data-channel reissue is a future resilience step.
- Data-token owner discovery remains a bounded linear snapshot over active
  clients, inherited from Task 8. A bounded opaque-token owner index is the
  appropriate later high-scale optimization.
- Windows cannot atomically transfer a reserved ephemeral UDP socket to a child
  process. The fixture holds the socket until immediately before Rustgos bind,
  minimizing but not eliminating the OS release/bind race.
- Only Windows x86_64 GNU was exercised in this task. IPv4-mapped normalization
  has unit coverage, but live IPv6 and cross-platform Windows/Linux process
  interoperability remain release-matrix work.

---

## Review fix round 1 (2026-08-28)

Repair commit: `fix: harden UDP generation and flow leases` (the commit
containing this appendix).

This appendix records the controller-requested repair pass and supersedes the
base report's fourth invariant plus its second and third deferred concerns. The
controller accepted one connected local UDP socket per active external flow as
the only application-agnostic way to preserve arbitrary multi-source,
out-of-order reply routing. Those sockets and their tasks are now governed by
the server-negotiated flow limit and lease rather than a client hard-coded
ceiling.

### Findings and implemented corrections

1. **A dead persistent UDP data child now ends its control generation.** Every
   UDP child installs a generation-fatal drop guard before data-channel setup.
   TLS EOF, writer failure, setup failure, task panic, or any other exit not
   caused by generation cancellation signals the control loop through a
   one-entry bounded channel. The control stream is then dropped, client status
   is cleared before children are cancelled/joined, and normal capped reconnect
   and complete tunnel re-registration restore the public listener. This is the
   minimal reliable option chosen over same-generation data-channel reissue,
   because the server listener currently owns and drops the public socket when
   its relay ends.
2. **`OpenUdpChannel` now carries the authoritative per-tunnel limits.** The
   stable explicit message includes `max_sessions`, `idle_timeout_millis`,
   `max_payload_bytes`, and `queue_capacity`; the data-channel acknowledgement
   must equal the complete control request. Decode rejects zero or out-of-range
   values. Rustgoc converts these values before opening the data TLS connection
   and uses them for the session table, live local-task/socket admission, idle
   sweep, TLS queue, per-flow queue, and receive buffer. The former
   1,000,000/60-second/65507-byte/1024-entry client constants are gone.
3. **Server expiry explicitly retires client flows.** New explicit message ID
   14 is `UdpSessionRetired { tunnel_id, session_id }`; its strict decoder
   rejects zero IDs. Each bounded server sweep returns at most its configured
   batch of expired IDs and nonblockingly enqueues retirement frames. A full
   data queue drops and counts retirement rather than blocking. Rustgoc cancels
   and removes the matching connected local socket/task. Its identical
   negotiated idle lease remains the bounded fallback when the retirement frame
   itself is dropped.
4. **Client activity is genuinely bidirectional and validity-gated.** A flow's
   activity instant is shared between its table owner and connected local task.
   A valid local reply refreshes it before bounded TLS queue admission. Socket
   errors, configured-oversize replies, and non-target senders do not refresh
   it: oversize is rejected first, and a connected UDP socket lets the OS admit
   packets only from the resolved local target. A mismatched session/source
   frame on the TLS side is likewise dropped before activity changes.
5. **Configured payload rejection moved to the client edge.** An oversized
   server datagram is discarded before a flow entry, socket, task, per-flow
   queue entry, or TLS work can be created. A local reply buffer is exactly the
   negotiated maximum plus one byte; an oversized reply is dropped before
   `UdpDatagram` construction or TLS queue admission. The server no longer has
   to receive a protocol-valid but tunnel-invalid reverse payload in the tested
   path.

### Repair RED / GREEN evidence

- `udp_data_channel_failure_reconnects_generation_and_restores_mapping` was
  introduced as a real-process RED. The initial run timed out waiting for a
  deterministic data-only disconnect because no bounded hook or recovery path
  existed. The internal-only, `RUSTGO_INTERNAL_TESTING=1` hook now closes only
  the UDP data relay after one reply. GREEN observes generation-1 zero-count
  cleanup, a new `registration_ready`/`udp_channel_ready`, and an exact reply on
  the same fixed public port. The focused unit
  `persistent_udp_child_exit_marks_the_generation_inactive` additionally proves
  `DataSessionTerminated` invokes the inactive callback before return.
- The first protocol negotiation test did not compile because
  `OpenUdpChannel` lacked all four limits and the retirement message/ID. GREEN
  round-trips both explicit messages and rejects invalid numeric metadata during
  decode. A separate Rustgoc boundary test checks all seven zero/above-maximum
  limit cases at the pre-data-connect conversion gate.
- The real `max_sessions=1`, `idle=150ms`, `max_payload=16`, `queue=1` test first
  failed because Rustgoc's readiness line exposed none of the server values.
  An intermediate run then showed the identical local lease could expire just
  before the retirement frame arrived. GREEN records retirement even when the
  idempotent local removal already won, observes `sessions=0`, and reuses
  capacity from a second external source.
- `oversized_local_reply_is_dropped_without_poisoning_the_channel` initially
  timed out waiting for a client-edge drop because the 17-byte reply was sent
  over TLS against a negotiated 16-byte tunnel. GREEN observes
  `reason="oversize_local_reply"`, proves the server never logs
  `oversize_data_frame`, and then relays a valid reply on the same channel.
- `valid_reverse_only_replies_keep_the_negotiated_client_lease_alive` first
  stopped at sequence 6 when the client unilaterally expired at 150ms. GREEN
  receives sequence 10 and beyond with no additional public request.
  `oversized_reverse_replies_do_not_refresh_the_client_lease` then exposed an
  over-broad first fix by timing out waiting for client expiry while 17-byte
  invalid replies arrived every 30ms. GREEN sees those drops and still expires
  the one flow within the negotiated lease.
- Strict-decode RED accepted `UdpSessionRetired { session_id: 0 }`. GREEN returns
  `FrameError::MalformedPayload` for both that frame and a zero-session-limit
  `OpenUdpChannel`.

### Revised session, queue, and lease invariants

1. For one tunnel generation, Rustgoc has no more than the negotiated
   `max_sessions` table entries and no more than that many live-or-cancelling
   local tasks/sockets. Admission checks both counts, so retirement cannot open
   a replacement socket until the cancelled task has joined.
2. One server flow ID has at most one client table entry, one connected local
   socket/task, and one bounded per-flow input queue. Retirement and local idle
   expiry are idempotent; both cancel through the same token and unlink the
   table's O(1) sweep node.
3. The negotiated TLS queue is positive and at most 65,536 entries. Each
   per-flow queue is `min(queue_capacity, 64)`. All producers use `try_send`;
   queue saturation drops work and increments the corresponding monotonic
   counter without growing memory or waiting.
4. Payloads larger than the negotiated tunnel maximum cannot allocate a new
   client flow or enter either client queue. Zero-byte datagrams remain legal
   and distinct from TLS/UDP socket closure.
5. Server and client use the same positive millisecond idle lease. Server
   expiry removes authority before sending a bounded best-effort retirement;
   client expiry independently closes any old socket if that notification was
   dropped. Only validated forward traffic or a valid connected-target reply
   refreshes activity.
6. A persistent UDP child may end normally only after its generation token is
   cancelled. Every other terminal path sends one bounded fatal signal. Status
   becomes inactive and the old control stream is dropped before child
   cancellation/join; the next generation cannot overlap it.

### Drop and metrics evidence added in this round

- Retirement queue saturation uses the existing rate-limited
  `event=udp_drop reason="retirement_queue_full"` counter; client same-idle
  cleanup supplies bounded convergence when that best-effort frame is lost.
- Configured local oversize logs and counts
  `reason="oversize_local_reply"` on Rustgoc, before frame construction. The
  regression asserts no matching server `oversize_data_frame` event.
- Invalid oversized reverse traffic repeatedly emits only the rate-limited drop
  series and cannot keep a lease alive. Valid reverse traffic refreshes the
  lease even if the bounded outbound queue later drops that otherwise valid
  reply.
- Data-only failure still emits both server and client `event=udp_cleanup`
  zero-count records; generation replacement does not reuse an old table,
  queue, task, socket, token, or TLS stream.

### Expanded real-process matrix

The UDP process suite now contains 14 tests. In addition to the original ten,
it covers:

1. negotiated one-flow/150ms/16-byte/one-entry limits, explicit retirement, and
   capacity reuse from a second external source;
2. data-TLS-only failure, inactive generation cleanup, reconnect,
   re-registration, and restored fixed-port mapping;
3. reverse-only valid replies continuing across multiple idle periods; and
4. periodic configured-oversize reverse replies being dropped without
   refreshing the client lease.

### Review-round verification

Observed on the final review tree:

```text
cargo test -p rustgo-e2e --test udp -- --nocapture
cargo test -p rustgo-protocol -p rustgoc -p rustgos -- --nocapture
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

- UDP real-process E2E: 14 passed, 0 failed. The final tree passed once inside
  the workspace run and once again as an independent focused rerun.
- TCP real-process regression: 10 passed, 0 failed.
- Protocol/server/client focused run: 115 passed, 0 failed (protocol 32,
  Rustgoc 28, Rustgos 55).
- Full workspace: 188 passed, 0 failed; every doc test passed.
- Format check and workspace/all-target Clippy with warnings denied exited 0.
- `git diff --check` had no whitespace errors; Git printed only the repository's
  existing LF-to-CRLF checkout notices.

### Remaining concerns after repair

- The controller-approved per-flow connected socket topology remains necessary
  for generic reordered replies. It is now strictly bounded by negotiated
  sessions and idle lifetime, but configurations near the one-million protocol
  ceiling still deliberately authorize correspondingly high socket/task
  pressure; operators should choose a realistic server limit.
- A UDP data-child failure intentionally tears down and re-registers the whole
  client generation. This restores one unambiguous listener owner and avoids a
  false-active status, but briefly interrupts unrelated tunnels. A later
  same-generation channel reissue would need a design that retains the public
  listener and prevents two concurrent channel owners.
- Retirement delivery is best effort under the same bounded queue as data. The
  identical client lease guarantees bounded cleanup, but a newly recycled
  server flow can lose initial UDP datagrams while the prior cancelled local
  task is still joining; the implementation preserves the hard socket/task
  bound instead of transiently exceeding it.
- The original report's bounded token-owner linear lookup and Windows ephemeral
  fixture bind race remain. Live IPv6 and Windows/Linux interoperability also
  remain release-matrix work; this repair was verified on Windows x86_64 GNU.

---

## Review fix round 2 (2026-08-28)

Repair commit: `fix: close UDP retirement ownership races` (the commit
containing this appendix).

This appendix records the second controller repair pass. It supersedes round
1's statement that best-effort retirement plus the matching idle lease was
sufficient: once a valid delayed local reply can refresh that lease, dropping
the retirement notification is not a safe convergence mechanism.

### Findings and implemented corrections

1. **Retirement delivery is now fail-closed.** The server still removes an
   expired flow from its authoritative table before it emits
   `UdpSessionRetired`, but a full or closed data-writer queue is now a terminal
   UDP-listener error. The listener logs and counts
   `reason="retirement_queue_full"`, cleans its flow table and writer, and calls
   `SessionRuntime::fail_generation()`. The active control loop directly
   observes the same cancellation token, drops the control stream, joins all
   listeners, and lets the client reconnect and re-register every tunnel. An
   undelivered retirement therefore cannot coexist indefinitely with an active
   old client socket.
2. **Local task completion is compare-and-remove by lease.** Every Rustgoc flow
   task receives a nonzero monotonic local lease in addition to the wire
   `session_id`. The table stores both values, the join result returns both, and
   completion removes the entry only when both still match. A retired or swept
   task completing after the same wire ID has been recreated can no longer
   delete or cancel the replacement flow.
3. **A UDP listener cannot be accepted before its data channel is preparable.**
   Rustgos now binds the public socket and reserves its pending authenticated
   UDP data token synchronously inside registration. Only after both succeed is
   `TunnelResult::accepted` produced and the listener spawned with that owned
   reservation. Token-capacity exhaustion rejects only that tunnel during
   registration, drops its bound socket, and leaves prepared sibling tunnels
   active. Later token send, acknowledgement, TLS EOF, writer, or relay failure
   remains generation-fatal; normal generation cancellation is the only
   nonfatal listener exit.

### Repair RED / GREEN evidence

- `retirement_queue_full_tears_down_generation_before_a_delayed_old_reply_can_renew_it`
  was introduced as a real-process RED with three flows, an 800 ms negotiated
  idle lease, queue capacity one, a 500 ms server writer delay, and a valid
  delayed local reply at 900 ms. Before the fix Rustgos logged
  `retirement_queue_full` but the test timed out waiting for `udp_cleanup`:
  generation 1 remained active and the old client socket could refresh itself.
  GREEN observes generation-1 zero-count cleanup, generation-2 registration and
  data readiness, waits until the delayed reply is actually sent, and then
  proves exact echo through the restored fixed public port. The first GREEN run
  also exposed Windows `WSAECONNRESET` in the delayed fixture after it replied
  to the intentionally closed old socket; the fixture now treats that Windows
  connected-UDP notification as recoverable and continues serving the new
  socket.
- `old_local_task_completion_cannot_remove_a_recreated_session_id` initially
  failed to compile because `ClientSession` had no lease and the table exposed
  no compare-and-remove operation. GREEN removes the stale epoch while
  preserving a recreated entry with the same wire ID and a newer local lease.
- `token_capacity_rejects_the_unprepared_udp_tunnel_before_registration` used
  the internal-only token-capacity override of one with two configured UDP
  tunnels. RED logged `registration_ready ... listeners=2`: the second tunnel
  had already been accepted even though its listener could never allocate a
  token. GREEN logs exactly one accepted listener and one client/server
  `udp_channel_ready`, relays through the prepared mapping, and observes no
  datagram through the rejected public port. Windows reports an ICMP-unreachable
  condition for that unbound port as `ConnectionReset`; the no-datagram helper
  accepts that documented socket outcome without weakening the positive echo
  assertion.

### Timing and ownership invariants after round 2

1. Removing server flow authority must be followed by exactly one of two
   outcomes: its retirement frame enters the bounded writer queue, or the
   owning generation is cancelled. Queue-full retirement is counted and then
   fatal; it is never merely dropped.
2. Generation cancellation is observed both by the UDP listener tree and the
   active control loop. The old control stream and every child are shut down
   and joined before reconnect can publish the next active generation, so a
   delayed old reply has no authoritative TLS route to renew.
3. A wire `session_id` is not a client task identity. Client task identity is
   `(session_id, local_lease)`, and only an exact match may mutate the table on
   completion. Task/socket admission still counts live-or-cancelling tasks, so
   the negotiated session cap is never exceeded while an old epoch drains.
4. An accepted UDP listener owns a bound public socket and a pending,
   tunnel-specific, one-use data token. Registration failure releases both; an
   accepted result cannot represent a listener that already failed token
   preparation.
5. Every non-cancellation server UDP-listener exit cancels the generation.
   Normal cancellation completes cleanup without recursively reporting a new
   failure. Payload, session, queue, token, sweep, and tunnel bounds from round
   1 remain hard bounds, and datagram boundaries remain unchanged.

### Drop, cleanup, and status evidence

- The saturation regression observes `event=udp_drop
  reason="retirement_queue_full"`, followed by server and client
  `event=udp_cleanup` with zero sessions/tasks for generation 1 and a later
  generation-2 `registration_ready` plus `udp_channel_ready`. The status cannot
  remain falsely active after the listener loses reliable retirement delivery.
- The token-capacity regression observes `registration_ready ... listeners=1`
  for two requested UDP tunnels, exactly one ready data channel on each side,
  a positive echo on that listener, and no payload on the rejected port.
- The local-lease unit regression proves a late join result is a no-op against
  the replacement epoch. No extra table entry, socket, task, or queue is
  allocated to achieve that protection.

### Review-round verification

Observed on the final review tree:

```text
cargo test -p rustgo-e2e --test udp -- --nocapture
cargo test -p rustgo-protocol -p rustgos -p rustgoc --no-fail-fast
cargo test -p rustgo-e2e --test tcp -- --nocapture
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
git diff --check
```

- UDP real-process E2E: 16 passed, 0 failed, including the retirement saturation
  and token-capacity regressions.
- TCP real-process regression: 10 passed, 0 failed.
- Protocol/server/client focused run: 116 passed, 0 failed (protocol 32,
  Rustgos 55, Rustgoc 29).
- Full workspace: 191 passed, 0 failed; every doc test passed.
- Format check and workspace/all-target Clippy with warnings denied exited 0.
- `git diff --check` had no whitespace errors; Git printed only LF-to-CRLF
  checkout notices.

### Remaining concerns after round 2

- Fail-closed listener/retirement failure deliberately rebuilds the whole
  generation, briefly interrupting unrelated tunnels. This is the reliable
  V0.1 ownership choice; same-generation recovery would require an explicit
  listener-preserving channel handoff protocol.
- Pending UDP tokens now start their bounded TTL during registration. The
  30-second default comfortably covers the bounded 64-tunnel registration
  exchange, but an unusually short test TTL or a heavily stalled peer can
  still cause the later data bind to expire and correctly rebuild the
  generation.
- The controller-approved per-flow connected socket design remains strictly
  bounded by negotiated sessions and idle retirement. The bounded linear token
  owner lookup, Windows ephemeral fixture bind race, live IPv6, and
  Windows/Linux interoperability remain release-matrix work.
