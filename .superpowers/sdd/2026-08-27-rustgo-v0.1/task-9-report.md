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
