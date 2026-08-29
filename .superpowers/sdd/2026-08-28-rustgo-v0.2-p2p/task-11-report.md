# Task 11 report: production peer orchestration and encrypted relay fallback

## Delivered

- Wired `ClientApp`, authenticated control generations, `ForwardRuntime`, and
  `ExportRegistry` through a bounded production actor. Real service opens resolve the
  provider-authoritative protocol and obtain a selected peer stream/datagram path.
- Added append-only CandidateSetV2 (ID 28). QUIC, native TCP, and relay use independent,
  labelled, single-use X25519 keys bound to session, role, generation, export,
  identities, version, and expiry. Legacy IDs and CandidateSet remain parseable.
- Added TLS-authenticated peer identity/key bindings (IDs 26/27); clients reject
  duplicate, expired, role/name/session/protocol mismatches and key substitution.
- Added strict server generation fencing: only +1 after both current participants,
  with rate/max-generation limits and replay/skip/duplicate rejection.
- Added authenticated dual-endpoint NAT observation. Clients request grants over their
  authenticated control channel, validate nonce/source/endpoint/expiry, and merge
  bounded observed UDP candidates. Failure retains local candidates and relay fallback.
- Made Task7 `PathManager` the production path authority. A mutually authenticated
  relay remains behind a one-shot gate and exposes no application I/O until selected;
  QUIC/native TCP attempts race it under manager timing and cancellation.
- Wired `RecheckAttemptFactory` through actor oneshots. The initiator owns each strict
  +1 signed generation; the responder waits for it, responds once, and both factories
  return concrete fresh-key/fresh-transcript attempts. No parallel actor race remains.
- Relay carries Task3 end-to-end AEAD ciphertext only. rustgos requires bilateral,
  protocol-matching requests and enforces expiry plus queue/frame/byte/rate limits.
- Promotion applies atomically to subsequent opens. Existing TCP streams and UDP source
  sessions drain on their selected generation, avoiding mid-flow migration, duplicates,
  and cross-session mixing.

## Functional evidence (2026-08-29)

- `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1`:
  PASS. Real rustgos plus provider/consumer rustgoc processes enabled both observation
  endpoints, forced initial relay, transferred TCP/UDP, asserted observation and fresh
  direct promotion from child logs, transferred subsequent TCP/UDP, exercised forced
  relay, and shut down cleanly.
- `cargo test --workspace --all-targets -- --test-threads=1`: all suites before the
  stop point passed; Windows produced one OS 10057 `NotConnected` in the existing
  `streams_sixteen_mib_without_a_whole_transfer_buffer` case, so Cargo stopped before
  later packages.
- Required isolated diagnosis,
  `cargo test -p rustgo-e2e --test tcp -- --test-threads=1`: PASS 10/10, including the
  16 MiB case. The failure is not reproducible and is consistent with the known Windows
  process/socket flake, not a Task11 regression.

## Scope

Task 12 namespace topology and Task 13 packaging/deployment were not implemented.

## Re-review closure (2026-08-29)

- NAT observation now binds the rendezvous generation's deterministic fixed port from
  `udp_port_range`. Both authenticated probes use a cloned handle to that exact socket;
  the owning handle remains live and is transferred directly into the Quinn endpoint.
  Observation failure retains the same fixed socket for the local candidate/fallback.
- `QuicPathAttempt::with_socket` consumes the retained socket rather than rebinding.
  Functional transport coverage proves the tuple cannot be rebound while observed,
  becomes the selected QUIC local tuple, and is released only on cancellation/teardown.
- The production actor owns observation, PathManager, relay and direct I/O tasks in a
  `JoinSet`; teardown cancels sessions, closes managers, then drains tasks with a bounded
  timeout before the control generation returns and fixed ports are released.
- Relay selection now transfers the pending service-open reply only after PathManager
  chooses relay. Rejecting the gated relay cannot close a concurrently selected direct
  flow. Existing relay streams/datagram sessions continue to drain normally.
- The process test waits for both peers' authoritative promotion state and asserts the
  selected post-promotion paths: TCP `NativeTcp` and UDP `QuicV4`, while the initial
  flows are `Relay`.
- Final evidence:
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed;
  `cargo test --workspace --all-targets -- --test-threads=1` passed in full, including
  the fixed-socket QUIC regression and real three-process test.

## Final P2 closure (2026-08-29)

- Generation teardown now has two bounded phases. It first waits five seconds for all
  owned tasks to drain, then calls `JoinSet::abort_all` and keeps joining for a second
  five-second bound. A remaining task becomes an explicit `TimedOut` actor result and
  an actionable generation-level error; pending opens are not reported closed until
  this resource fence has completed or surfaced the hard failure.
- Each authoritative service flow emits correlated `selected`, `io_start`, and
  `io_finished` lifecycle records with the full rendezvous `session_id`, channel/open
  ID, protocol, generation, selected `PathKind`, peer, and export.
- The real-process test parses those records as structured fields. For distinct exact
  sessions it proves the transferred initial TCP and UDP opens selected `Relay`, while
  post-promotion TCP selected `NativeTcp` and post-promotion UDP selected `QuicV4`;
  assertions correlate path, protocol, generation, open ID, export, and session rather
  than accepting unrelated log substrings.
- Final focused evidence:
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed
  (1/1). The final workspace run reached the pre-existing Windows 16 MiB TCP case and
  stopped on OS 10057 after 9/10 TCP cases; the required single isolated rerun,
  `cargo test -p rustgo-e2e --test tcp -- --test-threads=1`, passed 10/10 including that
  case. The immediately preceding full workspace gate passed all targets, so the
  isolated evidence identifies the final failure as the known non-reproducible Windows
  socket flake rather than a Task 11 regression.

## Generation fail-stop closure (2026-08-29)

- `PeerGenerationHandler::run_generation` now returns `Result<(), ClientError>` and the
  control session owns its join handle separately from ordinary event/data children.
  Actor errors and join failures therefore reach `ControlSession` and `ClientApp`
  instead of being reduced to logs.
- The active generation is cleared only after all data children and the peer owner have
  joined. Control disconnect still records the backoff timestamp immediately, so a slow
  teardown cannot be misclassified as a stable connection, but no reconnect or fixed
  port reuse begins before the resource fence.
- Actor teardown waits gracefully, then aborts all remaining Tokio tasks and
  unconditionally continues `join_next` until the `JoinSet` is empty. A five-second
  watchdog is diagnostic only and cannot release ownership; a forced abort returns a
  peer-generation failure. `ClientApp` treats peer-owner failure or join failure as
  fail-stop and returns the error rather than opening a new control generation.
- Functional coverage injects a slow failing peer owner into a real TLS control
  generation. It proves the generation remains active, the app does not finish or
  reconnect while the owner is unjoined, and after release the exact
  `PeerGenerationFailed` result is visible with no second socket accepted.
- Final evidence:
  `cargo test -p rustgoc --test control -- --test-threads=1` passed 11/11;
  `cargo test -p rustgoc --tests -- --test-threads=1` passed all rustgoc unit and
  functional targets, including the real rustgos plus two-rustgoc TCP/UDP process test.

## Direct data-plane control-loss isolation (2026-08-29)

- `ProductionPeerRuntime`, its actor, and configured `ForwardRuntime` are now
  process-lifetime owners rather than TLS-control-generation children. Each authenticated
  control generation attaches/detaches an explicitly fenced `ChildSessionContext`; stale
  events from an older generation are ignored, while reconnect installs only a strictly
  newer authoritative generation.
- Control detach immediately rejects new rendezvous/service opens and cancels relay or
  not-yet-selected sessions. Sessions whose application flow already selected
  `NativeTcp`, `QuicV4`, or `QuicV6` retain their independently authenticated transport
  and existing forward/export pumps for a bounded 15-second control-reconnect grace.
  Relay remains honestly dependent on rustgos and cannot survive the detach.
- The control grace is intentionally independent from `reconnect_timeout_secs`, which
  remains the PathManager direct-path recovery/recheck interval. Successful control
  reconnect clears the grace fence and rebinds new control-dependent work without
  changing the identity, transcript, session, or path generation of retained flows.
- Session cryptographic expiry still closes retained direct work. Authentication/key
  revocation that prevents reconnect leaves the runtime detached and closes retained
  work at the grace deadline. Explicit process shutdown cancels the persistent owner,
  shuts down forwards, and drains the actor's structured tasks before returning.
- The real rustgos plus two-rustgoc process test now holds an authenticated NativeTcp
  stream and QuicV4 UDP session open, kills rustgos, and proves both continue carrying
  payload while a new open is fenced and the existing relay flow fails. It restarts
  rustgos, observes both clients' `peer_control_rebound`, and proves the exact retained
  direct TCP and UDP flows still transfer payload before final process cleanup.
- Final evidence:
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed;
  `cargo test -p rustgoc --tests -- --test-threads=1` passed all rustgoc targets,
  including control lifecycle, forwards/exports, relay and the expanded process test.

## Mixed-OS delayed UDP relay fix (2026-08-29)

- Phase-1 correlation of the Windows-consumer/Linux-provider failure identified a
  server-side generation race rather than a persistent-runtime rebind defect. A TCP
  relay frame arrived before background direct recheck, while the slower UDP frame
  arrived after strict CandidateSetV2 `generation + 1`. rustgos reset the session's
  bilateral relay admission during that candidate advance, rejected the delayed opaque
  frame with protocol code 5, and the resulting consumer disconnect explained the
  provider's early `io_finished`.
- Relay authorization is now correctly session-scoped. Candidate generation advancement
  refreshes candidate digests and transport attempts but does not revoke an already
  bilateral relay for the same accepted session/protocol. It also cannot authorize a
  relay that was not already bilateral. Exact expiry, explicit close/disconnect,
  datagram/reliable flag matching, rate/byte admission and tombstones remain unchanged.
- A real TLS control functional regression now accepts both datagram RelayRequests,
  advances both participants to CandidateSetV2 generation 2 after the minimum generation
  fence, delays traffic, and proves opaque datagrams route and reply in both directions.
  It also proves an unknown session is rejected and explicit close immediately revokes
  the previously authorized relay. Existing expiry/tombstone coverage remains green.
- Final evidence:
  `cargo test -p rustgos --test rendezvous -- --test-threads=1` passed 10/10;
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed;
  `cargo clippy -p rustgos -p rustgoc --all-targets -- -D warnings` passed, as did
  `cargo fmt --all -- --check` and `git diff --check`.

## Cross-generation partial relay authorization fence (2026-08-29)

- CandidateSetV2 advancement now preserves relay state only when both participants had
  already authorized the relay before the generation boundary. Any partial
  `requested_by` state and its associated datagram/rate admission are reset when the
  session advances, so requests from different generations cannot compose into an
  authorization.
- A real TLS control regression covers one initiator request in generation 1, advances
  the same accepted datagram session to generation 2, and proves the responder's lone
  generation-2 request still rejects an opaque frame. A fresh initiator request in
  generation 2 then completes bilateral authorization and the identical frame routes.
  The existing regression continues to prove that a relay already bilateral before a
  recheck remains usable across the generation advance.
- Final evidence:
  `cargo test -p rustgos --test rendezvous -- --test-threads=1` passed 11/11;
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed;
  `cargo clippy -p rustgos -p rustgoc --all-targets -- -D warnings` passed, as did
  `cargo fmt --all -- --check` and `git diff --check`.

## Closed-session in-flight relay frame handling (2026-08-29)

- Production diagnostics identified the mixed-OS control reset as a late consumer TCP
  relay frame arriving 60 ms after the provider had finished I/O and closed the same
  fully authorized session. The frame hit the tombstone and the generic relay-frame
  rejection path returned connection-fatal protocol code 5; the following UDP open was
  consequently interrupted before reaching the provider.
- Tombstones now retain the two exact authenticated control-session owners until their
  existing fixed expiry. A relay frame for that exact closed session from either owner
  is dropped idempotently without forwarding, refreshing expiry, changing admission or
  consuming relay counters. A different authenticated identity and an unknown session
  remain rejected, as do all active-session authorization, protocol, flag, rate and
  queue violations. Session/tombstone capacity and expiry behavior are unchanged.
- Safe structured diagnostics remain for RelayRequest admission transitions and every
  relay-frame rejection/drop reason. They correlate session, sender role, generation,
  protocol, admission bits, phase, expiry and flags without recording ciphertext,
  tokens or keys.
- A real TLS functional regression establishes bilateral TCP relay, closes it from the
  provider, sends a delayed consumer frame, proves the frame is not forwarded and the
  control heartbeat remains usable, rejects wrong-identity and unknown-session frames,
  then establishes and transfers an independent bilateral UDP relay session on the same
  control connections.
- Final evidence:
  `cargo test -p rustgos --test rendezvous -- --test-threads=1` passed 12/12;
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed;
  `cargo clippy -p rustgos -p rustgoc --all-targets -- -D warnings` passed, as did
  `cargo fmt --all -- --check` and `git diff --check`.

## Responder decision/candidate ordering fence (2026-08-29)

- Clean-start mixed-OS tracing proved that the provider's authenticated NAT observation
  could finish before peer identity binding. Because the locally authorized export had
  already populated `protocol`, the responder emitted CandidateSetV2 before its signed
  ProviderDecision. rustgos correctly returned an invalid-state ServerNotice; the actor
  removed the session, and the later valid PunchGrant was rejected as `unknown_session`.
- A session now tracks authoritative provider-decision acceptance separately from local
  export protocol authorization. Observation completion retains the bounded owned socket
  and candidates, but CandidateSetV2 cannot be emitted until the accepted decision has
  been sent in protocol order. Candidate emission is fenced to once per generation;
  rejection, expiry, cancellation and normal structured socket teardown retain their
  existing behavior. ServerNotice handling remains fail-closed.
- The real rustgos plus two-rustgoc process test adds a deterministic lifecycle scenario
  that delays identity binding while authenticated observation completes first. It
  proves no pre-decision candidate rejection occurs, then transfers TCP and UDP over the
  resulting relay session, with structured correlation asserting at most one candidate
  emission for each session generation. Existing direct promotion and forced-relay
  scenarios remain separate and unchanged.
- Final evidence:
  `cargo test -p rustgoc --test peer_process -- --nocapture --test-threads=1` passed
  all three real-process scenarios; the control functional target passed 11/11;
  rustgoc all-target Clippy with warnings denied, fmt check and diff check passed.

## Resolve-only terminal pending drain (2026-08-29)

- Startup protocol discovery could queue ProviderDecision and CandidateSetV2 before the
  peer identity binding. Applying the accepted decision completed the resolve, sent one
  Close and removed the exact session, but the binding loop then tried to apply the
  remaining candidate to the removed session and logged a spurious invalid-state event.
- Pending drain now stops only when applying the preceding authenticated envelope
  terminally removes that exact session. Remaining pending values are dropped normally;
  live-session errors are still propagated and ordinary non-terminal pending decision
  plus candidate ordering continues through the same validation path.
- The deterministic delayed-binding real-process scenario now asserts that both startup
  resolve-only probes emit no orchestration rejection, while listeners become ready and
  subsequent non-terminal TCP and UDP sessions still transfer successfully.
- Final evidence: the three-scenario real-process peer test passed; the control
  functional target passed 11/11; rustgoc all-target Clippy with warnings denied, fmt
  check and diff check passed.
