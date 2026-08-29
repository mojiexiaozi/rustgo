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
