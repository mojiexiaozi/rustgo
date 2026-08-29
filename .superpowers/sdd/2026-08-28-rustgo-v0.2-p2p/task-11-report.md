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
