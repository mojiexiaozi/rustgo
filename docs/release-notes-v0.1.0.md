# Rustgo V0.1.0 release notes (draft)

Rustgo V0.1.0 establishes the relay-only baseline: TLS 1.3, per-device Ed25519
authentication, fixed-port TCP and UDP forwarding, bounded resources,
automatic reconnection, Linux/Windows CI, parser fuzzing, and text-only logs.
P2P is deferred to V0.2 and will retain relay fallback.

This draft is not a publication claim. Fill the final verification record from
the clean release checkout immediately before distribution.

## Verification record

- Source base before the Task 11 commit: `340378a837910f9635c240c2314bdfca119a7ef5`
- Host OS: Microsoft Windows 10 Pro 10.0.19045, 64-bit
- `rustc -Vv`: `rustc 1.98.0 (88d9e12ae 2026-08-18)`, host `x86_64-pc-windows-gnu`, LLVM 22.1.8
- `cargo -V`: `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- installed target triples: `x86_64-pc-windows-gnu`
- Windows release E2E: passed production credential `check`, managed default
  and explicit startup readiness, and TCP/UDP smoke transfers through release
  binaries
- Linux release E2E: not run on this host; no Bash or installed WSL distribution
- 60-second fuzz smoke: not run; `cargo-fuzz` is absent and this Windows GNU host failed to compile `libfuzzer-sys`'s Windows shim

Commands:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
cargo tree -d
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
bash scripts/e2e.sh
cargo +nightly fuzz run frame_decode -- -max_total_time=60
```

The platform scripts generate a real ephemeral CA, server certificate chain,
TLS private key, and device key pair outside cache paths. Default and explicit
startup gates keep owned PIDs, enforce readiness deadlines, drain both output
streams independently, and reap only those recorded processes.

## Artifact SHA-256

```text
efa50d6386301148d0ce913a18ac2b84e88dbda5d5083191cc53d6c1ae555dcd  rustgos.exe
c39ae01aff364015b5bf4a9a14e2289f2ff5db75b100d76c80689b54a4eb86d1  rustgoc.exe
NOT_BUILT_ON_THIS_HOST  rustgos
NOT_BUILT_ON_THIS_HOST  rustgoc
```

Only hashes for artifacts built and verified on their native target belong in
the final record. Never rename a Windows artifact as a Linux artifact or infer
an unexecuted platform result.
