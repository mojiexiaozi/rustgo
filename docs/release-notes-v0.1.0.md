# Rustgo V0.1.0 release notes (draft)

Rustgo V0.1.0 establishes the relay-only baseline: TLS 1.3, per-device Ed25519
authentication, fixed-port TCP and UDP forwarding, bounded resources,
automatic reconnection, Linux/Windows CI, parser fuzzing, and text-only logs.
P2P is deferred to V0.2 and will retain relay fallback.

This draft is not a publication claim. The record below describes the final
fix wave verified on the stated Windows host; unexecuted platform gates remain
explicitly unverified.

## Verification record

- Final implementation commit: `d85b0352bbbcad17387fd0044ebb74e4f9404e16`
- Final-fix baseline: `935fbb948e0320c57810ceaba690681237c9bd4e`
- Host OS: Microsoft Windows 10 Pro 10.0.19045, 64-bit
- `rustc -Vv`: `rustc 1.98.0 (88d9e12ae 2026-08-18)`, host
  `x86_64-pc-windows-gnu`, LLVM 22.1.8
- `cargo -V`: `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- Installed target triples: `x86_64-pc-windows-gnu`
- Windows release E2E: passed production credential checks, managed default
  and explicit startup readiness, and TCP/UDP smoke transfers through release
  binaries.
- Git Bash cleanup self-tests: passed with GNU Bash 5.2.37 and Python 3.13.12,
  including identity mismatch, a hung-helper hard deadline, and signal injection
  at cleanup entry.
- Native Linux release E2E: not run in this final-fix wave. Git Bash is not a
  native Linux result.
- Fuzzing and cross-OS validation: not run in this final-fix wave.

Commands that passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast -q
cargo build --workspace --release
cargo tree -d
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
"C:\Program Files\Git\bin\bash.exe" -n scripts/e2e.sh
RUSTGO_PIDFD_PYTHON=/c/Users/kimi/miniconda3/python.exe bash scripts/e2e.sh --self-test
C:\Users\kimi\miniconda3\python.exe -m unittest -v scripts.pidfd_supervisor_test.PidfdSupervisorStateMachineTests
```

The platform scripts generate a real ephemeral CA, server certificate chain,
TLS private key, and device key pair outside cache paths. Default and explicit
startup gates keep owned process objects, enforce readiness deadlines, drain
both output streams independently, and reap only recorded processes. The
example wildcard control listener supplies an explicit loopback UDP bind
identity during E2E.

`cargo tree -d` remains an informational dependency audit. It reports expected
distinct transitive versions of `getrandom`, `rand_core`, `syn`, `windows-sys`,
and `winnow`; it is not a zero-duplicate gate.

## Artifact SHA-256

```text
1ff076ffffbf62c8189625db22ff75249c6e52429be7cffc33ab8658801ce152  rustgos.exe
4160a7a408a793882e9966e8560a97e75e75d8d4c48d290e0bc56879511b7ee2  rustgoc.exe
NOT_BUILT_ON_THIS_HOST  rustgos
NOT_BUILT_ON_THIS_HOST  rustgoc
```

Only hashes for artifacts built and verified on their native target belong in
the final record. Never rename a Windows artifact as a Linux artifact or infer
an unexecuted platform result.
