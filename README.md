# Rustgo

Rustgo V0.4 is a self-hosted, fixed-port TCP, UDP, and authenticated P2P tunnel with optional embedded observability. A private-network client (`rustgoc` CLI or `rustgoc-gui`) connects to a public relay server (`rustgos`) over TLS 1.3, authenticates with an independent Ed25519 device key, and exposes explicitly configured ports.

V0.4 adds a cross-platform GUI client (`rustgoc-gui`) with real-time connection monitoring, tunnel display, traffic charts, P2P path visibility, and bounded resource usage. The GUI shares the same headless `rustgoc` library and connects to V0.1/V0.2/V0.3 servers without modification. On Windows, the GUI provides a system tray with minimize-to-tray support.

V0.3 added an optional read-only Web dashboard for real-time server and client monitoring, host telemetry, P2P path visibility, and bounded historical trends. The dashboard is loopback-only, HTTPS-ready via reverse proxy, and fully backward compatible with V0.2 and V0.1 clients.

V0.2 introduced named `[[exports]]` and `[[forwards]]`. Peers authenticate with their server-authorized device keys, try QUIC/UDP or native-TCP direct paths from fixed client port ranges, and fall back to the encrypted server relay when policy permits. Complex NAT can still prevent a direct path; relay fallback is a supported operating mode, not an authentication bypass.

## Build and validate

Install the stable Rust toolchain, then run:

```text
cargo build --workspace --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The binaries are `target/release/rustgos`, `target/release/rustgoc`, and `target/release/rustgoc-gui` (with `.exe` on Windows). The platform smoke gates exercise real release processes, ephemeral credentials, and both transports:

```text
bash scripts/e2e.sh
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
```

Each script creates one private temporary directory and removes only that directory. Credentials are never written into Cargo or CI cache paths. The Bash entry point is Linux-only and requires readable `/proc/<pid>/stat`, a kernel with `pidfd_open`/`pidfd_send_signal`, and Python 3.10+ exposing `os.pidfd_open` and `signal.pidfd_send_signal`. It opens one pidfd per cleanup attempt, verifies the recorded starttime only after that open, and sends TERM and any bounded KILL escalation through that same process object. Missing support or an unreadable identity fails the E2E run without a PID-only signal.

## GUI Client

The GUI client (`rustgoc-gui`) provides:
- Real-time connection status and generation display
- Live tunnel monitoring with protocol and port information
- Bounded log view (1,000 most recent lines)
- Traffic totals and network activity
- System tray integration on Windows (minimize to tray, quit from tray)

Run the GUI with:

```text
rustgoc-gui
```

The GUI and CLI both read `client.toml` beside their executable; neither accepts `-c` or `--config`. The GUI uses the same configuration format as the CLI client. Use `--selfcheck` to validate configuration and connectivity:

```text
rustgoc-gui --selfcheck
```

The selfcheck waits up to 30 seconds for an active connection, prints traffic and path status snapshots, then exits 0 on success. This is wired into the E2E scripts for automated validation.

All GUI-owned collections are bounded: 1,000 log lines, 300 telemetry chart points, 64 tray events. The GUI enforces `#![forbid(unsafe_code)]` and uses no GTK or AppIndicator dependencies on Linux.

## Releases

Pushing a version tag such as `v0.3` builds `rustgoc` and `rustgos` for Windows
x86_64, Linux x86_64, and Linux ARM64. The GitHub Release contains:

```text
rustgoc-win-x86-v0.3.zip
rustgos-win-x86-v0.3.zip
rustgoc-linux-x86-v0.3.zip
rustgos-linux-x86-v0.3.zip
rustgoc-linux-arm64-v0.3.zip
rustgos-linux-arm64-v0.3.zip
SHA256SUMS
```

Each ZIP contains one conventionally named executable and its matching
`client.toml` or `server.toml`. Linux ZIPs also contain
`docker-compose.yaml`. The configuration is an example: replace endpoints and
provide your own certificates and keys before startup. Releases never contain
generated credentials.

Verify checksums after downloading all seven assets. On Linux:

```text
sha256sum --check SHA256SUMS
```

On PowerShell:

```text
Get-Content SHA256SUMS | ForEach-Object {
    $hash, $name = $_ -split '  ', 2
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant() -ne $hash) {
        throw "Checksum mismatch: $name"
    }
}
```

See [docs/operations.md](docs/operations.md) for Compose deployment and the
maintainer release procedure.

## Start safely

Generate a key pair on the client host:

```text
rustgoc keygen -o ./keys
```

Keep `keys/device.key` on the client. Copy only `keys/device.pub` to the server operator and place its `ed25519:...` value in the matching server authorization entry. Create a TLS server certificate whose SAN contains the real DNS name used by clients, and configure every client with that same `server_name` plus an explicit CA certificate file.

Copy [examples/server.toml](examples/server.toml) and [examples/client.toml](examples/client.toml), provide their documented environment variables, then validate without binding or contacting the peer:

```text
rustgos check -c ./server.toml
rustgoc check
```

`check` uses the production credential loaders. The server parses every certificate in its TLS chain, validates the TLS private-key encoding and leaf/key match, and rejects malformed or weak Ed25519 authorization keys. The client parses every explicit CA certificate and its Rustgo device private key. These checks perform no bind or connect operation.

Place `client.toml` beside each client executable. The server defaults to `server.toml` in the current directory and also accepts `-c`:

```text
rustgos                 # rustgos -c ./server.toml
rustgoc                 # reads executable-adjacent client.toml
rustgoc-gui             # reads executable-adjacent client.toml
```

Configuration is never searched in parent or platform-specific directories. CLI startup requires `client.toml`; missing or damaged device keys are generated for approval-based enrollment. `check` validates existing credentials without requesting access. GUI `--selfcheck` connects and requires an already authorized device.

### Approval-based enrollment

With server enrollment and authenticated Web management enabled, new clients automatically request access over verified TLS. The administrator checks the public-key fingerprint and approves or rejects the request. Approved clients bind their key and connect automatically; pending keys and request IDs survive restart. This flow requires an updated server.

Use `rustgoc enroll` to request access, `rustgoc re-enroll` to reuse the current key, or `rustgoc re-enroll --confirm-replace-key` to explicitly request a replacement. The current key is retained until replacement approval. Back up the server enrollment database before upgrading to schema version 4. See [approval release instructions](deploy/approval-release/README.md).

See [docs/operations.md](docs/operations.md) for certificate commands, firewalls, service restarts, logging, key rotation, troubleshooting, and the complete release checklist.

## P2P ports and policy

The standard server layout uses `7443/tcp` for TLS control and relay traffic, `7443/udp` plus `7444/udp` for authenticated NAT observation. Each client also needs inbound/outbound access for its configured `p2p.udp_port_range` and `p2p.tcp_port_range`; choose non-overlapping ranges when several clients share one host. An export with omitted or empty `allowed_peers` permits every authenticated client and emits `P2P_EXPORT_ALLOW_ALL`. Set an explicit list for least privilege.

Human-readable logs report observation, selected path, promotion, and fallback events. The GUI client displays P2P path status (direct vs relay) in real-time via the public path-status store.

## Security and diagnostics

- Production traffic always uses TLS 1.3; there is no plaintext TOML option.
- The client name is an alias, not a credential. Name, enabled authorization,
  public key, signature, and challenge transcript must all match.
- Logs are human-readable, single-line text. JSON logging is not supported.
- Logs may include names, endpoints, IDs, and short fingerprints, but never
  private keys, full signatures, challenge material, or application payloads.

Rustgo is licensed under MIT or Apache-2.0.
