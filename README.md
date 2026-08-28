# Rustgo

Rustgo V0.1 is a self-hosted, fixed-port TCP and UDP tunnel. A private-network
client (`rustgoc`) connects to a public relay server (`rustgos`) over TLS 1.3,
authenticates with an independent Ed25519 device key, and exposes explicitly
configured ports.

V0.1 is **relay-only**: every application byte passes through `rustgos`. NAT
discovery, hole punching, direct P2P transport, and automatic P2P-to-relay
fallback are V0.2 work and are not partially implemented here.

## Build and validate

Install the stable Rust toolchain, then run:

```text
cargo build --workspace --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The binaries are `target/release/rustgos` and `target/release/rustgoc` (with
`.exe` on Windows). The platform smoke gates exercise real release processes,
ephemeral credentials, and both transports:

```text
bash scripts/e2e.sh
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
```

Each script creates one private temporary directory and removes only that
directory. Credentials are never written into Cargo or CI cache paths.

## Start safely

Generate a key pair on the client host:

```text
rustgoc keygen -o ./keys
```

Keep `keys/device.key` on the client. Copy only `keys/device.pub` to the server
operator and place its `ed25519:...` value in the matching server authorization
entry. Create a TLS server certificate whose SAN contains the real DNS name
used by clients, and configure every client with that same `server_name` plus
an explicit CA certificate file.

Copy [examples/server.toml](examples/server.toml) and
[examples/client.toml](examples/client.toml), provide their documented
environment variables, then validate without binding or contacting the peer:

```text
rustgos check -c ./server.toml
rustgoc check -c ./client.toml
```

With conventional filenames in the current directory, no-argument startup is
equivalent to explicit `-c`:

```text
rustgos                 # rustgos -c ./server.toml
rustgoc                 # rustgoc -c ./client.toml
```

Configuration is never searched in parent or platform-specific directories,
and missing files are not generated implicitly.

See [docs/operations.md](docs/operations.md) for certificate commands,
firewalls, service restarts, logging, key rotation, troubleshooting, and the
complete release checklist.

## Security and diagnostics

- Production traffic always uses TLS 1.3; there is no plaintext TOML option.
- The client name is an alias, not a credential. Name, enabled authorization,
  public key, signature, and challenge transcript must all match.
- Logs are human-readable, single-line text. JSON logging is not supported.
- Logs may include names, endpoints, IDs, and short fingerprints, but never
  private keys, full signatures, challenge material, or application payloads.

Rustgo is licensed under MIT or Apache-2.0.
