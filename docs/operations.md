# Rustgo V0.2 operations

## Scope and topology

Rustgo V0.2 preserves the V0.1 relay protocol and adds authenticated P2P.
`rustgoc` maintains one TLS control connection to `rustgos`; configured legacy
`[[tunnels]]` remain relay mappings. P2P `[[forwards]]` request named
`[[exports]]`, attempt fixed-port QUIC/UDP or native-TCP direct paths, and use
the encrypted relay when direct connectivity fails and fallback is enabled.

The server needs a stable DNS name and public address. In the examples below,
`tunnel.example.com` resolves to the server, TCP 7443 is the TLS control/data
listener, TCP 2222 is a public forwarded port, and UDP 27015 is a public
forwarded port.

## Install

Build on each target OS or install the corresponding release artifacts:

```text
cargo build --workspace --release
```

Install `rustgos` only on the public server and `rustgoc` on each authorized
private host. Run each process as a dedicated unprivileged service identity.
Keep server TLS private keys and client device private keys readable only by
their owning service account. Do not place credentials below a Cargo `target`
directory or another cached build directory.

## Create the TLS identity

The certificate SAN must contain the real DNS name configured as
`client.server_name`; an IP address or an unrelated local hostname is not a
substitute. The following OpenSSL example creates a private CA and a server
certificate for `tunnel.example.com`:

```text
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 -keyout ca.key -out ca.crt -subj "/CN=Rustgo Private CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -new -newkey rsa:3072 -sha256 -nodes -keyout server.key -out server.csr -subj "/CN=tunnel.example.com" -addext "subjectAltName=DNS:tunnel.example.com"
```

Create `server-ext.cnf`:

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:tunnel.example.com
```

Then sign the request:

```text
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 -extfile server-ext.cnf
openssl verify -CAfile ca.crt server.crt
```

Keep `ca.key` offline after signing. Install `server.crt` and `server.key` on
the relay server. Copy `ca.crt` (never `ca.key`) to every client and set
`certificate_authority_file` explicitly. A public-CA certificate is also
supported, but V0.1 still requires the explicit CA bundle path.

## Create and authorize a device

Run key generation on the client host:

```text
rustgoc keygen -o ./keys
```

This creates `device.key` and `device.pub` without overwriting an existing
pair. `device.key` never leaves the client. Transfer only `device.pub` to the
server operator through an authenticated channel, then copy its complete
`ed25519:...` line into one enabled `[[clients]]` entry. Client names and public
keys must each be unique; the name alone never authenticates a client.

The checked-in examples use environment substitution so they contain no real
credentials:

| Variable | Used by | Value |
| --- | --- | --- |
| `RUSTGO_SERVER_CERTIFICATE_FILE` | server | absolute path to `server.crt` |
| `RUSTGO_SERVER_PRIVATE_KEY_FILE` | server | absolute path to `server.key` |
| `RUSTGO_SERVER_UDP_BIND_IP` | server | specific local interface IP used for public UDP tunnel listeners |
| `RUSTGO_DEVICE_PUBLIC_KEY` | server | complete contents of `device.pub` |
| `RUSTGO_CERTIFICATE_AUTHORITY_FILE` | client | absolute path to `ca.crt` |
| `RUSTGO_DEVICE_PRIVATE_KEY_FILE` | client | absolute path to `device.key` |

An absent environment variable is an error. Unknown TOML fields are rejected.
Relative file paths are resolved against the directory containing the selected
configuration, not against the executable or a platform config directory.

## Configure and check

Use [../examples/server.toml](../examples/server.toml) and
[../examples/client.toml](../examples/client.toml) as the starting point. The
client example demonstrates both supported fixed-port mappings:

```toml
[[tunnels]]
name = "ssh"
protocol = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 2222

[[tunnels]]
name = "game"
protocol = "udp"
local_addr = "127.0.0.1:27015"
remote_port = 27015
```

The control/data TLS listener may use `bind_addr = "0.0.0.0:7000"`. UDP flow
identity, however, requires a real destination address. When `bind_addr` uses
`0.0.0.0` or `::`, set `server.udp_bind_ip` to one specific address assigned to
the server interface that receives the forwarded UDP traffic. Behind NAT, use
the address actually assigned to the host, not an external NAT address that the
host cannot bind. `0.0.0.0` and `::` are rejected as `udp_bind_ip`. If this field
is omitted with a wildcard control bind, UDP tunnel registrations are rejected
individually with `UDP_BIND_ADDRESS_REQUIRED`; TCP tunnels remain available.
When `bind_addr` already names a specific IP, `udp_bind_ip` may be omitted and
that IP is used for UDP listeners.

`check` uses the same strict parser, validation, path resolution, and
production credential loaders as startup. `rustgos check` parses every DER
certificate in the configured TLS chain, validates the TLS private-key format
and leaf/key match, and parses every authorized Ed25519 public key (including
weak-key rejection). `rustgoc check` parses every certificate in the explicit
CA chain and loads the Rustgo device private key. It does not bind a listener,
open a socket, resolve the peer, or contact the server:

```text
rustgos check -c C:\rustgo\server.toml
rustgoc check -c C:\rustgo\client.toml
rustgos check -c /etc/rustgo/server.toml
rustgoc check -c /etc/rustgo/client.toml
```

An explicit `-c` or `--config` selects exactly that file. With no arguments,
the current directory must contain the conventional filename:

```text
rustgos              == rustgos -c ./server.toml
rustgoc              == rustgoc -c ./client.toml
```

There is no `run` subcommand. Missing configuration, key, certificate, or CA
files are fatal; Rustgo does not search parent directories or generate them.

## Firewall and routing

Allow only configured ports:

- inbound TCP 7443 to `rustgos` for TLS control, legacy relay, and P2P relay;
- inbound UDP 7443 and UDP 7444 for authenticated NAT observation;
- inbound TCP 2222 for the example TCP mapping;
- inbound UDP 27015 for the example UDP mapping;
- outbound access from `rustgoc` to `tunnel.example.com:7443` over TCP and to
  `7443/udp` plus `7444/udp` when observation is enabled;
- inbound and outbound TCP/UDP for each client's configured fixed P2P port
  ranges (the example uses `7400-7499`); do not expose unrelated ports;
- client-host loopback access from `rustgoc` to the configured local targets.

Do not expose the local target itself to an untrusted LAN merely to make the
tunnel work. Every additional tunnel requires its own public firewall rule for
the configured transport. TCP and UDP can use the same numeric port because
they are distinct protocols.

## P2P exports, diagnostics, and fallback

An export names one local TCP or UDP service. `allowed_peers = ["laptop"]`
authorizes only those authenticated device names. If `allowed_peers` is omitted
or empty, all authenticated clients are authorized and rustgoc emits warning
code `P2P_EXPORT_ALLOW_ALL`. A forward binds a local address and selects the
provider peer plus export name; keep it on loopback unless LAN exposure is
intentional.

Direct connectivity is opportunistic. Symmetric or endpoint-dependent NAT,
carrier NAT, host firewalls, and short mapping lifetimes may prevent hole
punching. Inspect human-readable logs for authenticated observation candidates,
`peer service flow` path selection, direct promotion, and relay fallback. A
relay result is expected when `allow_relay_fallback = true`; disabling fallback
makes failure closed. Never weaken device authorization to improve NAT reachability.

## Start, restart, and upgrade

Run `check` before every start or restart. Start the server first, then the
client. V0.1 does not reload TOML, keys, authorization, certificates, limits,
or log settings in place: changes require a process restart.

When the server restarts, connected clients retry with capped jittered backoff,
authenticate again, and re-register all configured tunnels. During the restart
public mappings are unavailable. A client disconnect releases its server-side
listeners and data sessions; stale listener ownership is not retained.

For systemd upgrades:

1. save the checked configuration and artifact hashes;
2. stop the client, then replace its binary and restart it for a client-only
   upgrade;
3. for a server upgrade, copy the new binary beside the installed binary,
   verify its SHA-256, run `new-rustgos check -c /etc/rustgo/server.toml`, stop
   `rustgos`, preserve the old binary as a rollback copy, atomically rename the
   new binary into place, and start it; clients reconnect automatically;
4. verify one TCP and one UDP transfer and inspect both process logs.

After restart run `systemctl is-active rustgos` and inspect
`journalctl -u rustgos`; confirm unrelated services (including `frps` when
co-hosted) were neither restarted nor reconfigured.

## Logs

V0.2 emits human-readable, single-line text only. JSON logging and a web status
UI are not supported. Levels are `error`, `warn`, `info`, `debug`, and `trace`;
the default is `info`. Set `RUST_LOG` before process startup, for example:

```text
RUST_LOG=info rustgos -c /etc/rustgo/server.toml
RUST_LOG=rustgos=debug,rustgo_transport=info rustgos -c /etc/rustgo/server.toml
```

PowerShell:

```text
$env:RUST_LOG = "rustgoc=debug,rustgo_transport=info"
.\rustgoc.exe -c C:\rustgo\client.toml
```

Use `debug` or `trace` temporarily because they are verbose. Logs may contain
names, endpoints, connection/session IDs, and short public fingerprints. They
must not contain private keys, full signatures, authentication challenges, or
application payloads. Treat any log collector as operational metadata, not a
stable machine-readable API.

## Safe device-key rotation

`rustgoc keygen` refuses to overwrite, so generate into a new directory:

```text
rustgoc keygen -o ./keys-next
```

Because one client name maps to one authorized public key, V0.1 rotation is a
controlled restart rather than a dual-key overlap:

1. keep the old pair offline for rollback and verify `keys-next/device.pub`;
2. stop the old client;
3. replace only that client's server authorization with the new public key,
   run `rustgos check`, and restart the server;
4. point the client TOML at `keys-next/device.key`, run `rustgoc check`, and
   restart the client;
5. verify registration plus TCP and UDP traffic, then securely retire the old
   private key and remove the old public authorization.

Never copy either private key to the server. If rollback is needed, stop the
client and restore the old public/private references as one coordinated change.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `cannot read configuration` | Confirm the current directory for no-argument startup, or pass the exact file with `-c`. |
| missing referenced file | Remember relative paths are based on the TOML directory; verify service-account permissions as well as existence. |
| `check` reports a TLS certificate/key error | Verify every PEM certificate decodes to complete DER, the server leaf matches its private key, and the client CA file contains only intended trust roots. |
| TLS certificate or server-name failure at startup | Verify DNS, the certificate SAN, validity dates, and that the explicit CA file signed the server certificate. |
| authentication rejected | Confirm name, enabled status, public key on the server, and matching private key on the client. Do not rotate one side alone. |
| heartbeat incompatibility or reconnect loop | Keep `heartbeat_interval_secs` strictly below server `heartbeat_timeout_secs`; inspect both logs and clocks. |
| tunnel rejected with port conflict | Find the process or another Rustgo tunnel already owning that TCP/UDP port; one failed tunnel does not invalidate unrelated tunnels. |
| TCP connects but local service fails | Verify `local_addr` is listening on the client host and allows the Rustgo service identity. |
| UDP receives no reply | Check both-direction UDP firewall/NAT rules, the local UDP target, payload limits, and bounded-session/queue warnings. |
| configuration edit has no effect | Restart the affected V0.1 process; live reload is not implemented. |
| logs appear silent | Start with `RUST_LOG=info`, then temporarily raise the relevant crate to `debug`; V0.1 has no JSON/status endpoint. |

## Release gates

Run all commands from a clean checkout with the intended stable toolchain:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
cargo tree -d
```

Run the matching platform E2E entry point. The Bash E2E entry point is
Linux-only and requires readable `/proc/<pid>/stat`, Linux kernel pidfd support,
and Python 3.10+ with `os.pidfd_open` and `signal.pidfd_send_signal`. Its
preflight opens a pidfd before any E2E child or temporary credential is
created. Cleanup opens one pidfd for the recorded PID, validates the expected
starttime after the open, and performs TERM, bounded polling, KILL escalation,
and final bounded polling through that same pidfd. If the APIs, kernel support,
or identity check are unavailable, cleanup sends no PID-only signal and the E2E
gate exits nonzero.

The Linux CI gate runs both the mockable pidfd state-machine suite and real
pidfd integration cases for identity mismatch, cooperative TERM, and
TERM-to-KILL escalation before the release E2E script.

On a supported Linux/nightly libFuzzer host, install `cargo-fuzz` and run the
bounded parser smoke:

```text
cargo +nightly fuzz run frame_decode -- -max_total_time=60
```

Do not substitute a successful compile for the fuzz run. Record unavailable
hosts or toolchains as blocked evidence. Before publishing, record `rustc -Vv`,
`cargo -V`, installed target triples, the exact verification commands, and
SHA-256 for every distributed binary. Generated private keys and certificates
must not be present in the checkout, archive, or CI cache.
