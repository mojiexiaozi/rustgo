# Rustgo V1.0.0 Release Notes

## Summary

Rustgo V1.0.0 is the first stable release of the authenticated TCP and UDP
tunneling platform. It includes approval-based client enrollment, managed
forwarding configuration, encrypted peer-to-peer paths with relay fallback,
operational telemetry, authenticated Web management, and the desktop GUI
client.

## Server deployment

- `rustgos` generates a self-signed TLS certificate and private key when both
  configured identity files are absent during normal startup.
- Generated identities include `server.tls_server_name`, the enrollment public
  host, a concrete bind address, and loopback names and addresses.
- Existing identity files are never overwritten. A half-existing or mismatched
  identity fails closed.
- Identity creation is serialized and crash recoverable. Private keys use
  owner-only permissions on Unix and a restricted account ACL on Windows.
- The generated certificate SHA-256 fingerprint is logged for distribution
  through a protected channel.
- The server `check` command remains read-only and requires existing identity
  files.

## Client and management

- Clients can request approval over verified TLS and preserve pending
  enrollment state across restarts.
- Administrators can approve, disable, restore, and manage client tunnel
  configuration through authenticated Web management.
- Managed configuration uses revision checks and reconnect reconciliation to
  avoid stale updates and leaked listeners.
- Launching the GUI again brings the existing window to the foreground without
  racing application startup or shutdown.

## Networking and security

- TCP and UDP tunnels use authenticated TLS 1.3 control channels.
- Peer-to-peer QUIC/UDP and native TCP paths use authenticated ephemeral keys,
  with encrypted relay fallback when a direct path cannot be established.
- Resource limits, heartbeat deadlines, replay protection, bounded queues, and
  authenticated telemetry are enforced throughout the runtime.
- Logs redact private keys, authentication material, and application payloads.

## Upgrade notes

- Back up the server enrollment and telemetry databases before upgrading.
- Set `server.tls_server_name` to the DNS name or IP used by clients.
- Existing server TLS certificate and key files continue to be reused.
- A fresh deployment can leave both configured server identity paths absent;
  the service account only needs write access to their parent directory.
- Review the updated Compose template, which stores the generated server
  identity in the writable `data` directory.

## Release artifacts

The release workflow publishes `rustgoc`, `rustgoc-gui`, and `rustgos` archives
for Windows x86_64, Linux x86_64, and Linux ARM64, plus `SHA256SUMS`. GUI
archives contain the executable and `client.toml`; they do not contain a
Compose template. Verify the checksum manifest before installation.
