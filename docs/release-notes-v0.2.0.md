# Rustgo V0.2.0 release notes

V0.2.0 adds mutually authenticated P2P exports and forwards while retaining
the V0.1 fixed-port TCP/UDP relay protocol. Direct QUIC/UDP and native-TCP paths
are selected only after device-key and rendezvous transcript verification; an
encrypted relay path remains available when configured.

## Operator changes

- Keep `7443/tcp` open for control and relay traffic.
- Open only `7443/udp` and `7444/udp` for NAT observation.
- Permit each client's configured fixed TCP/UDP P2P port ranges.
- Use a unique Ed25519 device key per client and explicit `allowed_peers` for
  least privilege. Missing or empty `allowed_peers` intentionally allows every
  authenticated client and emits `P2P_EXPORT_ALLOW_ALL`.
- Run `rustgos check -c server.toml` and `rustgoc check -c client.toml` before
  restart. Logs remain human-readable text; there is no JSON mode or web UI.

## Release evidence

The verified commit is `dac2930`. The deployed Linux `rustgos` SHA-256 is
`41b2147b795f9adff30cd7637d0788db52aae5b6a0dd4119e76646a6352dc9c9` and
the dereferenced rollback binary is
`/opt/rustgo/backups/v0.2-20260829T130952Z/rustgos.v0.1`. Windows and
Linux process gates and two Linux namespace passes completed successfully;
`frps` retained its original PID, listeners, and binary hash. No generated
private key or certificate is included in the repository or release artifact.
