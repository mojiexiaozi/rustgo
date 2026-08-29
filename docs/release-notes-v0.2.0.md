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

### Final release remediation

The final source commit is `e725769` (client behavior `5f38329` plus the
portable `*.sh text eol=lf` archive contract). The ordinary command
`git archive --format=tar HEAD` produced SHA-256
`da57d0adcf4b0835f1c7f469960b0e0b3b1f8921764417b838bac3c163b7f227`;
all seven extracted shell scripts contained zero CR bytes.

Installed SHA-256 hashes are
`6903017663a884a5f54668ea1734521630d75337676c23a7648cd25ea3580a3b`
for `rustgos` and `40ca8af27c994a9c47487b512b44c924e883c10769b4c51c7cf2bab68603cf6a`
for `rustgoc`. Mixed Windows/Linux acceptance preserved four exact 16-byte
payloads (normal TCP/UDP and forced-relay TCP/UDP) with zero warning, protocol
error, or invalid-state entries. Authenticated observation used the configured
public `7443/udp` and `7444/udp` pair; selected public data paths were Relay,
so no public direct-path claim is made.

Fresh final-archive Linux evidence passed `scripts/e2e.sh` and two consecutive
`tests/netns/run.sh all` runs. E2E log SHA-256 was
`95cd0123480d42aa91d6ea0345ee585670dce3bed0c11207d375217e94e5b23f`;
both namespace logs were
`3c8326bb8363aee211fff08161ab678ca6fd668d7baa7cf6b7a142d5de19596e`.
The final audit found no test namespace, rule, or owned process residue.
