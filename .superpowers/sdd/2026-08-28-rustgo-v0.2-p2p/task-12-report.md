# Task 12 report: Linux complex-NAT namespace suite

## Delivered

- Added a disposable namespace topology with separate server, provider, consumer, and two NAT-router namespaces.
- Added real release-process startup for one `rustgos` and two independently keyed `rustgoc` clients.
- Added authenticated observation endpoints on fixed UDP ports 7443/7444 and bounded fixed candidate ranges 41000-41003/UDP and 42000-42003/TCP.
- Added endpoint-independent mapping, address/port-dependent filtering, shared-LAN direct, routed IPv6 direct, UDP-drop/native-TCP, changing-port symmetric NAT, all-direct-drop relay, and relay-to-fresh-generation promotion scenarios.
- Added TCP byte-integrity and UDP datagram-integrity probes and authoritative `PathKind` log assertions.
- Added scoped PID, namespace, veth, firewall, and state cleanup plus an independent residue audit.
- Added a Linux CI gate that runs the complete suite twice and audits cleanup.

## Review hardening

- Symmetric NAT now assigns deterministic, destination-dependent external observation ports for authenticated 7443/7444 probes. The gate reads both clients' real namespace conntrack tuples, requires all four mappings, and rejects unchanged ports.
- Relay acceptance also requires nonzero namespace firewall counters for blocked native-TCP candidate attempts, separating intended direct filtering from an unrelated implementation failure.
- The restricted topology runs an active kernel-filter probe: the established server tuple is echoed, while an unsolicited datagram from an alternate server port must time out.
- Relay promotion requires a second authenticated observation generation and correlates the only post-marker payload open to a distinct structured `session_id`, `open_id`, `generation`, `io_start`, and `NativeTcp` path.
- Every case, including smoke and failing cases, uses one cleanup/final-audit path. A deterministic cleanup-audit self-test proves owned residue is rejected before smoke can pass.
- Missing commands, binaries, root, Linux, firewall support, or namespace capability now normalize to explicit exit 77. The disposable capability namespace is deleted on every probe path.

## Safety

- All namespaces and host veth/bridge names are scoped to `rgnt-<run-id>`.
- Firewall rules live only inside disposable NAT namespaces; the host firewall is never modified.
- Cleanup signals a recorded PID only when `/proc/<pid>/cmdline` still contains the owned run prefix.
- Capability discovery exits 77 with a specific `SKIP` message. Missing release binaries, failed traffic, wrong path selection, or residue fail closed.

## Verification evidence on current host

Current host: Windows 11 with no installed WSL distribution.

```text
bash -n tests/netns/topology.sh tests/netns/run.sh tests/netns/assert_cleanup.sh \
  tests/netns/test_quic.sh tests/netns/test_tcp.sh tests/netns/test_symmetric.sh
exit 0

bash tests/netns/run.sh all
SKIP: Linux ip-netns is required
exit 77
```

The review-hardening validation evidence is recorded by the follow-up commit. Live kernel assertions remain intentionally unaccepted on this host.

## External acceptance gate

Live NAT/path assertions have not been claimed as passing locally. The required external gate is the Linux CI job or an equivalent root-capable Linux host:

```bash
cargo build --workspace --release --locked
sudo bash tests/netns/run.sh all
sudo bash tests/netns/run.sh all
sudo bash tests/netns/assert_cleanup.sh
```

Task 13 production deployment is intentionally untouched.
