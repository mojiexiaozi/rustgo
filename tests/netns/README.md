# Linux complex-NAT acceptance suite

This directory is a privileged, real-process functional gate for Rustgo P2P. It creates only disposable `rgnt-*` network namespaces, veth devices, namespace-local firewall tables, state directories, and processes. It never changes the host firewall.

Requirements: Linux, root, `iproute2`, conntrack-tools, Python 3, OpenSSL, nftables or iptables, and release `rustgos`/`rustgoc` binaries. Missing prerequisites or kernel/root capabilities exit 77 with an explicit `SKIP`; topology, mapping, filtering, traffic, path, promotion-correlation, or cleanup failures exit nonzero. No userspace simulation is accepted as a passing NAT result.

Run the full gate twice and audit residue:

```bash
cargo build --workspace --release --locked
sudo bash tests/netns/run.sh all
sudo bash tests/netns/run.sh all
sudo bash tests/netns/assert_cleanup.sh
```

The suite exercises isolated provider/consumer networks behind separate routers, fixed TCP/UDP candidate ranges, authenticated two-port observation mappings, endpoint-independent, address/port-filtered, shared-LAN-style, and routed IPv6 direct paths, UDP drop with native TCP selection, deterministic destination-dependent source-port changes, all-direct-drop relay fallback, and relay-to-fresh-generation promotion. It correlates the promoted payload open with one structured session/open/generation and a direct authoritative `PathKind`; cleanup is audited in `finally` paths, including smoke and failures.

Namespace ownership is recognizable by the `rgnt-` prefix. Cleanup verifies process command lines before signalling and deletes only the current run's namespaces/interface/state. `assert_cleanup.sh` rejects any remaining owned namespace, interface, host nft table, state directory, or process.
