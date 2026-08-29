# Linux complex-NAT acceptance suite

This directory is a privileged, real-process functional gate for Rustgo P2P. It creates only disposable `rgnt-*` network namespaces, veth devices, namespace-local firewall tables, state directories, and processes. It never changes the host firewall.

Requirements: Linux, root, `iproute2`, Python 3, OpenSSL, nftables or iptables, and release `rustgos`/`rustgoc` binaries. Missing kernel/root capabilities exit 77 with an explicit `SKIP`; missing binaries or failed traffic/path assertions fail. No simulation is accepted as a passing NAT result.

Run the full gate twice and audit residue:

```bash
cargo build --workspace --release --locked
sudo bash tests/netns/run.sh all
sudo bash tests/netns/run.sh all
sudo bash tests/netns/assert_cleanup.sh
```

The suite exercises isolated provider/consumer networks behind separate routers, fixed TCP/UDP candidate ranges, the authenticated two-port observation service, endpoint-independent, restricted, shared-LAN-style, and routed IPv6 direct paths, UDP drop with native TCP selection, changing-port/all-direct-drop relay fallback, relay-to-fresh-generation promotion, real TCP/UDP payload integrity, and process/resource teardown. Every data assertion also requires the consumer log to contain the authoritative selected `PathKind`.

Namespace ownership is recognizable by the `rgnt-` prefix. Cleanup verifies process command lines before signalling and deletes only the current run's namespaces/interface/state. `assert_cleanup.sh` rejects any remaining owned namespace, interface, host nft table, state directory, or process.
