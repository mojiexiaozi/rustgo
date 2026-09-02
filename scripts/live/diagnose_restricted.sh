#!/usr/bin/env bash
set -u
cd /root/rustgo-v02-71812f7/source
run=${1:?run id required}
export RG_RUN_ID="diag-${run}-$$"
export RG_PREFIX="rgnt-${RG_RUN_ID}"
export RG_STATE_DIR="/run/${RG_PREFIX}"
source tests/netns/topology.sh
require_linux_root || exit $?
out="/root/rustgo-v02-71812f7/evidence/${run}"
mkdir -p "$out"
create_topology restricted
create_credentials_and_configs
pids=""
for ns in "$RG_SERVER_NS" "$RG_CLIENT_A_NS" "$RG_CLIENT_B_NS" "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
    ip netns exec "$ns" timeout 35 tcpdump -U -i any -nn -tttt -w "$out/${ns}.pcap" 'udp or tcp port 7443' >"$out/${ns}.tcpdump.log" 2>&1 &
    pids="$pids $!"
done
start_stack
assert_restricted_filtering
assert_udp_payload "restricted-${run}"
payload_status=$?
assert_selected_path QuicV4
path_status=$?
for ns in "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
    ip netns exec "$ns" conntrack -L -p udp >"$out/${ns}.conntrack" 2>&1 || true
    if [ "$RG_FIREWALL" = nft ]; then
        ip netns exec "$ns" nft -a list table ip rustgo_netns >"$out/${ns}.rules" 2>&1 || true
    else
        ip netns exec "$ns" iptables-save -c >"$out/${ns}.rules" 2>&1 || true
    fi
done
cp "$RG_STATE_DIR"/*.log "$out/" 2>/dev/null || true
for pid in $pids; do kill "$pid" 2>/dev/null || true; done
wait $pids 2>/dev/null || true
for capture in "$out"/*.pcap; do tcpdump -nn -tttt -r "$capture" >"${capture%.pcap}.txt" 2>/dev/null || true; done
cleanup_topology
RG_AUDIT_PREFIX="$RG_PREFIX" RG_AUDIT_TAG="$RG_TAG" tests/netns/assert_cleanup.sh >"$out/cleanup.log" 2>&1
printf 'payload=%s path=%s\n' "$payload_status" "$path_status" | tee "$out/result"
exit "$path_status"
