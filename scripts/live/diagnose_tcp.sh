#!/usr/bin/env bash
set -u
cd /root/rustgo-v02-71812f7/source
run=${1:?run id required}
export RG_RUN_ID="tcpdiag-${run}-$$"
export RG_PREFIX="rgnt-${RG_RUN_ID}"
export RG_STATE_DIR="/run/${RG_PREFIX}"
source tests/netns/topology.sh
require_linux_root || exit $?
out="/root/rustgo-v02-71812f7/tcp-evidence/${run}"
mkdir -p "$out"
create_topology udp-drop
create_credentials_and_configs
pids=""
for ns in "$RG_SERVER_NS" "$RG_CLIENT_A_NS" "$RG_CLIENT_B_NS" "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
    ip netns exec "$ns" timeout 35 tcpdump -U -i any -nn -tttt -w "$out/${ns}.pcap" 'tcp or udp port 7443 or udp port 7444' >"$out/${ns}.tcpdump.log" 2>&1 &
    pids="$pids $!"
done
start_stack
set +e
if [ "${RG_TCP_ONLY:-0}" = 1 ]; then
    udp_status=99
else
    assert_udp_payload "udp-blocked-${run}"
    udp_status=$?
fi
assert_tcp_payload "tcp-native-${run}"
payload_status=$?
sleep 1
grep -Fq 'authoritative peer path selected path=NativeTcp' "$RG_STATE_DIR/consumer.log"
path_status=$?
for ns in "$RG_CLIENT_A_NS" "$RG_CLIENT_B_NS" "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
    ip netns exec "$ns" ss -tanop >"$out/${ns}.ss" 2>&1 || true
    ip netns exec "$ns" conntrack -L -p tcp >"$out/${ns}.conntrack" 2>&1 || true
done
for ns in "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
    ip netns exec "$ns" nft -a list table ip rustgo_netns >"$out/${ns}.rules" 2>&1 || true
done
cp "$RG_STATE_DIR"/*.log "$out/" 2>/dev/null || true
for pid in $pids; do kill "$pid" 2>/dev/null || true; done
wait $pids 2>/dev/null || true
for capture in "$out"/*.pcap; do tcpdump -nn -tttt -r "$capture" >"${capture%.pcap}.txt" 2>/dev/null || true; done
cleanup_topology
RG_AUDIT_PREFIX="$RG_PREFIX" RG_AUDIT_TAG="$RG_TAG" tests/netns/assert_cleanup.sh >"$out/cleanup.log" 2>&1
printf 'udp=%s payload=%s path=%s\n' "$udp_status" "$payload_status" "$path_status" | tee "$out/result"
exit "$path_status"
