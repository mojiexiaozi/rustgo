#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/topology.sh"
create_topology udp-drop
create_credentials_and_configs
start_stack
nat_a_udp_before=$(direct_drop_count "$RG_NAT_A_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST")
nat_b_udp_before=$(direct_drop_count "$RG_NAT_B_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST")
# Exercise the real Rustgo QUIC candidate first; its UDP service succeeds via
# relay, but both scoped NAT drop rules must see the attempted direct packets.
assert_udp_payload "udp-blocked-${RG_RUN_ID}"
payload="tcp-native-${RG_RUN_ID}"
assert_tcp_payload "$payload"
assert_selected_path NativeTcp
assert_direct_drop_evidence "$RG_NAT_A_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST" "$nat_a_udp_before"
assert_direct_drop_evidence "$RG_NAT_B_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST" "$nat_b_udp_before"
echo "PASS: UDP drop selected NativeTcp and preserved TCP bytes"
