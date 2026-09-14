#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/topology.sh"
mode=${1:-endpoint-independent}
create_topology "$mode"
create_credentials_and_configs
start_stack
if [ "$mode" = restricted ]; then
    assert_restricted_filtering
fi
payload="quic-${mode}-${RG_RUN_ID}"
assert_udp_payload "$payload"
expected=QuicV4
[ "$mode" != ipv6-direct ] || expected=QuicV6
if ! grep -F "已确定对端通信路径 path=$expected" "$RG_STATE_DIR/consumer.log" >/dev/null; then
    wait_log "$RG_STATE_DIR/consumer.log" "新直连路径已启用" 20
    assert_udp_payload "${payload}-promoted"
fi
assert_selected_path "$expected"
echo "PASS: $mode selected $expected and preserved one UDP datagram"
