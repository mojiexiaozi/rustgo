#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/topology.sh"
mode=${1:-symmetric}
create_topology "$mode"
create_credentials_and_configs
start_stack
nat_a_udp_before=$(direct_drop_count "$RG_NAT_A_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST")
nat_b_udp_before=$(direct_drop_count "$RG_NAT_B_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST")
nat_a_tcp_before=$(direct_drop_count "$RG_NAT_A_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST")
nat_b_tcp_before=$(direct_drop_count "$RG_NAT_B_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST")
if [ "$mode" = all-direct-drop ]; then
    assert_udp_payload "all-direct-udp-${RG_RUN_ID}"
    assert_selected_path Relay
fi
payload="relay-${mode}-${RG_RUN_ID}"
assert_tcp_payload "$payload"
assert_selected_path Relay
relay_line=$(grep -F "peer service flow" "$RG_STATE_DIR/consumer.log" | grep -F 'lifecycle="selected"' | grep -F "path=Relay" | tail -n 1)
relay_session=$(sed -n 's/.*session_id=\([^ ]*\).*/\1/p' <<<"$relay_line")
[ -n "$relay_session" ] || { echo "FAIL: relay selection lacked structured session evidence" >&2; exit 1; }
capture_observation_mappings initial
if [ "$mode" = symmetric ]; then
    assert_changed_observation_mappings "$RG_STATE_DIR/observation-initial.tsv"
    assert_direct_drop_evidence "$RG_NAT_A_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST" "$nat_a_tcp_before"
    assert_direct_drop_evidence "$RG_NAT_B_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST" "$nat_b_tcp_before"
    grep -Fq "path=Relay" "$RG_STATE_DIR/consumer.log" || { echo "FAIL: changing mappings did not end in relay" >&2; exit 1; }
fi
if [ "$mode" = all-direct-drop ]; then
    assert_direct_drop_evidence "$RG_NAT_A_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST" "$nat_a_udp_before"
    assert_direct_drop_evidence "$RG_NAT_B_NS" udp "$RG_UDP_FIRST:$RG_UDP_LAST" "$nat_b_udp_before"
    assert_direct_drop_evidence "$RG_NAT_A_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST" "$nat_a_tcp_before"
    assert_direct_drop_evidence "$RG_NAT_B_NS" tcp "$RG_TCP_FIRST:$RG_TCP_LAST" "$nat_b_tcp_before"
    allow_direct_after_relay
    wait_log "$RG_STATE_DIR/consumer.log" "fresh direct path promoted" 25
    [ "$(grep -Fc "authenticated NAT observation candidates ready" "$RG_STATE_DIR/consumer.log")" -ge 2 ] || {
        echo "FAIL: promotion did not complete a fresh authenticated observation generation" >&2
        exit 1
    }
    capture_observation_mappings promoted
    before_open=$(wc -l <"$RG_STATE_DIR/consumer.log")
    assert_tcp_payload "promoted-${RG_RUN_ID}"
    assert_new_direct_flow_since "$before_open" NativeTcp "$relay_session"
fi
echo "PASS: $mode selected encrypted Relay and preserved TCP bytes"
