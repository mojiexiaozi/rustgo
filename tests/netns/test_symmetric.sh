#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/topology.sh"
mode=${1:-symmetric}
create_topology "$mode"
create_credentials_and_configs
start_stack
payload="relay-${mode}-${RG_RUN_ID}"
assert_tcp_payload "$payload"
assert_selected_path Relay
if [ "$mode" = all-direct-drop ]; then
    allow_direct_after_relay
    wait_log "$RG_STATE_DIR/consumer.log" "fresh direct path promoted" 25
    assert_tcp_payload "promoted-${RG_RUN_ID}"
    grep -Fq "generation=" "$RG_STATE_DIR/consumer.log"
fi
echo "PASS: $mode selected encrypted Relay and preserved TCP bytes"
