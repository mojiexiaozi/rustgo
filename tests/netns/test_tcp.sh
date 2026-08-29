#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/topology.sh"
create_topology udp-drop
create_credentials_and_configs
start_stack
payload="tcp-native-${RG_RUN_ID}"
assert_tcp_payload "$payload"
assert_selected_path NativeTcp
echo "PASS: UDP drop selected NativeTcp and preserved TCP bytes"
