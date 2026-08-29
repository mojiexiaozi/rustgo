#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/topology.sh"

usage() { echo "usage: sudo bash tests/netns/run.sh {smoke|all|quic|tcp|symmetric}" >&2; exit 2; }
case "${1:-}" in smoke|all|quic|tcp|symmetric) suite=$1 ;; *) usage ;; esac
[ "$#" -eq 1 ] || usage
require_linux_root || { status=$?; exit "$status"; }

run_case() {
    local test=$1 mode=$2
    export RG_RUN_ID="$(date +%s)-$$-${RANDOM}"
    export RG_PREFIX="rgnt-${RG_RUN_ID}"
    export RG_STATE_DIR="/run/${RG_PREFIX}"
    # Re-source after assigning the run identity so every scoped name matches.
    source "$script_dir/topology.sh"
    trap 'status=$?; cleanup_topology; trap - EXIT; "$script_dir/assert_cleanup.sh" || status=1; exit "$status"' EXIT INT TERM
    bash "$script_dir/$test" "$mode"
    cleanup_topology
    trap - EXIT INT TERM
    "$script_dir/assert_cleanup.sh"
}

case "$suite" in
    smoke)
        export RG_RUN_ID="smoke-$$"
        export RG_PREFIX="rgnt-${RG_RUN_ID}"
        export RG_STATE_DIR="/run/${RG_PREFIX}"
        source "$script_dir/topology.sh"
        trap 'cleanup_topology' EXIT INT TERM
        create_topology endpoint-independent
        echo "PASS: topology isolates both private client networks"
        ;;
    quic)
        run_case test_quic.sh endpoint-independent
        run_case test_quic.sh restricted
        run_case test_quic.sh shared-lan
        run_case test_quic.sh ipv6-direct
        ;;
    tcp) run_case test_tcp.sh udp-drop ;;
    symmetric) run_case test_symmetric.sh symmetric ;;
    all)
        run_case test_quic.sh endpoint-independent
        run_case test_quic.sh restricted
        run_case test_quic.sh shared-lan
        run_case test_quic.sh ipv6-direct
        run_case test_tcp.sh udp-drop
        run_case test_symmetric.sh symmetric
        run_case test_symmetric.sh all-direct-drop
        ;;
esac
