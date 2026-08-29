#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/topology.sh"

usage() { echo "usage: sudo bash tests/netns/run.sh {smoke|all|quic|restricted|tcp|symmetric}" >&2; exit 2; }
case "${1:-}" in smoke|all|quic|restricted|tcp|symmetric) suite=$1 ;; *) usage ;; esac
[ "$#" -eq 1 ] || usage
require_linux_root || { status=$?; exit "$status"; }

finalize_case() {
    local original_status=$1 cleanup_status=0 audit_status=0
    trap - EXIT INT TERM
    cleanup_topology || cleanup_status=$?
    RG_AUDIT_PREFIX="$RG_PREFIX" RG_AUDIT_TAG="$RG_TAG" "$script_dir/assert_cleanup.sh" || audit_status=$?
    if [ "$original_status" -ne 0 ]; then return "$original_status"; fi
    if [ "$cleanup_status" -ne 0 ] || [ "$audit_status" -ne 0 ]; then return 1; fi
}

run_case() {
    local test=$1 mode=$2
    export RG_RUN_ID="$(date +%s)-$$-${RANDOM}"
    export RG_PREFIX="rgnt-${RG_RUN_ID}"
    export RG_STATE_DIR="/run/${RG_PREFIX}"
    # Re-source after assigning the run identity so every scoped name matches.
    source "$script_dir/topology.sh"
    trap 'status=$?; finalize_case "$status"; exit $?' EXIT INT TERM
    bash "$script_dir/$test" "$mode"
    finalize_case 0
}

case "$suite" in
    smoke)
        "$script_dir/assert_cleanup.sh" --self-test
        export RG_RUN_ID="smoke-$$"
        export RG_PREFIX="rgnt-${RG_RUN_ID}"
        export RG_STATE_DIR="/run/${RG_PREFIX}"
        source "$script_dir/topology.sh"
        trap 'status=$?; finalize_case "$status"; exit $?' EXIT INT TERM
        create_topology endpoint-independent
        echo "PASS: topology isolates both private client networks"
        finalize_case 0
        ;;
    quic)
        run_case test_quic.sh endpoint-independent
        run_case test_quic.sh restricted
        run_case test_quic.sh shared-lan
        run_case test_quic.sh ipv6-direct
        ;;
    restricted) run_case test_quic.sh restricted ;;
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
