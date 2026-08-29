#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = --self-test ]; then
    [ "$#" -eq 1 ] || exit 2
    marker=/run/rgnt-audit-selftest-$$
    mkdir "$marker"
    if RG_AUDIT_PREFIX=rgnt-audit-selftest- "$0" >/dev/null 2>&1; then
        rm -rf -- "$marker"
        echo "cleanup audit self-test failed to reject owned residue" >&2
        exit 1
    fi
    rm -rf -- "$marker"
    RG_AUDIT_PREFIX=rgnt-audit-selftest- "$0" >/dev/null
    echo "PASS: cleanup audit rejects deterministic owned residue"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: assert_cleanup.sh [--self-test]" >&2; exit 2; }
prefix=${RG_AUDIT_PREFIX:-rgnt-}
tag=${RG_AUDIT_TAG:-}
failed=0
while IFS= read -r ns; do
    case "$ns" in "$prefix"*) echo "leaked namespace: $ns" >&2; failed=1 ;; esac
done < <(ip netns list | awk '{print $1}')
while IFS= read -r iface; do
    case "$iface" in "$prefix"*) echo "leaked interface: $iface" >&2; failed=1 ;; esac
done < <(ip -o link show | sed -E 's/^[0-9]+: ([^:@]+).*/\1/')
if [ -n "$tag" ]; then
    while IFS= read -r iface; do
        case "$iface" in rg?"$tag") echo "leaked scoped interface: $iface" >&2; failed=1 ;; esac
    done < <(ip -o link show | sed -E 's/^[0-9]+: ([^:@]+).*/\1/')
fi
if command -v nft >/dev/null && nft list tables 2>/dev/null | grep -Fq rustgo_netns; then
    echo "leaked host firewall table: rustgo_netns" >&2
    failed=1
fi
for state in /run/${prefix}*; do
    [ ! -e "$state" ] || { echo "leaked state directory: $state" >&2; failed=1; }
done
if pgrep -af -- "$prefix" 2>/dev/null | grep -Ev 'assert_cleanup|pgrep' >&2; then
    echo "leaked rustgo netns process" >&2
    failed=1
fi
[ -z "$tag" ] || ! ss -H -lntup 2>/dev/null | grep -Fq -- "$tag" || {
    echo "leaked scoped listening socket: $tag" >&2
    failed=1
}
[ "$failed" -eq 0 ] || exit 1
echo "PASS: no rustgo-owned namespaces, interfaces, host rules, state, or processes remain"
