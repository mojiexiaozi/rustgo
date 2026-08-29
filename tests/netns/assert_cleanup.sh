#!/usr/bin/env bash
set -euo pipefail
prefix=${RG_AUDIT_PREFIX:-rgnt-}
failed=0
while IFS= read -r ns; do
    case "$ns" in "$prefix"*) echo "leaked namespace: $ns" >&2; failed=1 ;; esac
done < <(ip netns list | awk '{print $1}')
while IFS= read -r iface; do
    case "$iface" in "$prefix"*) echo "leaked interface: $iface" >&2; failed=1 ;; esac
done < <(ip -o link show | sed -E 's/^[0-9]+: ([^:@]+).*/\1/')
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
[ "$failed" -eq 0 ] || exit 1
echo "PASS: no rustgo-owned namespaces, interfaces, host rules, state, or processes remain"
