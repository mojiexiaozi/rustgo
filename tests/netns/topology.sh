#!/usr/bin/env bash
# Disposable Linux network-namespace topology for Rustgo P2P acceptance tests.
# shellcheck shell=bash

set -euo pipefail

RG_PREFIX=${RG_PREFIX:-rgnt-${RG_RUN_ID:-$$}}
RG_STATE_DIR=${RG_STATE_DIR:-/run/${RG_PREFIX}}
RG_ROOT=${RG_ROOT:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}
RG_BIN_DIR=${RG_BIN_DIR:-$RG_ROOT/target/release}
RG_SERVER_NS=${RG_PREFIX}-server
RG_NAT_A_NS=${RG_PREFIX}-nata
RG_NAT_B_NS=${RG_PREFIX}-natb
RG_CLIENT_A_NS=${RG_PREFIX}-provider
RG_CLIENT_B_NS=${RG_PREFIX}-consumer
RG_TAG=${RG_RUN_ID:-$$}
RG_TAG=${RG_TAG//[^a-zA-Z0-9]/}
RG_TAG=${RG_TAG: -8}
RG_BRIDGE=rgb${RG_TAG}
RG_SERVER_IP=10.231.0.2
RG_NAT_A_IP=10.231.0.11
RG_NAT_B_IP=10.231.0.12
RG_PROVIDER_IP=10.231.1.2
RG_CONSUMER_IP=10.231.2.2
RG_PROVIDER_V6=fd23:1::2
RG_CONSUMER_V6=fd23:2::2
RG_CONTROL_PORT=7443
RG_OBSERVE_ALT_PORT=7444
RG_UDP_FIRST=41000
RG_UDP_LAST=41003
RG_TCP_FIRST=42000
RG_TCP_LAST=42003
RG_TCP_EXPORT_PORT=18080
RG_UDP_EXPORT_PORT=18081
RG_TCP_FORWARD_PORT=19080
RG_UDP_FORWARD_PORT=19081

require_linux_root() {
    [ "$(uname -s)" = Linux ] || { echo "SKIP: Linux ip-netns is required" >&2; return 77; }
    [ "${EUID:-$(id -u)}" -eq 0 ] || { echo "SKIP: root is required for disposable network namespaces" >&2; return 77; }
    for command in ip python3 timeout openssl conntrack ping pgrep awk sed grep sysctl ss; do
        command -v "$command" >/dev/null || { echo "SKIP: required command is missing: $command" >&2; return 77; }
    done
    if command -v nft >/dev/null; then
        RG_FIREWALL=nft
    elif command -v iptables >/dev/null; then
        RG_FIREWALL=iptables
    else
        echo "SKIP: nftables or iptables is required" >&2
        return 77
    fi
    export RG_FIREWALL
    [ -x "$RG_BIN_DIR/rustgos" ] && [ -x "$RG_BIN_DIR/rustgoc" ] || {
        echo "SKIP: release rustgos/rustgoc prerequisites are missing in $RG_BIN_DIR" >&2
        return 77
    }
    local capcheck=${RG_PREFIX}-capcheck capability_ok=1
    ip netns del "$capcheck" 2>/dev/null || true
    ip netns add "$capcheck" || capability_ok=0
    if [ "$capability_ok" -eq 1 ]; then
        ip netns exec "$capcheck" ip link set lo up || capability_ok=0
        if [ "$RG_FIREWALL" = nft ]; then
            ip netns exec "$capcheck" nft list ruleset >/dev/null || capability_ok=0
        else
            ip netns exec "$capcheck" iptables -L >/dev/null || capability_ok=0
        fi
    fi
    ip netns del "$capcheck" 2>/dev/null || capability_ok=0
    if [ "$capability_ok" -ne 1 ]; then
        ip netns del "$capcheck" 2>/dev/null || true
        echo "SKIP: kernel namespace/firewall capabilities are unavailable" >&2
        return 77
    fi
}

record_pid() { printf '%s\n' "$1" >>"$RG_STATE_DIR/pids"; }

start_in_ns() {
    local namespace=$1 name=$2
    shift 2
    ip netns exec "$namespace" "$@" >"$RG_STATE_DIR/$name.log" 2>&1 &
    local pid=$!
    record_pid "$pid"
    printf '%s' "$pid"
}

wait_log() {
    local file=$1 pattern=$2 deadline=$((SECONDS + ${3:-20}))
    until grep -Fq -- "$pattern" "$file" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || {
            echo "FAIL: timeout waiting for '$pattern' in $file" >&2
            sed -n '1,240p' "$file" >&2 || true
            return 1
        }
        sleep 0.1
    done
}

cleanup_topology() {
    set +e
    if [ -f "$RG_STATE_DIR/pids" ]; then
        while IFS= read -r pid; do
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -Fq -- "$RG_PREFIX"; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done <"$RG_STATE_DIR/pids"
        sleep 0.2
        while IFS= read -r pid; do
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -Fq -- "$RG_PREFIX"; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
        done <"$RG_STATE_DIR/pids"
    fi
    for ns in "$RG_CLIENT_A_NS" "$RG_CLIENT_B_NS" "$RG_NAT_A_NS" "$RG_NAT_B_NS" "$RG_SERVER_NS"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$RG_BRIDGE" 2>/dev/null || true
    rm -rf -- "$RG_STATE_DIR"
    set -e
}

create_link() {
    local host_if=$1 namespace=$2 peer_if=$3
    ip link add "$host_if" type veth peer name "$peer_if"
    ip link set "$peer_if" netns "$namespace"
    ip link set "$host_if" master "$RG_BRIDGE"
    ip link set "$host_if" up
    ip -n "$namespace" link set "$peer_if" up
}

create_topology() {
    local mode=$1
    mkdir -p -- "$RG_STATE_DIR"
    : >"$RG_STATE_DIR/pids"
    printf '%s\n' "$mode" >"$RG_STATE_DIR/mode"
    for ns in "$RG_SERVER_NS" "$RG_NAT_A_NS" "$RG_NAT_B_NS" "$RG_CLIENT_A_NS" "$RG_CLIENT_B_NS"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    ip link add "$RG_BRIDGE" type bridge
    ip link set "$RG_BRIDGE" up
    create_link "rgs${RG_TAG}" "$RG_SERVER_NS" ext0
    create_link "rga${RG_TAG}" "$RG_NAT_A_NS" ext0
    create_link "rgg${RG_TAG}" "$RG_NAT_B_NS" ext0
    ip -n "$RG_SERVER_NS" addr add "$RG_SERVER_IP/24" dev ext0
    ip -n "$RG_NAT_A_NS" addr add "$RG_NAT_A_IP/24" dev ext0
    ip -n "$RG_NAT_B_NS" addr add "$RG_NAT_B_IP/24" dev ext0
    if [ "$mode" = shared-lan ]; then
        create_link "rpa${RG_TAG}" "$RG_CLIENT_A_NS" direct0
        create_link "rpc${RG_TAG}" "$RG_CLIENT_B_NS" direct0
        ip -n "$RG_CLIENT_A_NS" addr add 10.231.0.21/24 dev direct0
        ip -n "$RG_CLIENT_B_NS" addr add 10.231.0.22/24 dev direct0
    fi
    if [ "$mode" = ipv6-direct ]; then
        ip -n "$RG_SERVER_NS" addr add fd23:0::2/64 dev ext0 nodad
        ip -n "$RG_NAT_A_NS" addr add fd23:0::11/64 dev ext0 nodad
        ip -n "$RG_NAT_B_NS" addr add fd23:0::12/64 dev ext0 nodad
    fi

    ip link add "rai${RG_TAG}" type veth peer name lan0
    ip link set "rai${RG_TAG}" netns "$RG_NAT_A_NS"
    ip link set lan0 netns "$RG_CLIENT_A_NS"
    ip -n "$RG_NAT_A_NS" link set "rai${RG_TAG}" name int0
    ip -n "$RG_NAT_A_NS" addr add 10.231.1.1/24 dev int0
    ip -n "$RG_NAT_A_NS" link set int0 up
    ip -n "$RG_CLIENT_A_NS" addr add "$RG_PROVIDER_IP/24" dev lan0
    ip -n "$RG_CLIENT_A_NS" link set lan0 up
    ip -n "$RG_CLIENT_A_NS" route add default via 10.231.1.1
    if [ "$mode" = ipv6-direct ]; then
        ip -n "$RG_NAT_A_NS" addr add fd23:1::1/64 dev int0 nodad
        ip -n "$RG_CLIENT_A_NS" addr add "$RG_PROVIDER_V6/64" dev lan0 nodad
        ip -n "$RG_CLIENT_A_NS" route add default via fd23:1::1
    fi

    ip link add "rbi${RG_TAG}" type veth peer name lan0
    ip link set "rbi${RG_TAG}" netns "$RG_NAT_B_NS"
    ip link set lan0 netns "$RG_CLIENT_B_NS"
    ip -n "$RG_NAT_B_NS" link set "rbi${RG_TAG}" name int0
    ip -n "$RG_NAT_B_NS" addr add 10.231.2.1/24 dev int0
    ip -n "$RG_NAT_B_NS" link set int0 up
    ip -n "$RG_CLIENT_B_NS" addr add "$RG_CONSUMER_IP/24" dev lan0
    ip -n "$RG_CLIENT_B_NS" link set lan0 up
    ip -n "$RG_CLIENT_B_NS" route add default via 10.231.2.1
    if [ "$mode" = ipv6-direct ]; then
        ip -n "$RG_NAT_B_NS" addr add fd23:2::1/64 dev int0 nodad
        ip -n "$RG_CLIENT_B_NS" addr add "$RG_CONSUMER_V6/64" dev lan0 nodad
        ip -n "$RG_CLIENT_B_NS" route add default via fd23:2::1
        ip netns exec "$RG_NAT_A_NS" sysctl -qw net.ipv6.conf.all.forwarding=1
        ip netns exec "$RG_NAT_B_NS" sysctl -qw net.ipv6.conf.all.forwarding=1
        ip -n "$RG_NAT_A_NS" -6 route add fd23:2::/64 via fd23:0::12
        ip -n "$RG_NAT_B_NS" -6 route add fd23:1::/64 via fd23:0::11
        ip -n "$RG_SERVER_NS" -6 route add fd23:1::/64 via fd23:0::11
        ip -n "$RG_SERVER_NS" -6 route add fd23:2::/64 via fd23:0::12
    fi
    ip netns exec "$RG_NAT_A_NS" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$RG_NAT_B_NS" sysctl -qw net.ipv4.ip_forward=1

    configure_nat "$RG_NAT_A_NS" "$RG_NAT_A_IP" "$RG_PROVIDER_IP" "$mode"
    configure_nat "$RG_NAT_B_NS" "$RG_NAT_B_IP" "$RG_CONSUMER_IP" "$mode"

    # NAT isolation is real: private addresses are not routed across the external bridge.
    if ip netns exec "$RG_CLIENT_A_NS" ping -c1 -W1 "$RG_CONSUMER_IP" >/dev/null 2>&1; then
        echo "FAIL: direct private client addressing unexpectedly reachable" >&2
        return 1
    fi
}

configure_nat() {
    local namespace=$1 external_ip=$2 internal_ip=$3 mode=$4
    if [ "$RG_FIREWALL" = nft ]; then
        ip netns exec "$namespace" nft -f - <<EOF
table ip rustgo_netns {
 chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; iifname "int0" oifname "ext0" accept; }
 chain prerouting { type nat hook prerouting priority -100; }
 chain postrouting { type nat hook postrouting priority 100; }
}
EOF
        if [ "$mode" = symmetric ]; then
            ip netns exec "$namespace" nft add rule ip rustgo_netns postrouting oifname ext0 ip daddr "$RG_SERVER_IP" udp dport "$RG_CONTROL_PORT" snat to "$external_ip:43043"
            ip netns exec "$namespace" nft add rule ip rustgo_netns postrouting oifname ext0 ip daddr "$RG_SERVER_IP" udp dport "$RG_OBSERVE_ALT_PORT" snat to "$external_ip:43044"
            ip netns exec "$namespace" nft add rule ip rustgo_netns postrouting oifname ext0 masquerade random,fully-random
        else
            ip netns exec "$namespace" nft add rule ip rustgo_netns postrouting oifname ext0 snat to "$external_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = restricted ]; then
            ip netns exec "$namespace" nft add rule ip rustgo_netns prerouting iifname ext0 udp dport "$RG_UDP_FIRST-$RG_UDP_LAST" dnat to "$internal_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = udp-drop ]; then
            ip netns exec "$namespace" nft add rule ip rustgo_netns prerouting iifname ext0 tcp dport "$RG_TCP_FIRST-$RG_TCP_LAST" dnat to "$internal_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ]; then
            ip netns exec "$namespace" nft add rule ip rustgo_netns forward iifname ext0 oifname int0 udp dport "$RG_UDP_FIRST-$RG_UDP_LAST" accept
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = udp-drop ]; then
            ip netns exec "$namespace" nft add rule ip rustgo_netns forward iifname ext0 oifname int0 tcp dport "$RG_TCP_FIRST-$RG_TCP_LAST" accept
        fi
    else
        ip netns exec "$namespace" iptables -P FORWARD DROP
        ip netns exec "$namespace" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ip netns exec "$namespace" iptables -A FORWARD -i int0 -o ext0 -j ACCEPT
        if [ "$mode" = symmetric ]; then
            ip netns exec "$namespace" iptables -t nat -A POSTROUTING -o ext0 -p udp -d "$RG_SERVER_IP" --dport "$RG_CONTROL_PORT" -j SNAT --to-source "$external_ip:43043"
            ip netns exec "$namespace" iptables -t nat -A POSTROUTING -o ext0 -p udp -d "$RG_SERVER_IP" --dport "$RG_OBSERVE_ALT_PORT" -j SNAT --to-source "$external_ip:43044"
            ip netns exec "$namespace" iptables -t nat -A POSTROUTING -o ext0 -j MASQUERADE --random-fully
        else
            ip netns exec "$namespace" iptables -t nat -A POSTROUTING -o ext0 -j SNAT --to-source "$external_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = restricted ]; then
            ip netns exec "$namespace" iptables -t nat -A PREROUTING -i ext0 -p udp --dport "$RG_UDP_FIRST:$RG_UDP_LAST" -j DNAT --to-destination "$internal_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = udp-drop ]; then
            ip netns exec "$namespace" iptables -t nat -A PREROUTING -i ext0 -p tcp --dport "$RG_TCP_FIRST:$RG_TCP_LAST" -j DNAT --to-destination "$internal_ip"
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ]; then
            ip netns exec "$namespace" iptables -A FORWARD -i ext0 -o int0 -p udp --dport "$RG_UDP_FIRST:$RG_UDP_LAST" -j ACCEPT
        fi
        if [ "$mode" = endpoint-independent ] || [ "$mode" = shared-lan ] || [ "$mode" = udp-drop ]; then
            ip netns exec "$namespace" iptables -A FORWARD -i ext0 -o int0 -p tcp --dport "$RG_TCP_FIRST:$RG_TCP_LAST" -j ACCEPT
        fi
    fi
    if [ "$mode" = udp-drop ] || [ "$mode" = all-direct-drop ]; then
        firewall_drop_range "$namespace" udp "$RG_UDP_FIRST:$RG_UDP_LAST"
    fi
    if [ "$mode" = all-direct-drop ] || [ "$mode" = symmetric ]; then
        firewall_drop_range "$namespace" tcp "$RG_TCP_FIRST:$RG_TCP_LAST"
    fi
}

firewall_drop_range() {
    local namespace=$1 protocol=$2 range=$3
    if [ "$RG_FIREWALL" = nft ]; then
        if [ "$protocol" = udp ]; then
            ip netns exec "$namespace" nft insert rule ip rustgo_netns forward ip saddr != "$RG_SERVER_IP" udp dport "${range/:/-}" counter drop
        else
            ip netns exec "$namespace" nft insert rule ip rustgo_netns forward "$protocol" dport "${range/:/-}" counter drop
        fi
    else
        if [ "$protocol" = udp ]; then
            ip netns exec "$namespace" iptables -I FORWARD 1 ! -s "$RG_SERVER_IP" -p udp --dport "$range" -j DROP
        else
            ip netns exec "$namespace" iptables -I FORWARD 1 -p "$protocol" --dport "$range" -j DROP
        fi
    fi
}

allow_direct_after_relay() {
    local namespace
    for namespace in "$RG_NAT_A_NS" "$RG_NAT_B_NS"; do
        if [ "$RG_FIREWALL" = nft ]; then
            # Drop rules were inserted after the two base accept rules. Rebuild the
            # namespace-local filter chain without changing host policy.
            ip netns exec "$namespace" nft flush chain ip rustgo_netns forward
            ip netns exec "$namespace" nft add rule ip rustgo_netns forward ct state established,related accept
            ip netns exec "$namespace" nft add rule ip rustgo_netns forward iifname int0 oifname ext0 accept
        else
            ip netns exec "$namespace" iptables -D FORWARD 1 2>/dev/null || true
            ip netns exec "$namespace" iptables -D FORWARD 1 2>/dev/null || true
        fi
    done
}

create_credentials_and_configs() {
    mkdir -p "$RG_STATE_DIR"/{provider,consumer,server/authorized,pki}
    "$RG_BIN_DIR/rustgoc" keygen -o "$RG_STATE_DIR/provider/keys"
    "$RG_BIN_DIR/rustgoc" keygen -o "$RG_STATE_DIR/consumer/keys"
    cp "$RG_STATE_DIR/provider/keys/device.pub" "$RG_STATE_DIR/server/authorized/provider.pub"
    cp "$RG_STATE_DIR/consumer/keys/device.pub" "$RG_STATE_DIR/server/authorized/consumer.pub"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=rustgo-netns-ca \
        -keyout "$RG_STATE_DIR/pki/ca.key" -out "$RG_STATE_DIR/pki/ca.crt" >/dev/null 2>&1
    local mode server_ip server_socket
    mode=$(<"$RG_STATE_DIR/mode")
    if [ "$mode" = ipv6-direct ]; then
        server_ip=fd23:0::2
        server_socket="[fd23:0::2]"
    else
        server_ip=$RG_SERVER_IP
        server_socket=$RG_SERVER_IP
    fi
    openssl req -newkey rsa:2048 -nodes -subj /CN=rustgo-netns-server \
        -addext "subjectAltName=IP:$server_ip" -keyout "$RG_STATE_DIR/pki/server.key" \
        -out "$RG_STATE_DIR/pki/server.csr" >/dev/null 2>&1
    printf 'subjectAltName=IP:%s\n' "$server_ip" >"$RG_STATE_DIR/pki/ext.cnf"
    openssl x509 -req -days 1 -in "$RG_STATE_DIR/pki/server.csr" \
        -CA "$RG_STATE_DIR/pki/ca.crt" -CAkey "$RG_STATE_DIR/pki/ca.key" -CAcreateserial \
        -extfile "$RG_STATE_DIR/pki/ext.cnf" -out "$RG_STATE_DIR/pki/server.crt" >/dev/null 2>&1
    local provider_key consumer_key
    provider_key=$(tr -d '\r\n' <"$RG_STATE_DIR/provider/keys/device.pub")
    consumer_key=$(tr -d '\r\n' <"$RG_STATE_DIR/consumer/keys/device.pub")
    cat >"$RG_STATE_DIR/server/server.toml" <<EOF
[server]
bind_addr = "$server_socket:$RG_CONTROL_PORT"
p2p_observation_bind = "$server_socket:$RG_CONTROL_PORT"
p2p_observation_alternate_bind = "$server_socket:$RG_OBSERVE_ALT_PORT"
udp_bind_ip = "$server_ip"
certificate_file = "$RG_STATE_DIR/pki/server.crt"
private_key_file = "$RG_STATE_DIR/pki/server.key"
heartbeat_timeout_secs = 20
[limits]
max_clients = 8
max_tunnels_per_client = 8
max_tcp_connections_per_tunnel = 16
max_udp_sessions_per_tunnel = 32
max_udp_payload_bytes = 65507
[[clients]]
name = "provider"
public_key = "$provider_key"
enabled = true
[[clients]]
name = "consumer"
public_key = "$consumer_key"
enabled = true
EOF
    write_client_config provider "$RG_STATE_DIR/provider/keys/device.key" provider "$server_socket" "$server_ip"
    write_client_config consumer "$RG_STATE_DIR/consumer/keys/device.key" consumer "$server_socket" "$server_ip"
}

write_client_config() {
    local name=$1 key=$2 role=$3 server_socket=$4 server_name=$5
    cat >"$RG_STATE_DIR/$name/client.toml" <<EOF
[client]
name = "$name"
server_addr = "$server_socket:$RG_CONTROL_PORT"
server_name = "$server_name"
certificate_authority_file = "$RG_STATE_DIR/pki/ca.crt"
private_key_file = "$key"
heartbeat_interval_secs = 2
[p2p]
enabled = true
prefer_direct = true
direct_timeout_secs = 4
reconnect_timeout_secs = 2
allow_relay_fallback = true
udp_port_range = "$RG_UDP_FIRST-$RG_UDP_LAST"
tcp_port_range = "$RG_TCP_FIRST-$RG_TCP_LAST"
observation_primary_addr = "$server_socket:$RG_CONTROL_PORT"
observation_alternate_addr = "$server_socket:$RG_OBSERVE_ALT_PORT"
EOF
    if [ "$role" = provider ]; then
        cat >>"$RG_STATE_DIR/$name/client.toml" <<EOF
[[exports]]
name = "tcp-echo"
protocol = "tcp"
local_addr = "127.0.0.1:$RG_TCP_EXPORT_PORT"
allowed_peers = ["consumer"]
[[exports]]
name = "udp-echo"
protocol = "udp"
local_addr = "127.0.0.1:$RG_UDP_EXPORT_PORT"
allowed_peers = ["consumer"]
EOF
    else
        cat >>"$RG_STATE_DIR/$name/client.toml" <<EOF
[[forwards]]
name = "tcp-echo"
peer = "provider"
export = "tcp-echo"
listen_addr = "127.0.0.1:$RG_TCP_FORWARD_PORT"
[[forwards]]
name = "udp-echo"
peer = "provider"
export = "udp-echo"
listen_addr = "127.0.0.1:$RG_UDP_FORWARD_PORT"
EOF
    fi
}

start_stack() {
    start_in_ns "$RG_SERVER_NS" server "$RG_BIN_DIR/rustgos" -c "$RG_STATE_DIR/server/server.toml" >/dev/null
    wait_log "$RG_STATE_DIR/server.log" event=server_listening
    start_in_ns "$RG_CLIENT_A_NS" tcp-echo python3 -u -c 'import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",18080));s.listen()
while True:
 c,_=s.accept(); d=c.recv(65536); c.sendall(d); c.close()' "$RG_PREFIX" >/dev/null
    start_in_ns "$RG_CLIENT_A_NS" udp-echo python3 -u -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",18081))
while True:
 d,a=s.recvfrom(65535);s.sendto(d,a)' "$RG_PREFIX" >/dev/null
    start_in_ns "$RG_CLIENT_A_NS" provider "$RG_BIN_DIR/rustgoc" -c "$RG_STATE_DIR/provider/client.toml" >/dev/null
    wait_log "$RG_STATE_DIR/provider.log" event=registration_ready
    start_in_ns "$RG_CLIENT_B_NS" consumer "$RG_BIN_DIR/rustgoc" -c "$RG_STATE_DIR/consumer/client.toml" >/dev/null
    wait_log "$RG_STATE_DIR/consumer.log" event=registration_ready
    wait_log "$RG_STATE_DIR/consumer.log" event=peer_forwards_ready
}

assert_tcp_payload() {
    local payload=$1
    ip netns exec "$RG_CLIENT_B_NS" timeout 15 python3 -c 'import socket,sys
p=sys.argv[1].encode(); s=socket.create_connection(("127.0.0.1",19080),10); s.sendall(p); d=s.recv(65536); assert d==p,(d,p)' "$payload"
}

assert_udp_payload() {
    local payload=$1
    ip netns exec "$RG_CLIENT_B_NS" timeout 15 python3 -c 'import socket,sys
p=sys.argv[1].encode(); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10); s.sendto(p,("127.0.0.1",19081)); d,_=s.recvfrom(65535); assert d==p,(d,p)' "$payload"
}

assert_selected_path() {
    local expected=$1
    wait_log "$RG_STATE_DIR/consumer.log" "authoritative peer path selected path=$expected" 20
    grep -F "authoritative peer path selected" "$RG_STATE_DIR/consumer.log" | grep -Fq "path=$expected"
}

capture_observation_mappings() {
    local label=$1 namespace internal_ip external_ip output=$RG_STATE_DIR/observation-$label.tsv
    : >"$output"
    for side in provider consumer; do
        if [ "$side" = provider ]; then
            namespace=$RG_NAT_A_NS; internal_ip=$RG_PROVIDER_IP; external_ip=$RG_NAT_A_IP
        else
            namespace=$RG_NAT_B_NS; internal_ip=$RG_CONSUMER_IP; external_ip=$RG_NAT_B_IP
        fi
        ip netns exec "$namespace" conntrack -L -p udp 2>/dev/null |
            python3 -c 'import re,sys
side,internal,external,server=sys.argv[1:]
found={}
for line in sys.stdin:
 fields=re.findall(r"(?:src|dst|sport|dport)=([^ ]+)",line)
 if len(fields) < 8: continue
 osrc,odst,osport,odport,rsrc,rdst,rsport,rdport=fields[:8]
 if osrc==internal and odst==server and odport in {"7443","7444"} and rdst==external:
  found[odport]=rdport
for endpoint in ("7443","7444"):
 if endpoint not in found: raise SystemExit(f"missing authenticated observation mapping for {side}/{endpoint}")
 print(f"{side}\t{endpoint}\t{found[endpoint]}")' "$side" "$internal_ip" "$external_ip" "$RG_SERVER_IP" >>"$output"
    done
    [ "$(wc -l <"$output")" -eq 4 ] || { echo "FAIL: incomplete observation mapping evidence" >&2; return 1; }
}

assert_changed_observation_mappings() {
    local file=$1 side primary alternate
    for side in provider consumer; do
        primary=$(awk -v s="$side" '$1==s && $2==7443 {print $3}' "$file")
        alternate=$(awk -v s="$side" '$1==s && $2==7444 {print $3}' "$file")
        [ -n "$primary" ] && [ -n "$alternate" ] && [ "$primary" != "$alternate" ] || {
            echo "FAIL: $side observation mappings did not change across 7443/7444: $primary/$alternate" >&2
            return 1
        }
    done
}

direct_drop_count() {
    local namespace=$1 protocol=$2 range=$3 evidence
    evidence=$RG_STATE_DIR/direct-drop-${namespace##*-}-${protocol}.txt
    if [ "$RG_FIREWALL" = nft ]; then
        ip netns exec "$namespace" nft list chain ip rustgo_netns forward >"$evidence"
        awk -v p="$protocol" -v r="${range/:/-}" '
            index($0,p" dport "r) && match($0,/packets [0-9]+/) {
                value=substr($0,RSTART+8,RLENGTH-8); total+=value
            } END { print total+0 }' "$evidence"
    else
        ip netns exec "$namespace" iptables -L FORWARD -v -n -x >"$evidence"
        awk -v p="$protocol" -v r="$range" '$4==p && index($0,"dpts:"r) {total+=$1} END {print total+0}' "$evidence"
    fi
}

assert_direct_drop_evidence() {
    local namespace=$1 protocol=$2 range=$3 baseline=${4:-0} current
    current=$(direct_drop_count "$namespace" "$protocol" "$range")
    case "$baseline:$current" in *[!0-9:]*) echo "FAIL: invalid scoped drop counter evidence" >&2; return 1 ;; esac
    [ "$current" -gt "$baseline" ] || {
        echo "FAIL: scoped rustgo_netns/forward $protocol $range counter did not increase in $namespace ($baseline -> $current)" >&2
        return 1
    }
}

assert_restricted_filtering() {
    local marker="restricted-${RG_RUN_ID}"
    start_in_ns "$RG_SERVER_NS" restricted-probe python3 -u -c 'import socket,sys,time
marker=sys.argv[1].encode(); primary=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); primary.bind(("10.231.0.2",17600))
alternate=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); alternate.bind(("10.231.0.2",17601))
print("READY",flush=True)
d,a=primary.recvfrom(1024); assert d==marker; primary.sendto(d,a); time.sleep(.1); alternate.sendto(b"unsolicited",a)' "$marker" "$RG_PREFIX" >/dev/null
    wait_log "$RG_STATE_DIR/restricted-probe.log" READY
    ip netns exec "$RG_CLIENT_B_NS" timeout 8 python3 -c 'import socket,sys
marker=sys.argv[1].encode(); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.231.2.2",40999)); s.settimeout(3)
s.sendto(marker,("10.231.0.2",17600)); assert s.recvfrom(1024)[0]==marker
try: s.recvfrom(1024)
except socket.timeout: raise SystemExit(0)
raise SystemExit("address/port-dependent filter admitted an unsolicited alternate-source packet")' "$marker"
}

assert_new_direct_flow_since() {
    local start_line=$1 expected_path=$2 relay_session=$3 evidence=$RG_STATE_DIR/promoted-flow.log deadline=$((SECONDS + 20))
    while [ "$SECONDS" -lt "$deadline" ]; do
        tail -n "+$((start_line + 1))" "$RG_STATE_DIR/consumer.log" |
            grep -F "peer service flow" | grep -F 'lifecycle="selected"' | grep -F "path=$expected_path" >"$evidence" || true
        if [ -s "$evidence" ]; then
            local line session open generation
            line=$(tail -n 1 "$evidence")
            session=$(sed -n 's/.*session_id=\([^ ]*\).*/\1/p' <<<"$line")
            open=$(sed -n 's/.*open_id=\([^ ]*\).*/\1/p' <<<"$line")
            generation=$(sed -n 's/.*generation=\([^ ]*\).*/\1/p' <<<"$line")
            [ -n "$session" ] && [ -n "$open" ] && [ -n "$generation" ] && [ "$session" != "$relay_session" ] || {
                echo "FAIL: promoted flow lacks distinct structured session/open/generation evidence" >&2
                return 1
            }
            tail -n "+$((start_line + 1))" "$RG_STATE_DIR/consumer.log" |
                grep -F "session_id=$session" | grep -F "open_id=$open" | grep -Fq 'lifecycle="io_start"' || continue
            printf '%s\n' "$line" >"$evidence"
            return 0
        fi
        sleep 0.1
    done
    echo "FAIL: post-promotion service open did not select $expected_path" >&2
    return 1
}

export RG_PREFIX RG_STATE_DIR RG_ROOT RG_BIN_DIR RG_SERVER_NS RG_NAT_A_NS RG_NAT_B_NS
export RG_CLIENT_A_NS RG_CLIENT_B_NS RG_BRIDGE RG_SERVER_IP RG_PROVIDER_IP RG_CONSUMER_IP
export RG_CONTROL_PORT RG_OBSERVE_ALT_PORT RG_UDP_FIRST RG_UDP_LAST RG_TCP_FIRST RG_TCP_LAST
export RG_TCP_FORWARD_PORT RG_UDP_FORWARD_PORT
export RG_TAG
