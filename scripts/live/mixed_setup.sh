#!/usr/bin/env bash
set -euo pipefail
stage=/root/rustgo-v02-71812f7/mixed-os
rm -rf "$stage"; mkdir -p "$stage/provider/keys"
bin=/root/rustgo-v02-71812f7/source/target/release/rustgoc
"$bin" keygen -o "$stage/provider/keys"
provider_pub=$(cat "$stage/provider/keys/device.pub")
cat >"$stage/server.toml" <<EOF
[server]
bind_addr = "127.0.0.1:17543"
udp_bind_ip = "127.0.0.1"
certificate_file = "/etc/rustgo/pki/server.crt"
private_key_file = "/etc/rustgo/pki/server.key"
heartbeat_timeout_secs = 60
[limits]
max_clients = 8
max_tunnels_per_client = 8
max_tcp_connections_per_tunnel = 16
max_udp_sessions_per_tunnel = 16
max_udp_payload_bytes = 65507
[[clients]]
name = "linux-provider"
public_key = "$provider_pub"
enabled = true
[[clients]]
name = "windows-consumer"
public_key = "ed25519:BhASDJLqfriwEZzLVONxAmPfKWY8X29wxDQSxHB8DlE="
enabled = true
EOF
cat >"$stage/provider.toml" <<EOF
[client]
name = "linux-provider"
server_addr = "127.0.0.1:17543"
server_name = "rustgo-server.local"
certificate_authority_file = "/etc/rustgo/pki/ca.crt"
private_key_file = "$stage/provider/keys/device.key"
heartbeat_interval_secs = 20
[p2p]
enabled = true
prefer_direct = false
direct_timeout_secs = 4
reconnect_timeout_secs = 2
allow_relay_fallback = true
udp_port_range = "17600-17609"
tcp_port_range = "17700-17709"
[[exports]]
name = "tcp-echo"
protocol = "tcp"
local_addr = "127.0.0.1:17800"
allowed_peers = ["windows-consumer"]
[[exports]]
name = "udp-echo"
protocol = "udp"
local_addr = "127.0.0.1:17801"
allowed_peers = ["windows-consumer"]
EOF
/opt/rustgo/bin/rustgos check -c "$stage/server.toml"
python3 -u -c 'import socket,threading
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("127.0.0.1",17800));t.listen()
def a():
 while True:
  c,_=t.accept();d=c.recv(65535);c.sendall(d);c.close()
threading.Thread(target=a,daemon=True).start();u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("127.0.0.1",17801))
while True:
 d,a=u.recvfrom(65535);u.sendto(d,a)' >"$stage/echo.log" 2>&1 & echo $! >"$stage/echo.pid"
/opt/rustgo/bin/rustgos -c "$stage/server.toml" >"$stage/server.log" 2>&1 & echo $! >"$stage/server.pid"
for _ in $(seq 1 100); do grep -q event=server_listening "$stage/server.log" && break; sleep .1; done
"$bin" -c "$stage/provider.toml" >"$stage/provider.log" 2>&1 & echo $! >"$stage/provider.pid"
for _ in $(seq 1 100); do grep -q event=registration_ready "$stage/provider.log" && break; sleep .1; done
echo READY
