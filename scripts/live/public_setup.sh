#!/usr/bin/env bash
set -euo pipefail
stage=/root/rustgo-v02-d8e9bec/public-mixed
rm -rf "$stage"; mkdir -p "$stage/linux-keys"
cp /etc/rustgo/server.toml "$stage/server.original.toml"
/opt/rustgo/bin/rustgoc keygen -o "$stage/linux-keys"
linux_pub=$(cat "$stage/linux-keys/device.pub")
cp "$stage/server.original.toml" "$stage/server.test.toml"
cat >>"$stage/server.test.toml" <<EOF
[[clients]]
name = "public-linux-peer"
public_key = "$linux_pub"
enabled = true
[[clients]]
name = "public-windows-peer"
public_key = "ed25519:BhASDJLqfriwEZzLVONxAmPfKWY8X29wxDQSxHB8DlE="
enabled = true
EOF
/opt/rustgo/bin/rustgos check -c "$stage/server.test.toml"
install -o root -g rustgo -m 0640 "$stage/server.test.toml" /etc/rustgo/server.toml
systemctl restart rustgos
python3 -u -c 'import socket,threading
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("127.0.0.1",18800));t.listen()
def a():
 while True:
  c,_=t.accept();d=c.recv(65535);c.sendall(d);c.close()
threading.Thread(target=a,daemon=True).start();u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("127.0.0.1",18801))
while True:
 d,a=u.recvfrom(65535);u.sendto(d,a)' >"$stage/echo.log" 2>&1 & echo $! >"$stage/echo.pid"
cat >"$stage/provider.toml" <<EOF
[client]
name = "public-linux-peer"
server_addr = "8.133.176.172:7443"
server_name = "rustgo-server.local"
certificate_authority_file = "/etc/rustgo/pki/ca.crt"
private_key_file = "$stage/linux-keys/device.key"
heartbeat_interval_secs = 20
[p2p]
enabled = true
prefer_direct = true
direct_timeout_secs = 8
reconnect_timeout_secs = 3
allow_relay_fallback = true
udp_port_range = "18900-18909"
tcp_port_range = "19000-19009"
observation_primary_addr = "8.133.176.172:7443"
observation_alternate_addr = "8.133.176.172:7444"
[[exports]]
name = "tcp-echo"
protocol = "tcp"
local_addr = "127.0.0.1:18800"
allowed_peers = ["public-windows-peer"]
[[exports]]
name = "udp-echo"
protocol = "udp"
local_addr = "127.0.0.1:18801"
allowed_peers = ["public-windows-peer"]
EOF
RUST_LOG=rustgoc=trace /root/rustgo-v02-ca2c690/rustgoc -c "$stage/provider.toml" >"$stage/provider.log" 2>&1 & echo $! >"$stage/provider.pid"
for _ in $(seq 1 150); do grep -q event=registration_ready "$stage/provider.log" && { echo READY; exit 0; }; sleep .1; done
cat "$stage/provider.log"; exit 1
