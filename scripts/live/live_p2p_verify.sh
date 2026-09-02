#!/usr/bin/env bash
set -euo pipefail
stage=/root/rustgo-v02-71812f7/live-p2p
rm -rf "$stage"
mkdir -p "$stage/provider" "$stage/consumer"
server_backup="$stage/server.final.toml"
cp /etc/rustgo/server.toml "$server_backup"
pids=""
restore() {
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  wait $pids 2>/dev/null || true
  install -o root -g rustgo -m 0640 "$server_backup" /etc/rustgo/server.toml
  systemctl restart rustgos
}
trap restore EXIT
bin=/root/rustgo-v02-71812f7/source/target/release/rustgoc
"$bin" keygen -o "$stage/provider/keys"
"$bin" keygen -o "$stage/consumer/keys"
cp "$server_backup" "$stage/server.test.toml"
cat >>"$stage/server.test.toml" <<EOF

[[clients]]
name = "v02-provider"
public_key = "$(cat "$stage/provider/keys/device.pub")"
enabled = true

[[clients]]
name = "v02-consumer"
public_key = "$(cat "$stage/consumer/keys/device.pub")"
enabled = true
EOF
/opt/rustgo/bin/rustgos check -c "$stage/server.test.toml"
install -o root -g rustgo -m 0640 "$stage/server.test.toml" /etc/rustgo/server.toml
systemctl restart rustgos
systemctl is-active --quiet rustgos
python3 -u -c 'import socket,threading
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("127.0.0.1",28200));t.listen()
def a():
 while True:
  c,_=t.accept();d=c.recv(65535);c.sendall(d);c.close()
threading.Thread(target=a,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("127.0.0.1",28201))
while True:
 d,a=u.recvfrom(65535);u.sendto(d,a)' >"$stage/echo.log" 2>&1 & pids="$pids $!"
write_configs() {
  local direct=$1
  cat >"$stage/provider/client.toml" <<EOF
[client]
name = "v02-provider"
server_addr = "127.0.0.1:7443"
server_name = "rustgo-server.local"
certificate_authority_file = "/etc/rustgo/pki/ca.crt"
private_key_file = "$stage/provider/keys/device.key"
heartbeat_interval_secs = 20
[p2p]
enabled = true
prefer_direct = $direct
direct_timeout_secs = 4
reconnect_timeout_secs = 2
allow_relay_fallback = true
udp_port_range = "28300-28309"
tcp_port_range = "28400-28409"
observation_primary_addr = "127.0.0.1:7443"
observation_alternate_addr = "127.0.0.1:7444"
[[exports]]
name = "tcp-echo"
protocol = "tcp"
local_addr = "127.0.0.1:28200"
allowed_peers = ["v02-consumer"]
[[exports]]
name = "udp-echo"
protocol = "udp"
local_addr = "127.0.0.1:28201"
allowed_peers = ["v02-consumer"]
EOF
  cat >"$stage/consumer/client.toml" <<EOF
[client]
name = "v02-consumer"
server_addr = "127.0.0.1:7443"
server_name = "rustgo-server.local"
certificate_authority_file = "/etc/rustgo/pki/ca.crt"
private_key_file = "$stage/consumer/keys/device.key"
heartbeat_interval_secs = 20
[p2p]
enabled = true
prefer_direct = $direct
direct_timeout_secs = 4
reconnect_timeout_secs = 2
allow_relay_fallback = true
udp_port_range = "28500-28509"
tcp_port_range = "28600-28609"
observation_primary_addr = "127.0.0.1:7443"
observation_alternate_addr = "127.0.0.1:7444"
[[forwards]]
name = "tcp-forward"
peer = "v02-provider"
export = "tcp-echo"
listen_addr = "127.0.0.1:28700"
[[forwards]]
name = "udp-forward"
peer = "v02-provider"
export = "udp-echo"
listen_addr = "127.0.0.1:28701"
EOF
}
payloads() {
 python3 -c 'import socket,sys;p=sys.argv[1].encode();s=socket.create_connection(("127.0.0.1",28700),5);s.sendall(p);assert s.recv(100)==p' "$1-tcp"
 python3 -c 'import socket,sys;p=sys.argv[1].encode();s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(15);s.sendto(p,("127.0.0.1",28701));assert s.recv(100)==p' "$1-udp"
}
run_clients() {
 : >"$stage/provider.log"; : >"$stage/consumer.log"
 "$bin" -c "$stage/provider/client.toml" >"$stage/provider.log" 2>&1 & provider=$!; pids="$pids $provider"
 for _ in $(seq 1 100); do grep -q 'event=registration_ready' "$stage/provider.log" && break; sleep .1; done
 "$bin" -c "$stage/consumer/client.toml" >"$stage/consumer.log" 2>&1 & consumer=$!; pids="$pids $consumer"
 for _ in $(seq 1 100); do ss -lnt | grep -q ':28700 ' && return; sleep .1; done
 return 1
}
stop_clients() { kill "$provider" "$consumer"; wait "$provider" "$consumer" 2>/dev/null || true; pids=$(echo "$pids" | sed "s/ $provider//;s/ $consumer//"); }
write_configs true; run_clients; payloads direct
grep -q 'protocol=Tcp.*path=NativeTcp' "$stage/consumer.log"
grep -q 'protocol=Udp.*path=QuicV4' "$stage/consumer.log"
cp "$stage/consumer.log" "$stage/direct-consumer.log"; stop_clients
write_configs false; run_clients; payloads forced-relay
grep -q 'protocol=Tcp.*path=Relay' "$stage/consumer.log"
grep -q 'protocol=Udp.*path=Relay' "$stage/consumer.log"
cp "$stage/consumer.log" "$stage/relay-consumer.log"; stop_clients
echo 'PASS installed rustgos V0.2 TCP/UDP direct and forced Relay with authenticated payloads'
