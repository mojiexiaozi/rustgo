#!/usr/bin/env bash
set -euo pipefail
stage=/root/rustgo-v02-71812f7/live-verify
mkdir -p "$stage"
name=$(openssl x509 -in /etc/rustgo/pki/server.crt -noout -subject | sed -n 's/.*CN *= *//p')
cat >"$stage/client.toml" <<EOF
[client]
name = "validation-client"
server_addr = "127.0.0.1:7443"
server_name = "$name"
certificate_authority_file = "/etc/rustgo/pki/ca.crt"
private_key_file = "/etc/rustgo/validation-client/device.key"
heartbeat_interval_secs = 20

[[tunnels]]
name = "live-tcp"
protocol = "tcp"
local_addr = "127.0.0.1:28180"
remote_port = 28181

[[tunnels]]
name = "live-udp"
protocol = "udp"
local_addr = "127.0.0.1:28182"
remote_port = 28183
EOF
/opt/rustgo/bin/rustgoc check -c "$stage/client.toml"
python3 -u -c 'import socket,threading
t=socket.socket(); t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); t.bind(("127.0.0.1",28180)); t.listen()
def a():
 while True:
  c,_=t.accept(); d=c.recv(65535); c.sendall(d); c.close()
threading.Thread(target=a,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind(("127.0.0.1",28182))
while True:
 d,a=u.recvfrom(65535); u.sendto(d,a)' >"$stage/echo.log" 2>&1 & echo_pid=$!
/opt/rustgo/bin/rustgoc -c "$stage/client.toml" >"$stage/client.log" 2>&1 & client_pid=$!
cleanup() { kill "$client_pid" "$echo_pid" 2>/dev/null || true; wait "$client_pid" "$echo_pid" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 100); do ss -lnt | grep -q ':28181 ' && break; sleep .1; done
python3 -c 'import socket
p=b"live-v01-tcp"; s=socket.create_connection(("127.0.0.1",28181),3); s.sendall(p); assert s.recv(100)==p'
udp_ip=$(sed -n 's/^udp_bind_ip = "\([^"]*\)"/\1/p' /etc/rustgo/server.toml)
python3 -c 'import socket,sys
p=b"live-v01-udp"; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(p,(sys.argv[1],28183)); assert s.recv(100)==p' "$udp_ip"
echo 'PASS live V0.1 TCP/UDP relay authentication and payloads'
