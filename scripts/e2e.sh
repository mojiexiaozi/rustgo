#!/usr/bin/env bash
set -euo pipefail

startup_gate_only=false
if [ "${1:-}" = "--startup-gate-only" ]; then
    startup_gate_only=true
    shift
fi
if [ "$#" -ne 0 ]; then
    echo "usage: scripts/e2e.sh [--startup-gate-only]" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
system_temp_base=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
temporary_directory=$(mktemp -d "$system_temp_base/rustgo-e2e.XXXXXXXX")
managed_pids=()
process_sequence=0
started_pid=
started_stdout=
started_stderr=

stop_managed() {
    local pid=$1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    local pid
    for pid in "${managed_pids[@]}"; do
        stop_managed "$pid"
    done

    if [ -n "${temporary_directory:-}" ] && [ -d "$temporary_directory" ]; then
        local cleanup_target
        cleanup_target=$(CDPATH= cd -- "$temporary_directory" && pwd -P)
        case "$cleanup_target" in
            "$system_temp_base"/rustgo-e2e.*) rm -rf -- "$cleanup_target" ;;
            *)
                echo "refusing unsafe cleanup target: $cleanup_target" >&2
                status=1
                ;;
        esac
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_managed() {
    local name=$1
    local working_directory=$2
    local binary=$3
    shift 3
    process_sequence=$((process_sequence + 1))
    started_stdout="$temporary_directory/process-$process_sequence-$name.stdout.log"
    started_stderr="$temporary_directory/process-$process_sequence-$name.stderr.log"
    (
        cd -- "$working_directory"
        exec "$binary" "$@"
    ) >"$started_stdout" 2>"$started_stderr" &
    started_pid=$!
    managed_pids+=("$started_pid")
}

combined_output() {
    local stdout_file=$1
    local stderr_file=$2
    [ ! -f "$stdout_file" ] || sed -n 'p' "$stdout_file"
    [ ! -f "$stderr_file" ] || sed -n 'p' "$stderr_file"
}

wait_for_output() {
    local pid=$1
    local stdout_file=$2
    local stderr_file=$3
    local pattern=$4
    local deadline=$((SECONDS + 15))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if { [ -f "$stdout_file" ] && grep -Fq -- "$pattern" "$stdout_file"; } ||
            { [ -f "$stderr_file" ] && grep -Fq -- "$pattern" "$stderr_file"; }; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "managed process $pid exited before readiness marker: $pattern" >&2
            combined_output "$stdout_file" "$stderr_file" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "managed process $pid missed the 15s readiness deadline: $pattern" >&2
    combined_output "$stdout_file" "$stderr_file" >&2
    return 1
}

export TMPDIR="$temporary_directory"
export RUST_LOG=info
export RUSTGO_E2E_BIN_PROFILE=release
cd -- "$workspace"

cargo build --workspace --release

client_directory="$temporary_directory/client"
server_directory="$temporary_directory/server"
client_key_directory="$client_directory/keys"
server_authorized_directory="$server_directory/authorized"
pki_directory="$temporary_directory/pki"
mkdir -p -- "$client_directory" "$server_directory" "$server_authorized_directory" "$pki_directory"

client_binary="$workspace/target/release/rustgoc"
server_binary="$workspace/target/release/rustgos"
pki_generator="$workspace/target/release/generate_ephemeral_pki"
port_allocator="$workspace/target/release/find_available_tcp_port"
"$client_binary" keygen -o "$client_key_directory"
"$pki_generator" "$pki_directory" localhost

# The server side receives only the public device key. The private key remains
# below the isolated client directory and is removed with that directory.
cp -- "$client_key_directory/device.pub" "$server_authorized_directory/device.pub"

server_certificate="$pki_directory/server.crt"
server_private_key="$pki_directory/server.key"
certificate_authority="$pki_directory/ca.crt"
device_private_key="$client_key_directory/device.key"
RUSTGO_DEVICE_PUBLIC_KEY=$(tr -d '\r\n' < "$server_authorized_directory/device.pub")
export RUSTGO_SERVER_CERTIFICATE_FILE="$server_certificate"
export RUSTGO_SERVER_PRIVATE_KEY_FILE="$server_private_key"
export RUSTGO_CERTIFICATE_AUTHORITY_FILE="$certificate_authority"
export RUSTGO_DEVICE_PRIVATE_KEY_FILE="$device_private_key"
export RUSTGO_DEVICE_PUBLIC_KEY

"$server_binary" check -c "$workspace/examples/server.toml"
"$client_binary" check -c "$workspace/examples/client.toml"

for invocation in default explicit; do
    gate_directory="$temporary_directory/startup-$invocation"
    mkdir -- "$gate_directory"
    server_config="$gate_directory/server.toml"
    client_config="$gate_directory/client.toml"
    server_port=$("$port_allocator")
    server_lines=(
        '[server]'
        "bind_addr = \"127.0.0.1:$server_port\""
        "certificate_file = \"$server_certificate\""
        "private_key_file = \"$server_private_key\""
        'heartbeat_timeout_secs = 10'
        ''
        '[limits]'
        'max_clients = 4'
        'max_tunnels_per_client = 4'
        'max_tcp_connections_per_tunnel = 4'
        'max_udp_sessions_per_tunnel = 4'
        'max_udp_payload_bytes = 65507'
        ''
        '[[clients]]'
        'name = "home-pc"'
        "public_key = \"$RUSTGO_DEVICE_PUBLIC_KEY\""
        'enabled = true'
    )
    printf '%s\n' "${server_lines[@]}" >"$server_config"

    if [ "$invocation" = explicit ]; then
        start_managed "$invocation-server" "$gate_directory" "$server_binary" -c server.toml
    else
        start_managed "$invocation-server" "$gate_directory" "$server_binary"
    fi
    server_pid=$started_pid
    server_stdout=$started_stdout
    server_stderr=$started_stderr
    wait_for_output "$server_pid" "$server_stdout" "$server_stderr" event=server_listening
    server_address=$(combined_output "$server_stdout" "$server_stderr" |
        sed -n 's/.*address=\([^[:space:]]*\).*/\1/p' |
        head -n 1)
    if [ -z "$server_address" ]; then
        echo "could not recover listening address for $invocation server" >&2
        combined_output "$server_stdout" "$server_stderr" >&2
        exit 1
    fi

    client_lines=(
        '[client]'
        'name = "home-pc"'
        "server_addr = \"$server_address\""
        'server_name = "localhost"'
        "certificate_authority_file = \"$certificate_authority\""
        "private_key_file = \"$device_private_key\""
        'heartbeat_interval_secs = 2'
    )
    printf '%s\n' "${client_lines[@]}" >"$client_config"

    if [ "$invocation" = explicit ]; then
        start_managed "$invocation-client" "$gate_directory" "$client_binary" -c client.toml
    else
        start_managed "$invocation-client" "$gate_directory" "$client_binary"
    fi
    client_pid=$started_pid
    client_stdout=$started_stdout
    client_stderr=$started_stderr
    wait_for_output "$client_pid" "$client_stdout" "$client_stderr" event=registration_ready
    stop_managed "$client_pid"
    stop_managed "$server_pid"
done

if [ "$startup_gate_only" = false ]; then
    cargo test -p rustgo-e2e --test tcp tcp_echo -- --exact --test-threads=1
    cargo test -p rustgo-e2e --test udp udp_echo -- --exact --test-threads=1
fi
