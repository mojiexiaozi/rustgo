#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
system_temp_base=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
temporary_directory=$(mktemp -d "$system_temp_base/rustgo-e2e.XXXXXXXX")

cleanup() {
    if [ -z "${temporary_directory:-}" ] || [ ! -d "$temporary_directory" ]; then
        return
    fi

    cleanup_target=$(CDPATH= cd -- "$temporary_directory" && pwd -P)
    case "$cleanup_target" in
        "$system_temp_base"/rustgo-e2e.*) rm -rf -- "$cleanup_target" ;;
        *)
            echo "refusing unsafe cleanup target: $cleanup_target" >&2
            return 1
            ;;
    esac
}
trap cleanup EXIT

export TMPDIR="$temporary_directory"
export RUSTGO_E2E_BIN_PROFILE=release
cd -- "$workspace"

cargo build --workspace --release

client_directory="$temporary_directory/client"
server_directory="$temporary_directory/server"
client_key_directory="$client_directory/keys"
server_authorized_directory="$server_directory/authorized"
mkdir -p -- "$client_directory" "$server_directory" "$server_authorized_directory"

client_binary="$workspace/target/release/rustgoc"
server_binary="$workspace/target/release/rustgos"
"$client_binary" keygen -o "$client_key_directory"

# The server side receives only the public device key. The private key remains
# below the isolated client directory and is removed with that directory.
cp -- "$client_key_directory/device.pub" "$server_authorized_directory/device.pub"

server_certificate="$server_directory/server.crt"
server_private_key="$server_directory/server.key"
certificate_authority="$client_directory/ca.crt"
: > "$server_certificate"
: > "$server_private_key"
: > "$certificate_authority"

export RUSTGO_SERVER_CERTIFICATE_FILE="$server_certificate"
export RUSTGO_SERVER_PRIVATE_KEY_FILE="$server_private_key"
export RUSTGO_CERTIFICATE_AUTHORITY_FILE="$certificate_authority"
export RUSTGO_DEVICE_PRIVATE_KEY_FILE="$client_key_directory/device.key"
RUSTGO_DEVICE_PUBLIC_KEY=$(tr -d '\r\n' < "$server_authorized_directory/device.pub")
export RUSTGO_DEVICE_PUBLIC_KEY

"$server_binary" check -c "$workspace/examples/server.toml"
"$client_binary" check -c "$workspace/examples/client.toml"

compare_default_invocation() {
    binary=$1
    config_name=$2
    config_source=$3
    gate_directory="$temporary_directory/default-${config_name%.toml}"
    mkdir -- "$gate_directory"
    cp -- "$config_source" "$gate_directory/$config_name"

    set +e
    default_output=$(cd -- "$gate_directory" && "$binary" 2>&1)
    default_exit=$?
    explicit_output=$(cd -- "$gate_directory" && "$binary" -c "$config_name" 2>&1)
    explicit_exit=$?
    set -e

    if [ "$default_exit" -eq 0 ] || [ "$default_exit" -ne "$explicit_exit" ] || [ "$default_output" != "$explicit_output" ]; then
        echo "no-argument startup is not equivalent to explicit -c for $binary" >&2
        return 1
    fi
}

compare_default_invocation "$server_binary" server.toml "$workspace/examples/server.toml"
compare_default_invocation "$client_binary" client.toml "$workspace/examples/client.toml"

cargo test -p rustgo-e2e --test tcp tcp_echo -- --exact --test-threads=1
cargo test -p rustgo-e2e --test udp udp_echo -- --exact --test-threads=1
