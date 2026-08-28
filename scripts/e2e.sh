#!/usr/bin/env bash
set -euo pipefail

managed_pids=()
managed_identities=()
started_pid=
started_stdout=
started_stderr=
process_sequence=0

parse_proc_stat_starttime() {
    local stat_line=$1
    local stat_suffix
    local starttime
    local stat_fields=()

    case "$stat_line" in
        *') '*) ;;
        *) return 1 ;;
    esac
    # comm is parenthesized and may itself contain spaces or right
    # parentheses. Strip through the final ") "; the remaining tokens begin
    # at field 3, so array index 19 is field 22 (starttime).
    stat_suffix=${stat_line##*) }
    read -r -a stat_fields <<<"$stat_suffix"
    if [ "${#stat_fields[@]}" -lt 20 ]; then
        return 1
    fi
    starttime=${stat_fields[19]}
    case "$starttime" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$starttime"
}

read_process_identity() {
    local pid=$1
    local stat_line
    local starttime
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if ! IFS= read -r stat_line <"/proc/$pid/stat"; then
        return 1
    fi
    case "$stat_line" in
        "$pid ("*) ;;
        *) return 1 ;;
    esac
    if ! starttime=$(parse_proc_stat_starttime "$stat_line"); then
        return 1
    fi
    printf 'linux-proc-starttime:%s\n' "$starttime"
}

process_is_alive() {
    local pid=$1
    local expected_identity=$2
    process_identity_matches "$pid" "$expected_identity" || return 1
    kill -0 "$pid" 2>/dev/null
}

terminate_process() {
    local pid=$1
    local expected_identity=$2
    process_identity_matches "$pid" "$expected_identity" || return 1
    kill "$pid"
}

wait_for_process() {
    local pid=$1
    local expected_identity=$2
    process_identity_matches "$pid" "$expected_identity" || return 1
    wait "$pid"
}

remove_tree() {
    rm -rf -- "$1"
}

is_managed_pid() {
    local target=$1
    local owned
    for owned in "${managed_pids[@]}"; do
        if [ "$owned" = "$target" ]; then
            return 0
        fi
    done
    return 1
}

register_managed_pid() {
    local pid=$1
    local identity=$2
    if is_managed_pid "$pid"; then
        echo "refusing duplicate managed PID registration: $pid" >&2
        return 1
    fi
    if [ -z "$identity" ]; then
        echo "refusing managed PID without process identity: $pid" >&2
        return 1
    fi
    managed_pids+=("$pid")
    managed_identities+=("$identity")
}

managed_identity_for_pid() {
    local target=$1
    local index
    for index in "${!managed_pids[@]}"; do
        if [ "${managed_pids[$index]}" = "$target" ]; then
            printf '%s\n' "${managed_identities[$index]}"
            return 0
        fi
    done
    return 1
}

process_identity_matches() {
    local pid=$1
    local expected_identity=$2
    local observed_identity
    if ! observed_identity=$(read_process_identity "$pid"); then
        return 1
    fi
    [ "$observed_identity" = "$expected_identity" ]
}

managed_process_is_alive() {
    local pid=$1
    local identity
    if ! identity=$(managed_identity_for_pid "$pid"); then
        return 1
    fi
    process_is_alive "$pid" "$identity"
}

unregister_managed_pid() {
    local target=$1
    local found=false
    local index
    local remaining_pids=()
    local remaining_identities=()
    for index in "${!managed_pids[@]}"; do
        if [ "${managed_pids[$index]}" = "$target" ]; then
            found=true
        else
            remaining_pids+=("${managed_pids[$index]}")
            remaining_identities+=("${managed_identities[$index]}")
        fi
    done
    managed_pids=("${remaining_pids[@]}")
    managed_identities=("${remaining_identities[@]}")
    [ "$found" = true ]
}

wait_and_unregister_managed_pid() {
    local pid=$1
    local expected_identity=$2
    local previous_int previous_term
    local deferred_signal=0
    local observed_signal=0
    local unregister_failed=0
    local identity_lost=0
    previous_int=$(trap -p INT)
    previous_term=$(trap -p TERM)

    # Defer interrupt handling across wait plus unregister. Bash runs a pending
    # trap between commands, so restoring the normal exit traps only after the
    # registry update prevents a freshly reused PID from remaining owned.
    trap 'deferred_signal=130; observed_signal=130' INT
    trap 'deferred_signal=143; observed_signal=143' TERM
    while true; do
        deferred_signal=0
        if ! process_identity_matches "$pid" "$expected_identity"; then
            identity_lost=1
            break
        fi
        if wait_for_process "$pid" "$expected_identity"; then
            :
        else
            # A terminated child normally makes wait return its nonzero exit
            # status. The wait still reaped it; only a deferred signal requires
            # another wait attempt before unregistering.
            :
        fi
        if [ "$deferred_signal" -eq 0 ]; then
            break
        fi
    done
    if ! unregister_managed_pid "$pid"; then
        unregister_failed=1
    fi

    if [ -n "$previous_int" ]; then
        eval "$previous_int"
    else
        trap - INT
    fi
    if [ -n "$previous_term" ]; then
        eval "$previous_term"
    else
        trap - TERM
    fi

    if [ "$unregister_failed" -ne 0 ]; then
        echo "managed PID disappeared before unregister: $pid" >&2
        return 1
    fi
    if [ "$observed_signal" -ne 0 ]; then
        return "$observed_signal"
    fi
    if [ "$identity_lost" -ne 0 ]; then
        return 0
    fi
    return 0
}

stop_managed() {
    local pid=$1
    local identity
    local terminate_failed=0
    local reap_status=0
    if ! is_managed_pid "$pid"; then
        return 0
    fi
    if ! identity=$(managed_identity_for_pid "$pid"); then
        echo "managed PID has no registered identity: $pid" >&2
        return 1
    fi
    if ! process_identity_matches "$pid" "$identity"; then
        unregister_managed_pid "$pid"
        return 0
    fi
    if process_is_alive "$pid" "$identity"; then
        if ! process_identity_matches "$pid" "$identity"; then
            unregister_managed_pid "$pid"
            return 0
        fi
        if ! terminate_process "$pid" "$identity" 2>/dev/null; then
            if ! process_identity_matches "$pid" "$identity"; then
                unregister_managed_pid "$pid"
                return 0
            fi
            echo "failed to terminate owned process: $pid" >&2
            terminate_failed=1
        fi
    fi
    if ! process_identity_matches "$pid" "$identity"; then
        unregister_managed_pid "$pid"
        return "$terminate_failed"
    fi
    if wait_and_unregister_managed_pid "$pid" "$identity"; then
        reap_status=0
    else
        reap_status=$?
    fi
    if [ "$terminate_failed" -ne 0 ]; then
        return 1
    fi
    return "$reap_status"
}

cleanup_owned_children() {
    local failed=0
    local pid
    local pending=("${managed_pids[@]}")
    for pid in "${pending[@]}"; do
        if ! stop_managed "$pid"; then
            echo "failed to clean up owned process: $pid" >&2
            failed=1
        fi
    done
    if [ "${#managed_pids[@]}" -ne 0 ]; then
        echo "owned process registry is not empty after cleanup" >&2
        failed=1
    fi
    if [ "${#managed_identities[@]}" -ne 0 ]; then
        echo "owned process identity registry is not empty after cleanup" >&2
        failed=1
    fi
    [ "$failed" -eq 0 ]
}

cleanup_temporary_directory() {
    if [ -z "${temporary_directory:-}" ]; then
        return 0
    fi
    if [ ! -e "$temporary_directory" ] && [ ! -L "$temporary_directory" ]; then
        return 0
    fi

    local cleanup_target
    if ! cleanup_target=$(CDPATH= cd -- "$temporary_directory" && pwd -P); then
        echo "failed to resolve owned temporary directory: $temporary_directory" >&2
        return 1
    fi
    case "$cleanup_target" in
        "$system_temp_base"/rustgo-e2e.*) ;;
        *)
            echo "refusing unsafe cleanup target: $cleanup_target" >&2
            return 1
            ;;
    esac
    if ! remove_tree "$cleanup_target"; then
        echo "failed to remove owned temporary directory: $cleanup_target" >&2
        return 1
    fi
    if [ -e "$cleanup_target" ] || [ -L "$cleanup_target" ]; then
        echo "owned temporary directory remains after removal: $cleanup_target" >&2
        return 1
    fi
    return 0
}

select_cleanup_exit_status() {
    local original_status=$1
    local cleanup_failed=$2
    if [ "$original_status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        echo 1
    else
        echo "$original_status"
    fi
}

cleanup() {
    local original_status=$?
    local cleanup_failed=0
    local final_status
    trap - EXIT INT TERM
    set +e

    cleanup_owned_children || cleanup_failed=1
    cleanup_temporary_directory || cleanup_failed=1
    if [ "$cleanup_failed" -ne 0 ]; then
        if [ "$original_status" -eq 0 ]; then
            echo "cleanup failed; changing successful exit status to 1" >&2
        else
            echo "cleanup also failed; preserving original exit status $original_status" >&2
        fi
    fi
    final_status=$(select_cleanup_exit_status "$original_status" "$cleanup_failed")
    exit "$final_status"
}

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
    local started_identity
    if ! started_identity=$(read_process_identity "$started_pid"); then
        # Keep the PID registered with a value the Linux reader can never
        # produce. EXIT cleanup will unregister it without signalling or
        # waiting because ownership cannot be verified safely.
        register_managed_pid "$started_pid" identity-unavailable
        echo "cannot verify identity of started process $started_pid; refusing PID-only cleanup" >&2
        return 1
    fi
    register_managed_pid "$started_pid" "$started_identity"
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
        if ! managed_process_is_alive "$pid"; then
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

run_cleanup_self_test() (
    set -euo pipefail

    assert_file_contains() {
        local file=$1
        local expected=$2
        local contents
        contents=$(<"$file")
        case "$contents" in
            *"$expected"*) return 0 ;;
            *)
                echo "missing expected diagnostic in $file: $expected" >&2
                return 1
                ;;
        esac
    }

    local parsed_starttime
    if parsed_starttime=$(parse_proc_stat_starttime \
        '4242 (worker ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20'); then
        [ "$parsed_starttime" = 987654 ]
    else
        echo "failed to parse a valid proc stat starttime fixture" >&2
        return 1
    fi
    if parse_proc_stat_starttime \
        '4242 (truncated worker) S 1 2 3 4 5 6 7 8 9' >/dev/null; then
        echo "accepted a truncated proc stat fixture" >&2
        return 1
    fi

    # Simulate a naturally exited child whose numeric PID is immediately reused
    # before an explicit wait. Cleanup must compare the registered process
    # identity and never signal or wait for the unrelated replacement.
    managed_pids=()
    managed_identities=()
    local alive_calls=0
    local terminate_calls=0
    local wait_calls=0
    local current_identity=identity-A
    local identity_readable=true
    read_process_identity() {
        [ "$identity_readable" = true ] || return 1
        printf '%s\n' "$current_identity"
    }
    process_is_alive() {
        [ "$1" = 4242 ]
        [ "$2" = identity-A ]
        alive_calls=$((alive_calls + 1))
        return 0
    }
    terminate_process() {
        [ "$1" = 4242 ]
        [ "$2" = identity-A ]
        terminate_calls=$((terminate_calls + 1))
        return 0
    }
    wait_for_process() {
        [ "$1" = 4242 ]
        [ "$2" = identity-A ]
        wait_calls=$((wait_calls + 1))
        return 0
    }
    register_managed_pid 4242 identity-A
    current_identity=identity-B
    cleanup_owned_children
    [ "$alive_calls" -eq 0 ]
    [ "$terminate_calls" -eq 0 ]
    [ "$wait_calls" -eq 0 ]
    [ "${#managed_pids[@]}" -eq 0 ]
    [ "${#managed_identities[@]}" -eq 0 ]

    # An unreadable or missing /proc identity is also unverifiable and must
    # take the same never-signal path.
    identity_readable=false
    register_managed_pid 4242 identity-A
    cleanup_owned_children
    [ "$alive_calls" -eq 0 ]
    [ "$terminate_calls" -eq 0 ]
    [ "$wait_calls" -eq 0 ]
    [ "${#managed_pids[@]}" -eq 0 ]
    [ "${#managed_identities[@]}" -eq 0 ]

    # The matching identity remains an owned child and must follow the normal
    # terminate, wait, and unregister lifecycle.
    identity_readable=true
    current_identity=identity-A
    register_managed_pid 4242 identity-A
    cleanup_owned_children
    [ "$alive_calls" -eq 1 ]
    [ "$terminate_calls" -eq 1 ]
    [ "$wait_calls" -eq 1 ]
    [ "${#managed_pids[@]}" -eq 0 ]
    [ "${#managed_identities[@]}" -eq 0 ]

    # Simulate rm failure against a real, correctly scoped mktemp directory.
    # The helper must fail, retain the directory, and emit a clear diagnostic.
    local test_directory cleanup_error cleanup_status preserved_error preserved_status
    test_directory=$(mktemp -d "$system_temp_base/rustgo-e2e.XXXXXXXX")
    trap 'command rm -rf -- "$test_directory"' EXIT
    temporary_directory=$test_directory
    cleanup_error="$test_directory/cleanup.stderr"
    remove_tree() {
        return 1
    }
    if cleanup_temporary_directory 2>"$cleanup_error"; then
        echo "cleanup_temporary_directory accepted a simulated remove failure" >&2
        return 1
    fi
    assert_file_contains "$cleanup_error" "failed to remove owned temporary directory"
    [ -d "$test_directory" ]
    [ "$(select_cleanup_exit_status 0 1)" -eq 1 ]
    [ "$(select_cleanup_exit_status 23 1)" -eq 23 ]

    # Exercise the actual EXIT cleanup path as well as its helpers. A cleanup
    # failure must turn success into failure without hiding a prior failure.
    cleanup_error="$test_directory/cleanup-success.stderr"
    if (trap cleanup EXIT; exit 0) 2>"$cleanup_error"; then
        echo "cleanup trap accepted a simulated remove failure" >&2
        return 1
    else
        cleanup_status=$?
    fi
    [ "$cleanup_status" -eq 1 ]
    assert_file_contains "$cleanup_error" "cleanup failed; changing successful exit status to 1"
    [ -d "$test_directory" ]

    preserved_error="$test_directory/cleanup-failure.stderr"
    if (trap cleanup EXIT; exit 23) 2>"$preserved_error"; then
        echo "cleanup trap hid an original failure" >&2
        return 1
    else
        preserved_status=$?
    fi
    [ "$preserved_status" -eq 23 ]
    assert_file_contains "$preserved_error" "cleanup also failed; preserving original exit status 23"
    [ -d "$test_directory" ]
    command rm -rf -- "$test_directory"
    trap - EXIT
)

startup_gate_only=false
cleanup_self_test=false
case "${1:-}" in
    --startup-gate-only)
        startup_gate_only=true
        shift
        ;;
    --self-test)
        cleanup_self_test=true
        shift
        ;;
    "")
        ;;
    *)
        echo "usage: scripts/e2e.sh [--startup-gate-only | --self-test]" >&2
        exit 2
        ;;
esac
if [ "$#" -ne 0 ]; then
    echo "usage: scripts/e2e.sh [--startup-gate-only | --self-test]" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
system_temp_base=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)

if [ "$cleanup_self_test" = true ]; then
    run_cleanup_self_test
    echo "e2e bash cleanup self-test passed"
    exit 0
fi

if ! read_process_identity "$$" >/dev/null; then
    echo "scripts/e2e.sh requires Linux /proc PID starttime identity support" >&2
    exit 1
fi

temporary_directory=$(mktemp -d "$system_temp_base/rustgo-e2e.XXXXXXXX")
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
