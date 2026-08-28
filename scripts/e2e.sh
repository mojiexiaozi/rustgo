#!/usr/bin/env bash
set -euo pipefail

managed_pids=()
managed_identities=()
started_pid=
started_stdout=
started_stderr=
process_sequence=0
cleanup_deadline=0
managed_term_grace_seconds=2
managed_kill_reap_seconds=2

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
    kill -TERM "$pid"
}

kill_process() {
    local pid=$1
    local expected_identity=$2
    process_identity_matches "$pid" "$expected_identity" || return 1
    kill -KILL "$pid"
}

begin_cleanup_deadline() {
    local timeout_seconds=$1
    cleanup_deadline=$((SECONDS + timeout_seconds))
}

cleanup_deadline_expired() {
    [ "$SECONDS" -ge "$cleanup_deadline" ]
}

cleanup_poll_pause() {
    sleep 0.1
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

wait_for_managed_identity_release() {
    local pid=$1
    local expected_identity=$2
    local timeout_seconds=$3

    begin_cleanup_deadline "$timeout_seconds"
    while true; do
        if ! process_identity_matches "$pid" "$expected_identity"; then
            if ! unregister_managed_pid "$pid"; then
                echo "managed PID disappeared before unregister: $pid" >&2
                return 1
            fi
            return 0
        fi
        if cleanup_deadline_expired; then
            return 1
        fi
        if ! process_is_alive "$pid" "$expected_identity"; then
            # A child may exit between the identity read and signal-0 probe.
            # Continue only while the same identity remains readable; Bash
            # reaps asynchronous children and /proc then releases the identity.
            if ! process_identity_matches "$pid" "$expected_identity"; then
                if ! unregister_managed_pid "$pid"; then
                    echo "managed PID disappeared before unregister: $pid" >&2
                    return 1
                fi
                return 0
            fi
        fi
        cleanup_poll_pause
    done
}

stop_managed() {
    local pid=$1
    local identity
    local terminate_failed=0
    local kill_failed=0
    local kill_sent=0
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

    if wait_for_managed_identity_release \
        "$pid" "$identity" "$managed_term_grace_seconds"; then
        return "$terminate_failed"
    fi

    # The TERM grace period expired while the original identity was still
    # present. Re-check both identity and liveness, then check identity again at
    # the KILL wrapper so a recycled numeric PID is never signalled.
    if ! process_identity_matches "$pid" "$identity"; then
        unregister_managed_pid "$pid"
        return "$terminate_failed"
    fi
    if process_is_alive "$pid" "$identity"; then
        if ! process_identity_matches "$pid" "$identity"; then
            unregister_managed_pid "$pid"
            return "$terminate_failed"
        fi
        if kill_process "$pid" "$identity" 2>/dev/null; then
            kill_sent=1
        else
            if ! process_identity_matches "$pid" "$identity"; then
                unregister_managed_pid "$pid"
                return "$terminate_failed"
            fi
            echo "failed to KILL owned process: $pid" >&2
            kill_failed=1
        fi
    else
        if ! process_identity_matches "$pid" "$identity"; then
            unregister_managed_pid "$pid"
            return "$terminate_failed"
        fi
    fi

    if wait_for_managed_identity_release \
        "$pid" "$identity" "$managed_kill_reap_seconds"; then
        if [ "$terminate_failed" -ne 0 ] || [ "$kill_failed" -ne 0 ]; then
            return 1
        fi
        return 0
    fi

    if ! process_identity_matches "$pid" "$identity"; then
        unregister_managed_pid "$pid"
        if [ "$terminate_failed" -ne 0 ] || [ "$kill_failed" -ne 0 ]; then
            return 1
        fi
        return 0
    fi
    if [ "$kill_sent" -ne 0 ]; then
        echo "owned process did not exit after KILL before cleanup deadline: $pid" >&2
    else
        echo "owned process could not be reaped before cleanup deadline: $pid" >&2
    fi
    if ! unregister_managed_pid "$pid"; then
        echo "managed PID disappeared before unregister: $pid" >&2
    fi
    return 1
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

    install_managed_child_simulation() {
        local behavior=$1
        managed_pids=()
        managed_identities=()
        simulated_behavior=$behavior
        simulated_alive=true
        simulated_identity=identity-A
        simulated_identity_readable=true
        alive_calls=0
        terminate_calls=0
        kill_calls=0
        wait_calls=0
        deadline_starts=0
        deadline_checks=0
        total_deadline_checks=0
        poll_pause_calls=0

        if [ "$behavior" = missing-identity ]; then
            simulated_identity_readable=false
        fi

        read_process_identity() {
            [ "$1" = 4242 ]
            [ "$simulated_identity_readable" = true ] || return 1
            printf '%s\n' "$simulated_identity"
        }
        process_is_alive() {
            [ "$1" = 4242 ]
            [ "$2" = identity-A ]
            alive_calls=$((alive_calls + 1))
            if [ "$simulated_behavior" = term-identity-changes ] &&
                [ "$terminate_calls" -eq 1 ] && [ "$alive_calls" -eq 3 ]; then
                # Change identity after the TERM deadline, in the race window
                # between escalation liveness and the final pre-KILL check.
                simulated_identity=identity-B
            fi
            [ "$simulated_alive" = true ]
        }
        terminate_process() {
            [ "$1" = 4242 ]
            [ "$2" = identity-A ]
            terminate_calls=$((terminate_calls + 1))
            case "$simulated_behavior" in
                term-exits)
                    simulated_alive=false
                    simulated_identity_readable=false
                    ;;
            esac
        }
        kill_process() {
            [ "$1" = 4242 ]
            [ "$2" = identity-A ]
            kill_calls=$((kill_calls + 1))
            if [ "$simulated_behavior" = term-ignored-kill-exits ]; then
                simulated_alive=false
                simulated_identity_readable=false
            fi
        }
        wait_for_process() {
            [ "$1" = 4242 ]
            [ "$2" = identity-A ]
            wait_calls=$((wait_calls + 1))
            return 0
        }
        begin_cleanup_deadline() {
            deadline_starts=$((deadline_starts + 1))
            deadline_checks=0
        }
        cleanup_deadline_expired() {
            deadline_checks=$((deadline_checks + 1))
            total_deadline_checks=$((total_deadline_checks + 1))
            [ "$deadline_checks" -ge 2 ]
        }
        cleanup_poll_pause() {
            poll_pause_calls=$((poll_pause_calls + 1))
        }
    }

    assert_managed_child_scenario() (
        local behavior=$1
        local expected_status=$2
        local expected_term_calls=$3
        local expected_kill_calls=$4
        local expected_deadline_starts=$5
        local minimum_deadline_checks=$6
        install_managed_child_simulation "$behavior"
        register_managed_pid 4242 identity-A

        local observed_status=0
        local scenario_error
        scenario_error=$(mktemp "$system_temp_base/rustgo-e2e-self-test.XXXXXXXX")
        trap 'command rm -f -- "$scenario_error"' EXIT
        if cleanup_owned_children 2>"$scenario_error"; then
            observed_status=0
        else
            observed_status=$?
        fi
        if [ "$observed_status" -ne "$expected_status" ]; then
            echo "$behavior cleanup status: expected $expected_status, got $observed_status" >&2
            return 1
        fi
        if [ "$terminate_calls" -ne "$expected_term_calls" ]; then
            echo "$behavior TERM calls: expected $expected_term_calls, got $terminate_calls" >&2
            return 1
        fi
        if [ "$kill_calls" -ne "$expected_kill_calls" ]; then
            echo "$behavior KILL calls: expected $expected_kill_calls, got $kill_calls" >&2
            return 1
        fi
        if [ "$deadline_starts" -ne "$expected_deadline_starts" ]; then
            echo "$behavior deadline starts: expected $expected_deadline_starts, got $deadline_starts" >&2
            return 1
        fi
        if [ "$total_deadline_checks" -lt "$minimum_deadline_checks" ]; then
            echo "$behavior deadline checks: expected at least $minimum_deadline_checks, got $total_deadline_checks" >&2
            return 1
        fi
        [ "$wait_calls" -eq 0 ]
        [ "$total_deadline_checks" -le 8 ]
        [ "$poll_pause_calls" -le 4 ]
        [ "${#managed_pids[@]}" -eq 0 ]
        [ "${#managed_identities[@]}" -eq 0 ]
        if [ "$expected_status" -eq 0 ]; then
            [ ! -s "$scenario_error" ]
        else
            assert_file_contains "$scenario_error" \
                "owned process did not exit after KILL before cleanup deadline"
        fi
        command rm -f -- "$scenario_error"
        trap - EXIT
    )

    # These scenarios exercise the real cleanup state machine with deterministic
    # process primitives: cooperative TERM, TERM escalation, identity loss,
    # missing identity, and a child that remains present even after KILL.
    assert_managed_child_scenario term-exits 0 1 0 1 0
    assert_managed_child_scenario term-ignored-kill-exits 0 1 1 2 2
    assert_managed_child_scenario term-identity-changes 0 1 0 1 2
    assert_managed_child_scenario missing-identity 0 0 0 0 0
    assert_managed_child_scenario kill-stuck 1 1 1 2 4

    run_kill_stuck_cleanup() (
        local original_status=$1
        install_managed_child_simulation kill-stuck
        cleanup_temporary_directory() {
            return 0
        }
        register_managed_pid 4242 identity-A
        trap cleanup EXIT
        exit "$original_status"
    )

    local kill_stuck_output kill_stuck_status
    if kill_stuck_output=$(run_kill_stuck_cleanup 0 2>&1); then
        echo "cleanup accepted a managed child that remained alive after KILL" >&2
        return 1
    else
        kill_stuck_status=$?
    fi
    [ "$kill_stuck_status" -eq 1 ]
    case "$kill_stuck_output" in
        *"cleanup failed; changing successful exit status to 1"*) ;;
        *)
            echo "missing cleanup-success propagation diagnostic" >&2
            return 1
            ;;
    esac

    if kill_stuck_output=$(run_kill_stuck_cleanup 23 2>&1); then
        echo "cleanup hid an original failure while KILL did not converge" >&2
        return 1
    else
        kill_stuck_status=$?
    fi
    [ "$kill_stuck_status" -eq 23 ]
    case "$kill_stuck_output" in
        *"cleanup also failed; preserving original exit status 23"*) ;;
        *)
            echo "missing original-failure preservation diagnostic" >&2
            return 1
            ;;
    esac

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
