#!/usr/bin/env bash
set +e
gate_name=$1
shift
log_file="${gate_name}.log"
exit_file="${gate_name}.exit"
tmp_file="${exit_file}.tmp"
rm -f "$log_file" "$exit_file" "$tmp_file"
"$@" >"$log_file" 2>&1
rc=$?
printf '%s\n' "$rc" >"$tmp_file"
mv "$tmp_file" "$exit_file"
exit "$rc"
