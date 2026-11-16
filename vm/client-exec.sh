#!/usr/bin/env bash
# Runs a shell command on the client VM over its serial console and prints
# its output: vm/client-exec.sh 'command' [timeout-seconds]
set -euo pipefail
dir=$(dirname "$0")
source "$dir/env.sh"
source "$dir/serial.sh"

log=$VM_DIR/client-exec.log
: >"$log"
serial_open "$CLIENT_SERIAL" "$log"
serial_send ''
serial_expect '' 1 || true
sleep 1
serial_expect '' 1 || true
if grep -aq 'login:' "$log"; then
    serial_send root
    serial_expect '# ' 15
fi

tag=$RANDOM$RANDOM
# The quotes keep the echoed command line from matching the markers.
serial_send "echo BEGIN-''$tag; { $1 ; } 2>&1; echo END-''$tag=\$?"
serial_expect "END-$tag=" "${2:-60}"
serial_expect '# ' 5 || true
tr -d '\r' <"$log" | awk -v b="BEGIN-$tag" -v e="END-$tag=" '
    index($0, e) == 1 { sub(e, "exit="); print; exit }
    found { print }
    $0 == b { found = 1 }'
