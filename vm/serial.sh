# Minimal expect for a VM serial console over its Unix socket. Sourced.
# shellcheck shell=bash
#
#   serial_open SOCKET LOG
#   serial_send TEXT          # sends TEXT and a carriage return
#   serial_expect TEXT [SECS] # waits until TEXT appears in new output

serial_open() {
    coproc SERIAL { socat - "UNIX-CONNECT:$1"; }
    SERIAL_LOG=$2
    SERIAL_BUF=
}

serial_send() {
    printf '%s\r' "$1" >&"${SERIAL[1]}"
    sleep 0.2
}

serial_expect() {
    local want=$1 deadline=$((SECONDS + ${2:-60})) chunk
    while ((SECONDS < deadline)); do
        chunk=
        IFS= read -r -d '' -t 0.5 -n 4096 chunk <&"${SERIAL[0]}" || true
        if [[ -n $chunk ]]; then
            printf '%s' "$chunk" >>"$SERIAL_LOG"
            SERIAL_BUF+=$chunk
        fi
        if [[ $SERIAL_BUF == *"$want"* ]]; then
            SERIAL_BUF=${SERIAL_BUF#*"$want"}
            return 0
        fi
        SERIAL_BUF=${SERIAL_BUF: -8192}
    done
    echo "serial: timed out waiting for '$want'" >&2
    return 1
}
