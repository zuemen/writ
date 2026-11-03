#!/usr/bin/env bash
# Local NEAR sandbox: start / stop / status. Data is in .sandbox/ (.gitignore).
# Binary source: $NEAR_SANDBOX_BIN, or the one near-workspaces downloaded during `make -C contract test`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOME_DIR="$ROOT/.sandbox"
PIDF="$HOME_DIR/pid"
find_bin() {
  if [ -n "${NEAR_SANDBOX_BIN:-}" ]; then echo "$NEAR_SANDBOX_BIN"; return; fi
  ls "$ROOT"/contract/target/debug/build/near-sandbox-*/out/.near/near-sandbox-*/near-sandbox 2>/dev/null | head -1
}
preload() {
  # neard needs an fd limit of 65535; in containers with too low a hard limit use a shim (a normal computer never gets here)
  if [ "$(ulimit -Hn)" != "unlimited" ] && [ "$(ulimit -Hn)" -lt 65535 ]; then
    [ -f "$ROOT/tools/fakerlimit.so" ] || gcc -shared -fPIC -o "$ROOT/tools/fakerlimit.so" "$ROOT/tools/fakerlimit.c" -ldl
    echo "LD_PRELOAD=$ROOT/tools/fakerlimit.so"
  fi
}
case "${1:-}" in
  start)
    BIN="$(find_bin)"; [ -x "$BIN" ] || { echo "near-sandbox not found: run 'make -C contract test' once or set NEAR_SANDBOX_BIN"; exit 1; }
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "sandbox already running"; exit 0; fi
    if curl -sf http://127.0.0.1:3030/status >/dev/null; then
      echo "port 3030 is already serving a NEAR RPC that this script did not start (another sandbox?). Stop it first."; exit 1
    fi
    rm -rf "$HOME_DIR"; mkdir -p "$HOME_DIR"
    env $(preload) "$BIN" --home "$HOME_DIR" init >/dev/null 2>&1
    (env $(preload) nohup "$BIN" --home "$HOME_DIR" run > "$HOME_DIR/run.log" 2>&1 & echo $! > "$PIDF")
    for i in $(seq 1 60); do curl -sf http://127.0.0.1:3030/status >/dev/null && { echo "sandbox up at http://127.0.0.1:3030"; exit 0; }; sleep 0.5; done
    echo "sandbox failed to start; see $HOME_DIR/run.log"; exit 1 ;;
  stop)
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true; rm -f "$PIDF"; echo "sandbox stopped" ;;
  status)
    curl -sf http://127.0.0.1:3030/status >/dev/null && echo up || echo down ;;
  *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
