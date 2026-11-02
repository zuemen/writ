#!/usr/bin/env bash
# make verify —— 一個指令重現所有主張，最後印一張成績單。給機器初審與想自己查的人。
# 只碰本機 sandbox；最後讀一次公開的 testnet 狀態（只讀，不簽交易）。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG="$(mktemp -d)"
RPC="https://test.rpc.fastnear.com"
CONTRACT="writ-mandate-writ.testnet"
fail=0
row() { printf '%-34s %-6s %s\n' "$1" "$2" "$3"; [ "$2" = "PASS" ] || [ "$2" = "SKIP" ] || fail=1; }

make setup > "$LOG/setup.log" 2>&1; s_setup=$?
make test > "$LOG/test.log" 2>&1; s_test=$?
make demo > "$LOG/demo.log" 2>&1; s_demo=$?
make keri-check > "$LOG/keri.log" 2>&1; s_keri=$?

echo
echo "WRIT VERIFY"
row "build" "$([ $s_setup = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 -E '^[0-9a-f]{64} ' "$LOG/setup.log" | cut -c1-16) wasm sha256 (prefix)"
row "attack bench (make test)" "$([ $s_test = 0 ] && echo PASS || echo FAIL)" "$(head -1 docs/bench.md | tr -d '*')"
row "unit + bench tests" "$([ $s_test = 0 ] && echo PASS || echo FAIL)" "$(grep -E '^test result' /tmp/writ_bench.log | tail -1 | cut -c1-40)"
row "end-to-end story (make demo)" "$([ $s_demo = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 DEMO_RESULT "$LOG/demo.log" | cut -c1-90)"
row "credential chain (make keri-check)" "$([ $s_keri = 0 ] && echo PASS || echo FAIL)" "$(awk '/verify.py check/{f=1} /test_forgeries/{f=0} f' "$LOG/keri.log" | grep -c '^✓') checks on official vLEI schemas"
row "forged credentials refused" "$([ $s_keri = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 KERI_FORGERIES "$LOG/keri.log")"

# 公開 testnet：合約帳號不該有 full-access key（只讀）
keys="$(curl -sS -m 20 -X POST -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$CONTRACT\"}}" "$RPC" 2>/dev/null)"
if [ -z "$keys" ]; then
  row "testnet contract keys" "SKIP" "RPC not reachable"
else
  full="$(printf '%s' "$keys" | grep -o 'FullAccess' | wc -l | tr -d ' ')"
  row "testnet contract keys" "$([ "$full" = 0 ] && echo PASS || echo FAIL)" "$full full-access keys on $CONTRACT"
fi
[ -s docs/testnet.md ] && [ -s docs/testnet-usdc.md ] && [ -s docs/attack-live.md ] && ev=PASS || ev=FAIL
row "recorded evidence present" "$ev" "docs/testnet.md docs/testnet-usdc.md docs/attack-live.md"
echo
if [ $fail = 0 ]; then echo "VERIFY_RESULT|PASS"; else echo "VERIFY_RESULT|FAIL (logs in $LOG)"; fi
exit $fail
