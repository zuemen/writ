#!/usr/bin/env bash
# make verify: one command reproduces every claim and prints a scorecard. For machine first-pass review and for those who want to check themselves.
# Touches only the local sandbox; at the end reads the public testnet state once (read-only, signs no transaction).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG="$(mktemp -d)"
RPC="https://test.rpc.fastnear.com"
CONTRACT="writ-net30.testnet"
fail=0
row() { printf '%-34s %-6s %s\n' "$1" "$2" "$3"; [ "$2" = "PASS" ] || [ "$2" = "SKIP" ] || fail=1; }

make setup > "$LOG/setup.log" 2>&1; s_setup=$?
make test > "$LOG/test.log" 2>&1; s_test=$?
make demo > "$LOG/demo.log" 2>&1; s_demo=$?
make keri-check > "$LOG/keri.log" 2>&1; s_keri=$?
make credit-demo > "$LOG/credit.log" 2>&1; s_credit=$?

echo
echo "WRIT VERIFY"
row "build" "$([ $s_setup = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 -E '^[0-9a-f]{64} ' "$LOG/setup.log" | cut -c1-16) wasm sha256 (prefix)"
row "attack bench (make test)" "$([ $s_test = 0 ] && echo PASS || echo FAIL)" "$(head -1 docs/bench.md | tr -d '*')"
row "unit + bench tests" "$([ $s_test = 0 ] && echo PASS || echo FAIL)" "$(grep -E '^test result' /tmp/writ_bench.log | tail -1 | cut -c1-40)"
row "end-to-end story (make demo)" "$([ $s_demo = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 DEMO_RESULT "$LOG/demo.log" | cut -c1-90)"
row "who pays (make credit-demo)" "$([ $s_credit = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 CREDIT_RESULT "$LOG/credit.log" | cut -c1-90)"
row "credential chain (make keri-check)" "$([ $s_keri = 0 ] && echo PASS || echo FAIL)" "$(awk '/verify.py check/{f=1} /test_forgeries/{f=0} f' "$LOG/keri.log" | grep -c '^✓') checks on official vLEI schemas"
row "forged credentials refused" "$([ $s_keri = 0 ] && echo PASS || echo FAIL)" "$(grep -m1 KERI_FORGERIES "$LOG/keri.log")"

# Public testnet: the contract account should have no full-access key (read-only)
keys="$(curl -sS -m 20 -X POST -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$CONTRACT\"}}" "$RPC" 2>/dev/null)"
if [ -z "$keys" ]; then
  row "testnet contract keys" "SKIP" "RPC not reachable"
else
  full="$(printf '%s' "$keys" | grep -o 'FullAccess' | wc -l | tr -d ' ')"
  row "testnet contract keys" "$([ "$full" = 0 ] && echo PASS || echo FAIL)" "$full full-access keys on $CONTRACT"
fi
[ -s docs/testnet.md ] && [ -s docs/testnet-credit.md ] && [ -s docs/testnet-usdc.md ] && [ -s docs/attack-live.md ] && ev=PASS || ev=FAIL
row "recorded evidence present" "$ev" "docs/testnet.md docs/testnet-credit.md docs/testnet-usdc.md docs/attack-live.md"
echo
if [ $fail = 0 ]; then echo "VERIFY_RESULT|PASS"; else echo "VERIFY_RESULT|FAIL (logs in $LOG)"; fi
exit $fail
