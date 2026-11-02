#!/usr/bin/env bash
# 組出網站到 .demo-testnet/site/。config.json 含測試用私鑰，故意只放在 hosted 頁，不進 repo。
# 需要先跑過 make bounty（鑰匙公開格）與 make pool（走流程用的格）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.demo-testnet/site"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$ROOT/site/index.html" "$ROOT/site/og.png" "$OUT/"
node -e '
const fs=require("fs");const d=process.argv[1];
const b=JSON.parse(fs.readFileSync(d+"/bounty.json"));const p=JSON.parse(fs.readFileSync(d+"/pool.json"));
fs.writeFileSync(d+"/site/config.json",JSON.stringify({rpc:p.rpc,contract:p.contract,merchant:p.merchant,relayer:p.relayer,cells:p.cells,
 bounty:{cell:b.cell,agent_sk:b.agent_sk,spent_link:b.spent_link}}));' "$ROOT/.demo-testnet"
cd "$ROOT/app"
NODE_PATH="$ROOT/app/node_modules" npx --yes esbuild@0.25.0 "$ROOT/site/app.ts" --bundle --alias:util="$ROOT/site/util-stub.js" --format=esm --target=es2022 --platform=browser --minify --outfile="$OUT/app.js"
ls -l "$OUT"
