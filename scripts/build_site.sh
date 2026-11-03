#!/usr/bin/env bash
# Assemble the site into .demo-testnet/site/. config.json contains test private keys, so it is deliberately kept only on the hosted page, not in the repo.
# Run make bounty (public key cell) and make pool (cells for the flow) first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.demo-testnet/site"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$ROOT/site/index.html" "$ROOT/site/og.png" "$OUT/"
node -e '
const fs=require("fs");const d=process.argv[1];
const b=JSON.parse(fs.readFileSync(d+"/bounty.json"));const l=JSON.parse(fs.readFileSync(d+"/live.json"));const p=JSON.parse(fs.readFileSync(d+"/pool.json"));
fs.writeFileSync(d+"/site/config.json",JSON.stringify({rpc:p.rpc,contract:p.contract,merchant:p.merchant,relayer:p.relayer,seller:p.seller,guarantor:p.guarantor,company:p.company,asset:p.asset,cells:p.cells,
 bounty:{cell:b.cell,agent_sk:b.agent_sk,spent_link:b.spent_link},live:{cell:l.cell,agent_sk:l.agent_sk,links:l.links}}));' "$ROOT/.demo-testnet"
cd "$ROOT/app"
NODE_PATH="$ROOT/app/node_modules" npx --yes esbuild@0.25.0 "$ROOT/site/app.ts" --bundle --alias:util="$ROOT/site/util-stub.js" --format=esm --target=es2022 --platform=browser --minify --outfile="$OUT/app.js"
ls -l "$OUT"
