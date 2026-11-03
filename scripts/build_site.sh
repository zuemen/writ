#!/usr/bin/env bash
# Assemble the site into .demo-testnet/site/. config.json contains test private keys, so it is deliberately kept only on the hosted page, not in the repo.
# Run make bounty (public key cell), make live-agent (the covered mandate) and make pool (cells for the seller flow) first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.demo-testnet/site"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$ROOT/site/index.html" "$ROOT/site/og.png" "$OUT/"
node -e '
const fs=require("fs");const d=process.argv[1];
const b=JSON.parse(fs.readFileSync(d+"/bounty.json"));const l=JSON.parse(fs.readFileSync(d+"/live.json"));const p=JSON.parse(fs.readFileSync(d+"/pool.json"));
if(!l.funder_key||!l.arbiter_key){console.error("live.json has no cover keys: run make live-agent");process.exit(1)}
if(l.contract!==p.contract||(p.asset&&l.asset!==p.asset.id)){console.error("live.json and pool.json name a different contract or asset");process.exit(1)}
fs.writeFileSync(d+"/site/config.json",JSON.stringify({rpc:p.rpc,contract:p.contract,merchant:p.merchant,relayer:p.relayer,seller:p.seller,guarantor:p.guarantor,company:p.company,asset:p.asset,cells:p.cells,
 bounty:{cell:b.cell,agent_sk:b.agent_sk,spent_link:b.spent_link},
 cover:{root:l.cell,agent_sk:l.agent_sk,links:l.links,unit:l.unit,funder_key:l.funder_key,arbiter_key:l.arbiter_key,inv1_paid_hash:l.inv1_paid_hash,dispute_secs:l.dispute_secs}}));' "$ROOT/.demo-testnet"
cd "$ROOT/app"
NODE_PATH="$ROOT/app/node_modules" npx --yes esbuild@0.25.0 "$ROOT/site/app.ts" --bundle --alias:util="$ROOT/site/util-stub.js" --format=esm --target=es2022 --platform=browser --minify --outfile="$OUT/app.js"
ls -l "$OUT"
