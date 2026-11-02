#!/usr/bin/env bash
# 組出「鑰匙公開」頁到 .demo-testnet/site/。config.json 含 agent 私鑰，故意只放在 hosted 頁，不進 repo。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.demo-testnet/site"
mkdir -p "$OUT"
cp "$ROOT/site/index.html" "$OUT/index.html"
cp "$ROOT/.demo-testnet/bounty.json" "$OUT/config.json"
cd "$ROOT/app"
NODE_PATH="$ROOT/app/node_modules" npx --yes esbuild@0.25.0 "$ROOT/site/app.ts" --bundle --alias:util="$ROOT/site/util-stub.js" --format=esm --target=es2022 --platform=browser --minify --outfile="$OUT/app.js"
ls -l "$OUT"
