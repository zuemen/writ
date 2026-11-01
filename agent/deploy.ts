/**
 * 把合約部署到 RPC 指向的鏈上的某個帳號（sandbox：test.near；testnet：你的帳號），並呼叫 new()。
 *   RPC=http://127.0.0.1:3030 CONTRACT=test.near OWNER_KEY=ed25519:... WASM=../contract/target/wasm32-unknown-unknown/release/sealed_mandate.wasm npx tsx deploy.ts
 */
import { Account, JsonRpcProvider, KeyPairSigner, teraToGas, type KeyPairString } from "near-api-js";
import { readFileSync } from "node:fs";

const RPC = process.env.RPC ?? "http://127.0.0.1:3030";
const CONTRACT = process.env.CONTRACT!;
const OWNER_KEY = process.env.OWNER_KEY! as KeyPairString;
const WASM = process.env.WASM ?? "../contract/target/wasm32-unknown-unknown/release/sealed_mandate.wasm";

const provider = new JsonRpcProvider({ url: RPC });
const owner = new Account(CONTRACT, provider, KeyPairSigner.fromSecretKey(OWNER_KEY));
const code = readFileSync(WASM);
const r = await owner.deployContract(code);
console.log("[deploy] code deployed, tx:", r.transaction.hash);
try {
  await owner.callFunction({ contractId: CONTRACT, methodName: "new", args: {}, gas: teraToGas("30") });
  console.log("[deploy] new() ✓ owner =", CONTRACT);
} catch (e) {
  console.log("[deploy] new() skipped (already initialized?)", String(e).slice(0, 120));
}
