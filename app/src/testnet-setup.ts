/**
 * make testnet —— 把同一個故事搬到 NEAR testnet（需要本人同意才執行：會簽 testnet 交易）。
 * 帳號由 testnet faucet（helper.testnet.near.org）建立，每個約 10 NEAR 測試幣，私鑰寫在 .demo-testnet/（.gitignore）。
 */
import { KeyPair, type KeyPairString } from "near-api-js";
import { readFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { DEMO, ROOT, as, call, writeJson, readJson, provider } from "./near.js";
import { py } from "./keri.js";

const tag = process.env.WRIT_TESTNET_TAG ?? `writ${Date.now().toString(36)}`;
const names = ["writ", "verifier", "acme", "merchant", "attacker", "regulator"];
const path = join(DEMO, "accounts.json");
const accts: Record<string, { id: string; sk: KeyPairString }> = existsSync(path) ? readJson(path) : {};

for (const n of names) {
  if (accts[n]) continue;
  const id = `${tag}-${n}.testnet`;
  const kp = KeyPair.fromRandom("ed25519");
  const res = await fetch("https://helper.testnet.near.org/account", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ newAccountId: id, newAccountPublicKey: kp.getPublicKey().toString() }),
  });
  if (!res.ok) throw new Error(`faucet refused ${id}: ${res.status} ${await res.text()}`);
  accts[n] = { id, sk: kp.toString() as KeyPairString };
  writeJson(path, accts);
  console.log(`  created ${id}`);
  await new Promise((r) => setTimeout(r, 1500));
}

const writ = as(accts.writ.id, accts.writ.sk);
const wasm = readFileSync(join(ROOT, "contract/res/writ.wasm"));
const d = await writ.deployContract(wasm);
console.log(`  deployed ${accts.writ.id} tx ${d.transaction.hash}`);
for (const [m, args] of [
  ["new", { unseal_delay_secs: 10 }],
  ["set_supervisor", { account: accts.regulator.id, enabled: true }],
  ["set_verifier", { account: accts.verifier.id, pk_hex: py("verify.py", "keygen", "--force").trim() }],
] as const) {
  const r = await call(writ, accts.writ.id, m, args);
  if (r.error) throw new Error(`${m}: ${r.error}`);
}
rmSync(join(ROOT, "keri/.keystore"), { recursive: true, force: true });
rmSync(join(ROOT, "keri/bundle"), { recursive: true, force: true });
rmSync(join(ROOT, "keri/registrar"), { recursive: true, force: true });
const init = py("issuer.py", "init", "--scope", accts.merchant.id, "--rail", accts.acme.id, "--n", "50", "--unit", "1e23", "--daily", "20", "--days", "30");
py("verify.py", "pin", "--le", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).le);
console.log("  mock vLEI ecosystem issued for", accts.acme.id);
void provider;
