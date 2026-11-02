/**
 * 本機 sandbox 上的一次性布置（make demo-setup）：
 *   1. 用 sandbox 根帳號 test.near 建五個帳號：writ（合約）、verifier、acme（法人金庫）、merchant、attacker
 *   2. 部署 writ.wasm、new()、把驗證者公鑰登記進白名單
 *   3. 重建 mock vLEI 生態系（keri/.keystore）：LE → ECR → human → AMC → agent（委派 AID）
 * 私鑰全部寫在 .demo/（.gitignore），只用於本機 sandbox。
 */
import { KeyPair, actions, type KeyPairString } from "near-api-js";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { NEAR, ROOT, DEMO, as, call, readJson, writeJson, provider } from "./near.js";
import { py } from "./keri.js";

const ROOTACC = "test.near";
const rootKey = readJson(join(ROOT, ".sandbox", "validator_key.json")).secret_key as KeyPairString;
const root = as(ROOTACC, rootKey);

const plan: Record<string, string> = { writ: "60", verifier: "10", acme: "100", merchant: "10", attacker: "10", regulator: "10" };
const accts: Record<string, { id: string; sk: KeyPairString }> = {};

for (const [name, amt] of Object.entries(plan)) {
  const id = `${name}.${ROOTACC}`;
  const kp = KeyPair.fromRandom("ed25519");
  await root.signAndSendTransaction({
    receiverId: id,
    actions: [actions.createAccount(), actions.transfer(NEAR(amt)), actions.addFullAccessKey(kp.getPublicKey())],
    waitUntil: "FINAL",
  });
  accts[name] = { id, sk: kp.toString() as KeyPairString };
  console.log(`  account ${id.padEnd(22)} ${amt} NEAR`);
}
writeJson(join(DEMO, "accounts.json"), accts);

const writ = as(accts.writ.id, accts.writ.sk);
const wasm = readFileSync(join(ROOT, "contract/res/writ.wasm"));
const d = await writ.deployContract(wasm);
console.log(`  deployed writ.wasm (${wasm.length} bytes) tx ${d.transaction.hash}`);
await call(writ, accts.writ.id, "new", { unseal_delay_secs: Number(process.env.UNSEAL_DELAY ?? 10) });
await call(writ, accts.writ.id, "set_supervisor", { account: accts.regulator.id, enabled: true });

const vpk = py("verify.py", "keygen", "--force").trim();
const r = await call(writ, accts.writ.id, "set_verifier", { account: accts.verifier.id, pk_hex: vpk });
if (r.error) throw new Error(r.error);
console.log(`  verifier ${accts.verifier.id} whitelisted (pk ${vpk.slice(0, 16)}…)`);

rmSync(join(ROOT, "keri/.keystore"), { recursive: true, force: true });
rmSync(join(ROOT, "keri/bundle"), { recursive: true, force: true });
const out = py("issuer.py", "init", "--scope", accts.merchant.id, "--rail", accts.acme.id,
  "--n", "50", "--unit", "1e23", "--daily", "20", "--days", "30");
const st = JSON.parse(out.slice(out.indexOf("{"), out.lastIndexOf("}") + 1));
console.log(`  KERI: LE ${st.le.slice(0, 12)}… → ECR → human ${st.human.slice(0, 12)}… → AMC → agent ${st.agent.slice(0, 12)}… (delegated)`);
console.log(`  agent KERI key = NEAR key ${st.agent_near_pk}`);
void provider;
