/**
 * make pool —— 替網站預先開一批真的委任格，讓訪客不用伺服器也能走完整個流程。
 * 每一格有自己的 KERI 鏈（根 → QVI → 法人 → ECR → AMC）。預先產生：撥給 agent 的前兩個鏈節、HR 簽好的 ECR 撤銷事件。
 * 訪客按下按鈕時，瀏覽器才把它們送上鏈；交易是真的，只有鏈下的簽章是事先做好的。
 * 另建一把只能呼叫 revoke_by_kel 的 relayer 鑰匙給頁面用。
 * 結果寫到 .demo-testnet/pool.json（含私鑰，只給 hosted 頁，不進 repo）。
 */
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { KeyPair, actions, type KeyPairString } from "near-api-js";
import { DEMO, NEAR, ROOT, RPC, as, readJson, writeJson } from "./near.js";
import { A, register } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const a = A();
const COUNT = Number(process.env.WRIT_POOL ?? 6);
const path = join(DEMO, "pool.json");
const pool: any = existsSync(path) ? readJson(path) : { rpc: RPC, contract: a.writ.id, merchant: a.merchant.id, cells: [] };

if (!pool.relayer) {
  const kp = KeyPair.fromRandom("ed25519");
  const id = `relay.${a.owner.id}`;
  const full = KeyPair.fromRandom("ed25519");
  await as(a.owner.id, a.owner.sk).signAndSendTransaction({
    receiverId: id,
    actions: [
      actions.createAccount(),
      actions.transfer(NEAR("0.6")),
      actions.addFullAccessKey(full.getPublicKey()),
      actions.addFunctionCallAccessKey(kp.getPublicKey(), a.writ.id, ["revoke_by_kel"], NEAR("0.5")),
    ],
    waitUntil: "FINAL",
  });
  pool.relayer = { id, sk: kp.toString() as KeyPairString };
  writeJson(path, pool);
  console.log(`  relayer ${id}`);
}

for (let i = 0; i < COUNT; i++) {
  for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
  const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", "10", "--unit", "1e23", "--daily", "10", "--days", "30");
  py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
  const reg = await register(process.env.WRIT_POOL_DEPOSIT ?? "0.75");
  if (!reg.ok) throw new Error("register failed: " + reg.error);
  const links = [releaseLink(1), releaseLink(2)];
  const sk = keriPrivate().agent_near_secret_key;
  py("issuer.py", "revoke-ecr");
  const rv = readJson(join(ROOT, "keri/bundle/revocation.json"));
  pool.cells.push({
    cell: String(reg.cell),
    agent_pk: reg.agent_pk,
    agent_sk: sk,
    links,
    ixn_hex: rv.ixn_hex,
    sig_hex: rv.sig_hex,
    rev_said: rv.rev_said,
    ecr: readJson(join(DEMO, "ecr_opening.json")),
  });
  writeJson(path, pool);
  console.log(`  cell #${reg.cell} ready (${pool.cells.length} in pool)`);
}
