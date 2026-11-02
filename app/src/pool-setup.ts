/**
 * make pool —— 替網站預先開一批真的組織樹，讓訪客不用伺服器也能走完整個流程。
 * 每一棵樹有自己的 KERI 鏈（根 → QVI → 法人 → ECR → AMC）和兩層真的 hire。預先產生：鏈節、HR 簽好的 ECR 撤銷事件。
 * 訪客按下按鈕時，瀏覽器才把它們送上鏈；交易是真的，只有鏈下的簽章是事先做好的。
 * 另建一把只能呼叫 revoke_by_kel 的 relayer 鑰匙給頁面用。
 * 結果寫到 .demo-testnet/pool.json（含私鑰，只給 hosted 頁，不進 repo）。
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { KeyPair, actions, teraToGas, type KeyPairString } from "near-api-js";
import { DEMO, NEAR, ROOT, RPC, as, call, readJson, view, writeJson } from "./near.js";
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
      actions.transfer(NEAR("1")),
      actions.addFullAccessKey(full.getPublicKey()),
      actions.addFunctionCallAccessKey(kp.getPublicKey(), a.writ.id, ["revoke_by_kel"], NEAR("0.8")),
    ],
    waitUntil: "FINAL",
  });
  pool.relayer = { id, sk: kp.toString() as KeyPairString };
  writeJson(path, pool);
  console.log(`  relayer ${id}`);
}

// PayWord 鏈：links[0] = w0，付 k 節交出 links[k]
function chain(n: number) {
  const links: Buffer[] = new Array(n + 1);
  links[n] = randomBytes(32);
  for (let k = n - 1; k >= 0; k--) links[k] = createHash("sha256").update(links[k + 1]).digest();
  return links.map((l) => l.toString("hex"));
}
const agentAcct = (sk: string) => as(a.writ.id, sk as KeyPairString);

for (let i = 0; i < COUNT; i++) {
  for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
  // 員工 → 應付帳款 agent（兩個收款對象）
  const init = py("issuer.py", "init", "--scope", `${a.merchant.id},${a.supplier.id}`, "--rail", a.acme.id, "--n", "10", "--unit", "1e22", "--daily", "10", "--days", "30");
  py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
  const reg = await register(process.env.WRIT_POOL_DEPOSIT ?? "0.75");
  if (!reg.ok) throw new Error("register failed: " + reg.error);
  const rootSk = keriPrivate().agent_near_secret_key;
  const c: any = await view(a.writ.id, "get_cell", { cell: reg.cell });

  // 應付帳款 agent → 採購 agent（只能付一個對象、6 節）
  const midKey = KeyPair.fromRandom("ed25519");
  const midChain = chain(6);
  const h1 = await call(agentAcct(rootSk), a.writ.id, "hire", {
    preimage: releaseLink(6), j: 6,
    child: { agent_pk: midKey.getPublicKey().toString(), w0: midChain[0], scope: [a.merchant.id], valid_until: c.valid_until, daily_links: 6, max_links: 3 },
  }, { gas: teraToGas("60") });
  if (!h1.value?.Hired) throw new Error("hire 1: " + JSON.stringify(h1));

  // 採購 agent → 詢價 agent（3 節）
  const leafKey = KeyPair.fromRandom("ed25519");
  const leafChain = chain(3);
  const h2 = await call(agentAcct(midKey.toString()), a.writ.id, "hire", {
    preimage: midChain[3], j: 3,
    child: { agent_pk: leafKey.getPublicKey().toString(), w0: leafChain[0], scope: [a.merchant.id], valid_until: c.valid_until, daily_links: 3, max_links: 2 },
  }, { gas: teraToGas("60") });
  if (!h2.value?.Hired) throw new Error("hire 2: " + JSON.stringify(h2));

  // HR 撤銷員工的 ECR（鏈下簽好，訪客按下去才上鏈）
  py("issuer.py", "revoke-ecr");
  const rv = readJson(join(ROOT, "keri/bundle/revocation.json"));
  pool.cells.push({
    cell: String(reg.cell),
    root: { cell: String(reg.cell), sk: rootSk, pk: reg.agent_pk },
    mid: { cell: String(h1.value.Hired.child), sk: midKey.toString(), pk: midKey.getPublicKey().toString(), next: midChain[4] },
    leaf: { cell: String(h2.value.Hired.child), sk: leafKey.toString(), pk: leafKey.getPublicKey().toString(), links: leafChain.slice(1) },
    ixn_hex: rv.ixn_hex,
    sig_hex: rv.sig_hex,
    ecr: readJson(join(DEMO, "ecr_opening.json")),
  });
  writeJson(path, pool);
  console.log(`  tree #${reg.cell} ready (${pool.cells.length} in pool)`);
}
