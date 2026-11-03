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
const DEMO_COMPANY = "Demo Trading Ltd (fictional)";
const path = join(DEMO, "pool.json");
const pool: any = existsSync(path) ? readJson(path) : { rpc: RPC, contract: a.writ.id, merchant: a.merchant.id, cells: [] };

if (!pool.relayer) {
  const kp = KeyPair.fromRandom("ed25519");
  const id = `relay-${a.writ.id.split(".")[0]}.${a.owner.id}`;
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

// 訪客扮演賣方；保證人的步驟在頁面上自動化。兩把都是受限鑰匙，只能呼叫這些方法。
async function scopedKey(owner: { id: string; sk: KeyPairString }, methods: string[], allowance: string) {
  const kp = KeyPair.fromRandom("ed25519");
  await as(owner.id, owner.sk).signAndSendTransaction({
    receiverId: owner.id,
    actions: [actions.addFunctionCallAccessKey(kp.getPublicKey(), a.writ.id, methods, NEAR(allowance))],
    waitUntil: "FINAL",
  });
  return { id: owner.id, sk: kp.toString() as KeyPairString };
}
if (!pool.seller) {
  pool.seller = await scopedKey(a.merchant, ["accept_credit", "mark_delivered", "claim_default", "withdraw", "set_seller_policy"], "1.5");
  pool.guarantor = await scopedKey(a.verifier, ["enforce_recourse", "credit_unseal"], "1.5");
  pool.company = DEMO_COMPANY;
  // 賣方規則先存一條寬鬆的（押金要帶錢，鑰匙帶不了），之後訪客用受限鑰匙調整不用再付
  const sp = await call(as(a.merchant.id, a.merchant.sk), a.writ.id, "set_seller_policy", { policy: { max_amount: NEAR("1").toString(), max_tenor_secs: "86400", min_bond_bps: 0, max_defaults: 1000, guarantors: [], asset: null, max_fee_bps: 10000, arbiters: [] } }, { deposit: NEAR("0.015") });
  if (sp.error) throw new Error("set_seller_policy: " + sp.error);
  const st = await call(as(a.verifier.id, a.verifier.sk), a.writ.id, "stake", {}, { deposit: NEAR(process.env.WRIT_STAKE ?? "4") });
  if (st.error) throw new Error("stake: " + st.error);
  writeJson(path, pool);
}

for (let i = 0; i < COUNT; i++) {
  for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
  // 員工 → 應付帳款 agent（兩個收款對象）
  const init = py("issuer.py", "init", "--scope", `${a.merchant.id},${a.supplier.id}`, "--rail", a.acme.id, "--n", "20", "--unit", "2e22", "--daily", "20", "--days", "30",
    "--credit-limit", "3e23", "--bond-bps", "2500", "--premium-bps", "200", "--min-tenor", "5", "--max-tenor", "86400", "--arbiter", a.owner.id, "--contract", a.writ.id);
  py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
  // 保證金是硬性要求：開格費 0.37 + 兩次雇用 0.369 + 預算 0.12 + 單據儲存 0.007 + 費用 0.004 + 25% 保證金 0.05，再留 0.01
  const reg = await register(process.env.WRIT_POOL_DEPOSIT ?? "0.81");
  if (!reg.ok) throw new Error("register failed: " + reg.error);
  const rootSk = keriPrivate().agent_near_secret_key;
  const c: any = await view(a.writ.id, "get_cell", { cell: reg.cell });
  const { lei, salt } = JSON.parse(py("verify.py", "reveal", "--amc", c.amc_said));
  // 大單 10 節（0.2 NEAR）：根格只剩約 0.06（扣單據儲存與 2% 保證費，含 0.05 保證金），子格收回 0.12，還清前保證人仍有約 0.02 要追，揭露走得到
  const orderLinks = { small: releaseLink(7), large: releaseLink(16) };

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
    root: { cell: String(reg.cell), sk: rootSk, pk: reg.agent_pk, orders: orderLinks },
    lei,
    salt,
    mid: { cell: String(h1.value.Hired.child), sk: midKey.toString(), pk: midKey.getPublicKey().toString(), next: midChain[4] },
    leaf: { cell: String(h2.value.Hired.child), sk: leafKey.toString(), pk: leafKey.getPublicKey().toString(), links: leafChain.slice(1) },
    ixn_hex: rv.ixn_hex,
    sig_hex: rv.sig_hex,
    ecr: readJson(join(DEMO, "ecr_opening.json")),
  });
  writeJson(path, pool);
  console.log(`  tree #${reg.cell} ready (${pool.cells.length} in pool)`);
}
