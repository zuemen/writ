/**
 * make credit-usdc-demo —— 信用改用穩定幣：本機 ft-mock（6 位小數，當成 USDC），賣方付保證費。只碰本機 sandbox。
 *   1 風險卡：資產、NEAR 準備、保證金、誰付費
 *   2 賣方規則拒單 → 調整規則 → 接受
 *   3 用量單：上限 5、實際 4，賣方實收扣掉保證費
 *   4 下一筆不付：金庫與保證金先賠，不足的由保證人的代幣質押賠
 *   5 公司用代幣還保證人，解凍；帳上總額等於合約的代幣餘額
 * 結尾印 CREDIT_USDC_RESULT 一行給機器檢查。
 */
import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { KeyPair, actions, teraToGas, type KeyPairString } from "near-api-js";
import { NEAR, ROOT, as, call, readJson, view } from "./near.js";
import { A, checkOrder, register, setSellerPolicy } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const a = A();
const say = (s: string) => console.log(s);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
const USD = 1_000_000n;
const usd = (v: string | bigint) => (Number(BigInt(v)) / 1e6).toFixed(2) + " USDC";

// ---- 本機的「USDC」：部署 contract/ft-mock
const ROOTACC = "test.near";
const root = as(ROOTACC, readJson(join(ROOT, ".sandbox", "validator_key.json")).secret_key as KeyPairString);
const usdc = `usdc.${ROOTACC}`;
const kp = KeyPair.fromRandom("ed25519");
await root.signAndSendTransaction({
  receiverId: usdc,
  actions: [actions.createAccount(), actions.transfer(NEAR("10")), actions.addFullAccessKey(kp.getPublicKey()), actions.deployContract(readFileSync(join(ROOT, "contract/res/ft_mock.wasm")))],
  waitUntil: "FINAL",
});
const acme = as(a.acme.id, a.acme.sk);
const tokenAcct = as(usdc, kp.toString() as KeyPairString);
const init0 = await call(tokenAcct, usdc, "new", { owner_id: a.acme.id, total_supply: (1_000_000n * USD).toString() }, { gas: teraToGas("30") });
if (init0.error) throw new Error("token new: " + init0.error);
for (const who of [a.writ.id, a.merchant.id, a.verifier.id]) {
  const r = await call(acme, usdc, "storage_deposit", { account_id: who }, { deposit: NEAR("0.01"), gas: teraToGas("30") });
  if (r.error) throw new Error("storage_deposit: " + r.error);
}
const bal = async (who: string) => BigInt((await view(usdc, "ft_balance_of", { account_id: who })) as string);
async function ftCall(from: string, sk: KeyPairString, amount: bigint, msg: string) {
  const r = await call(as(from, sk), usdc, "ft_transfer_call", { receiver_id: a.writ.id, amount: amount.toString(), msg }, { deposit: 1n, gas: teraToGas("150") });
  if (r.error) throw new Error(`ft_transfer_call ${msg}: ${r.error}`);
  return r;
}

// ---- 憑證：信用條款簽進 AMC 與 attestation（計價資產、賣方付費、單一賣方上限）
for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", "20", "--unit", USD.toString(), "--daily", "20", "--days", "30",
  "--asset", usdc, "--credit-limit", (20n * USD).toString(), "--bond-bps", "2500", "--premium-bps", "200", "--fee-payer", "Seller", "--seller-cap-bps", "5000",
  "--min-tenor", "0", "--max-tenor", "86400", "--arbiter", a.arbiter.id, "--contract", a.writ.id);
py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
const reg = await register("1");
if (!reg.ok) throw new Error("register failed: " + reg.error);
const cell = reg.cell;
const agent = as(a.writ.id, keriPrivate().agent_near_secret_key as KeyPairString);
const seller = as(a.merchant.id, a.merchant.sk);

// 公司入金 6 USDC，保證人質押 100 USDC（都走 ft_transfer_call）
await ftCall(a.acme.id, a.acme.sk, 6n * USD, String(cell));
const toV = await call(acme, usdc, "ft_transfer", { receiver_id: a.verifier.id, amount: (100n * USD).toString() }, { deposit: 1n });
if (toV.error) throw new Error("ft_transfer: " + toV.error);
await ftCall(a.verifier.id, a.verifier.sk, 100n * USD, "stake");

const card: any = await view(a.writ.id, "risk_card", { cell });
say(`1  risk card: asset=${card.asset}, stake=${usd(card.guarantor_stake)}, bond=${card.bond_bps / 100}%, fee=${card.premium_bps / 100}% per 30 days paid by ${card.fee_payer}, single-seller cap=${card.seller_cap_bps / 100}%, NEAR reserve kept for storage=${(Number(BigInt(card.near_reserve) / 10n ** 18n) / 1e6).toFixed(3)} NEAR`);

let link = 0;
async function open(j: number, invoice: string, dueInSecs: number) {
  link += j;
  const due_at = (nowNs() + BigInt(dueInSecs) * 1_000_000_000n).toString();
  const r = await call(agent, a.writ.id, "open_credit", { preimage: releaseLink(link), j, to: a.merchant.id, invoice_hash: sha(invoice), due_at }, { gas: teraToGas("50") });
  if (!r.value?.CreditOpened) throw new Error(`open_credit: ${JSON.stringify(r.value ?? r.error)}`);
  return String(r.value.CreditOpened.credit);
}
async function seller_(m: string, args: object) {
  const x = await call(seller, a.writ.id, m, args, { gas: teraToGas("100") });
  if (x.error) throw new Error(`${m}: ${x.error}`);
}

// ---- 賣方規則
const rule = (minBond: number) => ({ max_amount: (10n * USD).toString(), max_tenor_secs: "7200", min_bond_bps: minBond, max_defaults: 0, guarantors: [] as string[], asset: usdc, max_fee_bps: 500, arbiters: [] as string[] });
const set1 = await setSellerPolicy(rule(5000));
if (set1.error) throw new Error("set_seller_policy: " + set1.error);
const k1 = await open(5, "INV-USDC-1", 3600);
const refused: any = await checkOrder(k1);
const tried = await call(seller, a.writ.id, "accept_credit", { credit: k1 }, { gas: teraToGas("50") });
const set2 = await setSellerPolicy(rule(2500));
if (set2.error) throw new Error("set_seller_policy: " + set2.error);
const allowed: any = await checkOrder(k1);
await seller_("accept_credit", { credit: k1 });
say(`2  seller rule asks 50% bond → ${refused.reasons.join(", ")}; accept → ${tried.error}; rule set to 25% → ok=${allowed.ok}; order ${k1} accepted`);

// ---- 用量單
await seller_("mark_delivered", { credit: k1, delivery_hash: sha("delivery 1"), final_amount: (4n * USD).toString() });
const s1 = await call(agent, a.writ.id, "settle", { credit: k1 }, { gas: teraToGas("50") });
if (!s1.value?.CreditSettled) throw new Error("settle: " + JSON.stringify(s1.value ?? s1.error));
const m0 = await bal(a.merchant.id);
await seller_("withdraw", { asset: usdc });
const got = (await bal(a.merchant.id)) - m0;
const st1: any = await view(a.writ.id, "stake_of", { account: a.verifier.id, asset: usdc });
say(`3  usage order: limit 5, billed 4, company paid 4; seller received ${usd(got)}, guarantor earned ${usd(st1.earned)}`);

// ---- 違約
const k2 = await open(8, "INV-USDC-2", 1);
await seller_("accept_credit", { credit: k2 });
await seller_("mark_delivered", { credit: k2, delivery_hash: sha("delivery 2") });
await sleep(5000); // 過到期日與 3 秒驗收期
await seller_("claim_default", { credit: k2 });
const cr: any = await view(a.writ.id, "credit_of", { credit: k2 });
const claim2 = BigInt((await view(a.writ.id, "claimable_of", { account: a.merchant.id, asset: usdc })) as string);
const frozen: any = await view(a.writ.id, "risk_card", { cell });
say(`4  order ${k2} not paid: vault and bond paid first, the token stake paid ${usd(cr.debt)}; seller is owed ${usd(claim2)}; frozen=${frozen.frozen}`);

// ---- 還債
await ftCall(a.acme.id, a.acme.sk, BigInt(cr.debt), `reimburse:${k2}`);
const after: any = await view(a.writ.id, "risk_card", { cell });
const book: any = await view(a.writ.id, "guarantor_book", { account: a.verifier.id, asset: usdc });
const total = BigInt((await view(a.writ.id, "token_total", { asset: usdc })) as string);
const held = await bal(a.writ.id);
const sol: any = await view(a.writ.id, "solvency");
say(`5  company repaid in USDC: frozen=${after.frozen}; book: earned ${usd(book.earned)}, claims ${usd(book.claims_paid)}, recovered ${usd(book.recovered)}, net loss ${usd(book.net_loss)}; books ${usd(total)} = token balance ${usd(held)}`);

const fee1 = (4n * USD * 200n) / 10_000n;
const fee2 = (8n * USD * 200n) / 10_000n;
const ok = refused.reasons.includes("BOND_TOO_LOW") && String(tried.error).includes("POLICY:BOND_TOO_LOW") && allowed.ok === true && got === 4n * USD - fee1 && BigInt(st1.earned) === fee1
  && BigInt(cr.debt) > 0n && claim2 === 8n * USD - fee2 && frozen.frozen === true && after.frozen === false && book.net_loss === "0" && total === held && sol.solvent === true;
console.log(`\nCREDIT_USDC_RESULT|${ok ? "PASS" : "FAIL"}|rule_refused=${String(tried.error)}|seller_received=${got}|guarantor_paid=${cr.debt}|repaid=${after.frozen === false}|books_match=${total === held}`);
process.exit(ok ? 0 : 1);
