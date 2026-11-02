/**
 * make credit-demo —— 「誰負責」的完整故事，用真的 KERI 憑證與簽章（本機 sandbox）：
 *   1 賣方看風險卡：公司名封存，保證人具名
 *   2 agent 賒帳、賣方交貨、公司按時付款：什麼都不揭露
 *   3 下一筆公司不付：賠付自動走完金庫與保證人的質押，賣方拿到全額
 *   4 公司被凍結，不能再賒，但 agent 還在、身分還封著
 *   5 追償期滿公司仍不還：整棵樹斷電，公司名公開（LE 的簽章防止栽贓）
 * 結尾印 CREDIT_RESULT 一行給機器檢查。
 */
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { teraToGas, type KeyPairString } from "near-api-js";
import { DEMO, NEAR, as, call, fmt, readJson, view } from "./near.js";
import { A, balance, register } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const a = A();
const say = (s: string) => console.log(s);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
const seller = as(a.merchant.id, a.merchant.sk);
const guarantor = as(a.verifier.id, a.verifier.sk);

// 金庫只放一點點，賴帳時賠付才會走到保證人
const reg = await register(process.env.WRIT_CREDIT_DEPOSIT ?? "0.6");
if (!reg.ok) throw new Error("register failed: " + reg.error);
const cell = reg.cell;
const agent = as(a.writ.id, keriPrivate().agent_near_secret_key as KeyPairString);
let link = 0;
const txs: [string, string | undefined][] = [["Company registers the mandate; guarantor attested it", (reg as any).hash]];

async function order(j: number, invoice: string, dueInSecs: number) {
  link += j;
  const due_at = (nowNs() + BigInt(dueInSecs) * 1_000_000_000n).toString();
  const r = await call(agent, a.writ.id, "open_credit", { preimage: releaseLink(link), j, to: a.merchant.id, invoice_hash: sha(invoice), due_at }, { gas: teraToGas("50") });
  if (!r.value?.CreditOpened) throw new Error(`open_credit: ${JSON.stringify(r.value ?? r.error)}`);
  const id = String(r.value.CreditOpened.credit);
  txs.push([`Agent orders on credit: ${invoice}`, r.hash]);
  for (const [m, args] of [["accept_credit", { credit: id }], ["mark_delivered", { credit: id, delivery_hash: sha(`delivery ${invoice}`) }]] as const) {
    const x = await call(seller, a.writ.id, m, args, { gas: teraToGas("50") });
    if (x.error) throw new Error(`${m}: ${x.error}`);
    txs.push([`Seller ${m === "accept_credit" ? "accepts" : "marks delivered"} ${invoice}; the fee moves to the guarantor on accept`, x.hash]);
  }
  return id;
}

const card0: any = await view(a.writ.id, "risk_card", { cell });
say(`1  risk card: legal entity=${card0.legal_entity}, guarantor=${card0.guarantor}, stake=${fmt(card0.guarantor_stake)}, limit=${fmt(card0.credit_limit)}, guarantee fee=${card0.premium_bps / 100}%`);

const paid = await order(1, "INV-CREDIT-1", 3600);
const s1 = await call(agent, a.writ.id, "settle", { credit: paid }, { gas: teraToGas("50") });
txs.push(["Agent settles the first order on time; the company stays sealed", s1.hash]);
const card1: any = await view(a.writ.id, "risk_card", { cell });
say(`2  order ${paid} delivered and paid on time → ${JSON.stringify(s1.value ?? s1.error)}; legal entity=${card1.legal_entity}; record: ${card1.settled} settled`);

const unpaid = await order(8, "INV-CREDIT-2", 1);
await sleep(5000);
const s0 = await balance(a.merchant.id);
const d = await call(seller, a.writ.id, "claim_default", { credit: unpaid }, { gas: teraToGas("100") });
if (d.error) throw new Error("claim_default: " + d.error);
txs.push(["Seller claims default, paid in full", d.hash]);
const cr: any = await view(a.writ.id, "credit_of", { credit: unpaid });
const w = await call(seller, a.writ.id, "withdraw", {}, { gas: teraToGas("30") });
if (w.error) throw new Error("withdraw: " + w.error);
const got = (await balance(a.merchant.id)) - s0;
say(`3  order ${unpaid} not paid → seller claims default; guarantor's stake paid ${fmt(cr.debt)}; seller received about ${fmt(got)}`);
const guarantorPaid = BigInt(cr.debt) > 0n;

const card2: any = await view(a.writ.id, "risk_card", { cell });
link += 1;
const frozen = await call(agent, a.writ.id, "open_credit", { preimage: releaseLink(link), j: 1, to: a.merchant.id, invoice_hash: sha("INV-CREDIT-3"), due_at: (nowNs() + 3_600_000_000_000n).toString() }, { gas: teraToGas("50") });
say(`4  frozen=${card2.frozen}, legal entity=${card2.legal_entity}; next order → ${JSON.stringify(frozen.value)}`);

await sleep(Number(process.env.WRIT_RECOURSE_SECS ?? 6) * 1000 + 1000);
const e = await call(guarantor, a.writ.id, "enforce_recourse", { credit: unpaid }, { gas: teraToGas("100") });
if (e.error) throw new Error("enforce_recourse: " + e.error);
txs.push(["Recourse period over: one transaction deletes the agent's key", e.hash]);
const dead = await call(agent, a.writ.id, "spend", { preimage: releaseLink(link + 1), j: 1, to: a.merchant.id, invoice_hash: sha("x") });
const c: any = await view(a.writ.id, "get_cell", { cell });
const { lei, salt } = JSON.parse(py("verify.py", "reveal", "--amc", c.amc_said));
const framed = await call(guarantor, a.writ.id, "credit_unseal", { credit: unpaid, lei: "VICTIMCO000000000099", salt, ecr: readJson(join(DEMO, "ecr_opening.json")) }, { gas: teraToGas("50") });
const u = await call(guarantor, a.writ.id, "credit_unseal", { credit: unpaid, lei, salt, ecr: readJson(join(DEMO, "ecr_opening.json")) }, { gas: teraToGas("50") });
if (u.error) throw new Error("credit_unseal: " + u.error);
txs.push(["The company is named, checked against the commitment and the legal entity's signature", u.hash]);
txs.push(["A false company name is refused", framed.hash]);
const card3: any = await view(a.writ.id, "risk_card", { cell });
say(`5  recourse period over: key deleted (${dead.tag ?? dead.error}); naming another company → ${framed.error}; legal entity=${card3.legal_entity} (LE signature checked)`);

const sol: any = await view(a.writ.id, "solvency");
const ok = card1.legal_entity === "sealed" && !!s1.value?.CreditSettled && guarantorPaid && card2.frozen === true && card2.legal_entity === "sealed" && frozen.value?.Rejected?.reason === "FROZEN" && !!framed.error && card3.legal_entity === lei && sol.solvent === true;
console.log(`\nCREDIT_RESULT|${ok ? "PASS" : "FAIL"}|paid_on_time_sealed=${card1.legal_entity === "sealed"}|guarantor_paid=${guarantorPaid}|frozen=${card2.frozen}|revealed=${card3.legal_entity === lei}`);
void NEAR;
if (process.env.WRIT_CREDIT_REPORT && ok) {
  const rows = txs.filter(([, h]) => h).map(([t, h]) => `| ${t} | [${h}](https://testnet.nearblocks.io/txns/${h}) |`).join("\n");
  writeFileSync(process.env.WRIT_CREDIT_REPORT, `# Buying on credit, on NEAR testnet\n\nContract: [${a.writ.id}](https://testnet.nearblocks.io/address/${a.writ.id}) · generated by \`make credit-testnet\`. Real transactions; the windows are short so the story runs in about a minute.\n\n| Step | Transaction |\n|---|---|\n${rows}\n\nThe seller received ${fmt(cr.amount)}; ${fmt(cr.debt)} of it came from the guarantor's stake. Risk card afterwards: legal entity \`${card3.legal_entity}\`, guarantor \`${card3.guarantor}\`, ${card3.settled} paid, ${card3.defaults} defaulted.\n`);
}
process.exit(ok ? 0 : 1);
