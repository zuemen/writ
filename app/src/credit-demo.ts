/**
 * make credit-demo: the full "who is responsible" story, with real KERI credentials and signatures (local sandbox):
 *   1 Seller sees the risk card: company name sealed, guarantor named
 *   1b Seller's rule rejects the order and reports the reason; seller adjusts the rule, order stands
 *   2 Agent buys on credit, seller delivers, company pays on time: nothing is disclosed
 *   3 Next one the company does not pay: payout runs through the vault and the guarantor's stake automatically, seller gets the full amount
 *   4 Company is frozen and cannot buy on credit again, but the agent remains and identity stays sealed
 *   5 Company still does not repay after the recovery period: the whole tree is cut off, company name is made public (the LE's signature prevents framing)
 * Prints one CREDIT_RESULT line at the end for machine checking.
 */
import { createHash } from "node:crypto";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { teraToGas, type KeyPairString } from "near-api-js";
import { DEMO, NEAR, ROOT, as, call, fmt, readJson, view } from "./near.js";
import { A, balance, checkOrder, register, setSellerPolicy } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const a = A();
// Against testnet: open a fresh credential (the ECR left by other flows is revoked). No dedicated arbiter account, use the owner
const LIVE = !!process.env.WRIT_CREDIT_REPORT;
if (LIVE) {
  for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
  const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", "20", "--unit", "1e23", "--daily", "20", "--days", "30",
    "--credit-limit", "1e24", "--bond-bps", "0", "--premium-bps", "200", "--min-tenor", "0", "--max-tenor", "86400", "--arbiter", a.owner.id, "--contract", a.writ.id);
  py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
}
const say = (s: string) => console.log(s);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
const seller = as(a.merchant.id, a.merchant.sk);
const guarantor = as(a.verifier.id, a.verifier.sk);

// The vault holds only a little, so a default payout reaches the guarantor
const reg = await register(process.env.WRIT_CREDIT_DEPOSIT ?? "0.6");
if (!reg.ok) throw new Error("register failed: " + reg.error);
const cell = reg.cell;
const agent = as(a.writ.id, keriPrivate().agent_near_secret_key as KeyPairString);
let link = 0;
const txs: [string, string | undefined][] = [["Company registers the mandate; guarantor attested it", (reg as any).hash]];

async function open(j: number, invoice: string, dueInSecs: number) {
  link += j;
  const due_at = (nowNs() + BigInt(dueInSecs) * 1_000_000_000n).toString();
  const r = await call(agent, a.writ.id, "open_credit", { preimage: releaseLink(link), j, to: a.merchant.id, invoice_hash: sha(invoice), due_at }, { gas: teraToGas("50") });
  if (!r.value?.CreditOpened) throw new Error(`open_credit: ${JSON.stringify(r.value ?? r.error)}`);
  const id = String(r.value.CreditOpened.credit);
  txs.push([`Agent orders on credit: ${invoice}`, r.hash]);
  return id;
}
async function acceptAndDeliver(id: string, invoice: string) {
  for (const [m, args] of [["accept_credit", { credit: id }], ["mark_delivered", { credit: id, delivery_hash: sha(`delivery ${invoice}`) }]] as const) {
    const x = await call(seller, a.writ.id, m, args, { gas: teraToGas("50") });
    if (x.error) throw new Error(`${m}: ${x.error}`);
    txs.push([m === "accept_credit" ? `Seller accepts ${invoice}; the fee moves to the guarantor` : `Seller marks ${invoice} delivered`, x.hash]);
  }
  return id;
}
async function order(j: number, invoice: string, dueInSecs: number) {
  return acceptAndDeliver(await open(j, invoice, dueInSecs), invoice);
}

const card0: any = await view(a.writ.id, "risk_card", { cell });
say(`1  risk card: legal entity=${card0.legal_entity}, guarantor=${card0.guarantor}, stake=${fmt(card0.guarantor_stake)}, limit=${fmt(card0.credit_limit)}, guarantee fee=${card0.premium_bps / 100}%`);

// Seller rule: require a 25% bond, 0.05 NEAR per order. This company's terms have no bond, so the order does not fit and the reason is returned
const strict = { max_amount: NEAR("0.05").toString(), max_tenor_secs: "7200", min_bond_bps: 2500, max_defaults: 0, guarantors: [] as string[], asset: null, max_fee_bps: 500, arbiters: [] as string[] };
const set1 = await setSellerPolicy(strict);
if (set1.error) throw new Error("set_seller_policy: " + set1.error);
txs.push(["Seller sets its credit rule", set1.hash]);
const paid = await open(1, "INV-CREDIT-1", 3600);
const refused: any = await checkOrder(paid);
const tried = await call(seller, a.writ.id, "accept_credit", { credit: paid }, { gas: teraToGas("50") });
txs.push(["The order breaks the seller's rule, so accepting it is refused", tried.hash]);
const set2 = await setSellerPolicy({ ...strict, max_amount: NEAR("1").toString(), min_bond_bps: 0 });
if (set2.error) throw new Error("set_seller_policy: " + set2.error);
txs.push(["Seller adjusts the rule", set2.hash]);
const allowed: any = await checkOrder(paid);
await acceptAndDeliver(paid, "INV-CREDIT-1");
const shipped = allowed.ok === true;
say(`1b seller rule → ${refused.reasons.join(", ")}; accept → ${tried.error}; rule adjusted → ok=${allowed.ok}, order ${paid} accepted`);

const s1 = await call(agent, a.writ.id, "settle", { credit: paid }, { gas: teraToGas("50") });
txs.push(["Agent settles the first order on time; the company stays sealed", s1.hash]);
const card1: any = await view(a.writ.id, "risk_card", { cell });
say(`2  order ${paid} delivered and paid on time → ${JSON.stringify(s1.value ?? s1.error)}; legal entity=${card1.legal_entity}; record: ${card1.settled} settled`);

// On testnet it takes several seconds from computing the due date to landing on chain, so give the due date some slack; wait past the due date and the 3-second acceptance period
const dueSecs = LIVE ? 30 : 1;
const placed = Date.now();
const unpaid = await order(8, "INV-CREDIT-2", dueSecs);
await sleep(Math.max(5000, placed + dueSecs * 1000 + 3000 - Date.now(), 5000));
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
const ruleOk = refused.ok === false && refused.reasons.includes("BOND_TOO_LOW") && String(tried.error).startsWith("POLICY:") && shipped;
const ok = ruleOk && card1.legal_entity === "sealed" && !!s1.value?.CreditSettled && guarantorPaid && card2.frozen === true && card2.legal_entity === "sealed" && frozen.value?.Rejected?.reason === "FROZEN" && !!framed.error && card3.legal_entity === lei && sol.solvent === true;
console.log(`\nCREDIT_RESULT|${ok ? "PASS" : "FAIL"}|rule_refused_then_shipped=${ruleOk}|paid_on_time_sealed=${card1.legal_entity === "sealed"}|guarantor_paid=${guarantorPaid}|frozen=${card2.frozen}|revealed=${card3.legal_entity === lei}`);
void NEAR;
if (process.env.WRIT_CREDIT_REPORT && ok) {
  const rows = txs.filter(([, h]) => h).map(([t, h]) => `| ${t} | [${h}](https://testnet.nearblocks.io/txns/${h}) |`).join("\n");
  writeFileSync(process.env.WRIT_CREDIT_REPORT, `# Buying on credit, on NEAR testnet\n\nContract: [${a.writ.id}](https://testnet.nearblocks.io/address/${a.writ.id}) · generated by \`make credit-testnet\`. Real transactions; the windows are short so the story runs in about a minute.\n\n| Step | Transaction |\n|---|---|\n${rows}\n\nThe seller received ${fmt(cr.amount)}; ${fmt(cr.debt)} of it came from the guarantor's stake. Risk card afterwards: legal entity \`${card3.legal_entity}\`, guarantor \`${card3.guarantor}\`, ${card3.settled} paid, ${card3.defaults} defaulted.\n`);
}
process.exit(ok ? 0 : 1);
