/**
 * A Sputnik DAO as the cover arbiter, on a deployed contract. The contract only checks predecessor == arbiter, so any account can rule, including a DAO.
 * Testnet only. Run with NEAR_RPC and WRIT_DEMO_DIR pointing at the testnet accounts file. Never prints a key.
 *   create   acme creates a DAO on the factory; the council is three demo accounts that are not the company, the guarantor, the seller or the owner
 *   mandate  a small new NEAR mandate naming the DAO as arbiter: cover activated, two payments made
 *   rule     claim 1: propose, vote, the DAO's resolve_claim upholds. Claim 2: the same, Deny. Reads cover_of and stake_of around each
 *   cleanup  the DAO calls void_cover on the denied claim, so the test lock does not sit on the guarantor's stake until the mandate expires
 *   all      all of the above
 * State (no keys) goes to <demo dir>/dao.json. Only the cell recorded there is ever acted on. Move that file away to start again: a new DAO costs 6 NEAR.
 * issuer.py and verify.py overwrite keri/ and three files in the demo dir; those three are restored after register, so the mandates already on chain keep their records.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { teraToGas } from "near-api-js";
import { DEMO, NEAR, ROOT, as, call, fmt, readJson, view, writeJson } from "./near.js";
import { A, activateCover, coverOf, fileClaim, pay, paymentOf, register } from "./flow.js";
import { py } from "./keri.js";
import { contextHash } from "./sdk.js";

const FACTORY = process.env.WRIT_DAO_FACTORY ?? "sputnikv2.testnet";
const DAO_DEPOSIT = "6"; // the factory deploys the code to the new account, about 545 KB of storage; recent testnet DAOs hold 6 NEAR
const BOND = NEAR("1"); // the default policy's proposal bond; add_proposal requires exactly this, and it comes back when the proposal executes
const RESOLVE_GAS = teraToGas("60");
const STATE = join(DEMO, "dao.json");
const a = A();
const COUNCIL = ["arbiter", "regulator", "supplier"]; // 3 members, threshold 1/2: two votes pass
const say = (s: string) => console.log(s);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const link = (h?: string) => (h ? `https://testnet.nearblocks.io/txns/${h}` : "(no hash)");
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64");
const signer = (n: string) => as(a[n].id, a[n].sk);

type State = { dao?: string; council?: string[]; cell?: string; steps: { step: string; tx?: string; note?: string }[] };
const load = (): State => (existsSync(STATE) ? readJson(STATE) : { steps: [] });
const save = (s: State) => writeJson(STATE, s);
const record = (s: State, step: string, tx?: string, note?: string) => {
  s.steps.push({ step, tx, note });
  save(s);
  say(`  ${step}${note ? `: ${note}` : ""}  ${link(tx)}`);
};

const INVOICES: Record<string, string> = {
  "DAO-1": "DAO-1  duplicate of an order already paid. Pay to merchant.",
  "DAO-2": "DAO-2  a real purchase of an open order. Pay to merchant.",
};
const context = (id: string) => contextHash(INVOICES[id], "dao-arbiter-demo", { tool: "pay", invoice: id, links: 1, to: a.merchant.id });

async function create(s: State) {
  if (s.dao) return say(`DAO already recorded: ${s.dao}`);
  const council = COUNCIL.map((n) => a[n].id);
  const name = `writ-arbiter-${Date.now().toString(36)}`;
  const args = { config: { name, purpose: "Writ cover arbiter test. Demo accounts vote; this is not an independent arbitrator.", metadata: "" }, policy: council };
  const r = await call(signer("acme"), FACTORY, "create", { name, args: b64(args) }, { deposit: NEAR(DAO_DEPOSIT), gas: teraToGas("300") });
  if (r.error) throw new Error(`create failed: ${r.error}, tx ${r.hash}`);
  // The deployed factory's create returns nothing, and a failed creation refunds without failing the transaction. The factory's list is the answer.
  const listed = ((await view(FACTORY, "get_dao_list")) as string[]).includes(`${name}.${FACTORY}`);
  if (!listed) throw new Error(`the factory does not list the DAO, tx ${r.hash}`);
  s.dao = `${name}.${FACTORY}`;
  s.council = council;
  record(s, "DAO created", r.hash, s.dao);
  const pol: any = await view(s.dao, "get_policy");
  say(`  council ${council.join(", ")}; threshold ${JSON.stringify(pol.default_vote_policy.threshold)}; bond ${fmt(pol.proposal_bond)}`);
}

async function mandate(s: State) {
  if (!s.dao) throw new Error("no DAO: run create first");
  if (s.cell) return say(`mandate already recorded: #${s.cell}`);
  const stake: any = await view(a.writ.id, "stake_of", { account: a.verifier.id });
  const limit = NEAR("0.1");
  const free = BigInt(stake.amount) - BigInt(stake.exposure);
  say(`guarantor's free NEAR stake ${fmt(free)}, limit needed ${fmt(limit)}`);
  if (free < limit) throw new Error("not enough free stake");

  const kept = ["ecr_opening.json", "verifier_records.json", "verifier_policy.json"].map((f) => join(DEMO, f));
  const copies = kept.map((p) => (existsSync(p) ? readFileSync(p) : null));
  let cell: string;
  try {
    for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
    const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", "20", "--unit", "1e22", "--daily", "20", "--days", "1", "--max-links", "1",
      "--cover-limit", limit.toString(), "--cover-deductible-bps", "2000", "--cover-premium-bps", "200", "--cover-claim-window", "1800", "--cover-arbiter", s.dao, "--contract", a.writ.id);
    py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
    const reg = await register("0.5"); // 0.45 is the fee for 20 links with cover; the rest is the vault
    if (!reg.ok) throw new Error("register failed: " + reg.error);
    cell = String(reg.cell);
    s.cell = cell;
    record(s, `mandate #${cell} registered, arbiter = DAO`, reg.hash);
  } finally {
    kept.forEach((p, i) => { if (copies[i]) writeFileSync(p, copies[i]!); else rmSync(p, { force: true }); });
  }
  const act = await activateCover(cell);
  if (act.error) throw new Error("activate_cover: " + act.error);
  record(s, "cover activated", act.hash);
  for (const id of Object.keys(INVOICES)) {
    const p = await pay(cell, 1, a.merchant.id, id, context(id));
    if (!p.value?.Paid) throw new Error(`${id}: ${JSON.stringify(p.value ?? p.error)}`);
    record(s, `${id} paid`, p.hash);
  }
  const cv: any = await coverOf(cell);
  say(`  cover ${cv.state}, arbiter ${cv.arbiter}, limit ${fmt(cv.limit)}, dispute_timeout ${cv.dispute_timeout} s`);
}

const snapshot = async (cell: string) => {
  const [cover, stake, claimable]: any[] = await Promise.all([coverOf(cell), view(a.writ.id, "stake_of", { account: a.verifier.id }), view(a.writ.id, "claimable_of", { account: a.acme.id })]);
  return { cover, stake, claimable: BigInt(claimable) };
};

/** One DAO decision: propose, first vote (nothing may happen), second vote (the call fires). */
async function decide(s: State, label: string, method: string, args: object) {
  const kind = { FunctionCall: { receiver_id: a.writ.id, actions: [{ method_name: method, args: b64(args), deposit: "0", gas: RESOLVE_GAS.toString() }] } };
  const p = await call(signer(COUNCIL[0]), s.dao!, "add_proposal", { proposal: { description: label, kind } }, { deposit: BOND, gas: teraToGas("50") });
  if (p.error) throw new Error(`add_proposal: ${p.error}`);
  const id = p.value as number;
  record(s, `proposal ${id}: ${label}`, p.hash);
  // `proposal` is required by the current source's act_proposal and ignored by older deployed code.
  const vote = (who: string) => call(signer(who), s.dao!, "act_proposal", { id, action: "VoteApprove", proposal: kind }, { gas: teraToGas("200") });
  const v1 = await vote(COUNCIL[0]);
  if (v1.error) throw new Error(`vote 1: ${v1.error}`);
  const after1: any = await view(s.dao!, "get_proposal", { id });
  record(s, `vote 1 of 2 on proposal ${id}`, v1.hash, `status ${after1.status}`);
  const v2 = await vote(COUNCIL[1]);
  if (v2.error) throw new Error(`vote 2: ${v2.error}`);
  const after2: any = await view(s.dao!, "get_proposal", { id });
  const ev = v2.logs.filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11)).event);
  record(s, `vote 2 of 2 on proposal ${id}`, v2.hash, `status ${after2.status}, contract events [${ev.join(", ")}]`);
  return { id, status: after2.status as string, ok: after2.status === "Approved" };
}

/** A claim from filing to ruling. Returns the seconds used, as this script's clock saw them. */
async function claim(s: State, invoice: string, ruling: "Deny" | { Uphold: { loss: string } }, reasons: string) {
  const cell = s.cell!;
  const t0 = Date.now();
  const f = await fileClaim(cell, invoice, INVOICES[invoice]);
  if (f.error) throw new Error(`file_claim: ${f.error}`);
  record(s, `file_claim ${invoice}`, f.hash);
  const r = await decide(s, `${typeof ruling === "string" ? "Deny" : "Uphold"} the claim on ${invoice}, mandate ${cell}`, "resolve_claim", { root: cell, invoice_hash: sha(invoice), ruling, ruling_hash: sha(reasons) });
  const secs = (Date.now() - t0) / 1000;
  say(`  ${secs.toFixed(1)} s from file_claim to the end of the second vote; proposal ${r.status}`);
  return { ...r, secs };
}

async function rule(s: State) {
  if (!s.cell) throw new Error("no mandate: run mandate first");
  const cell = s.cell;
  const s0 = await snapshot(cell);
  const rec: any = await paymentOf(cell, "DAO-1");
  const loss = rec.amount as string;

  // A council member alone is not the arbiter
  const t0 = Date.now();
  const f0 = await fileClaim(cell, "DAO-1", INVOICES["DAO-1"]);
  if (f0.error) throw new Error(`file_claim: ${f0.error}`);
  record(s, "file_claim DAO-1", f0.hash);
  const direct = await call(signer("arbiter"), a.writ.id, "resolve_claim", { root: cell, invoice_hash: sha("DAO-1"), ruling: { Uphold: { loss } }, ruling_hash: sha("x") });
  record(s, "a council member calls resolve_claim directly", direct.hash, `refused: ${direct.error ?? "NOT REFUSED"}`);
  const up = await decide(s, `Uphold the claim on DAO-1, mandate ${cell}`, "resolve_claim", { root: cell, invoice_hash: sha("DAO-1"), ruling: { Uphold: { loss } }, ruling_hash: sha("DAO-1 duplicated an order already paid") });
  const upSecs = (Date.now() - t0) / 1000;
  const s1 = await snapshot(cell);
  const payout = (BigInt(loss) * 8000n) / 10_000n;
  say(`  ${upSecs.toFixed(1)} s from file_claim to the end of the second vote; proposal ${up.status}`);
  say(`  stake ${fmt(s0.stake.amount)} -> ${fmt(s1.stake.amount)}; company claimable +${fmt(s1.claimable - s0.claimable)}; upheld ${s1.cover.upheld}, needs_clear ${s1.cover.needs_clear}, remaining ${fmt(s1.cover.remaining)}`);
  const upheldOk = !!direct.error && up.ok && s1.cover.upheld === 1 && BigInt(s0.stake.amount) - BigInt(s1.stake.amount) === payout && s1.claimable - s0.claimable === payout;

  const dn = await claim(s, "DAO-2", "Deny", "DAO-2 was a real purchase of an open order");
  const s2 = await snapshot(cell);
  say(`  stake ${fmt(s1.stake.amount)} -> ${fmt(s2.stake.amount)}; denied ${s2.cover.denied}, open_claim ${s2.cover.open_claim}`);
  const deniedOk = dn.ok && s2.cover.denied === 1 && s2.stake.amount === s1.stake.amount && s2.claimable === s1.claimable && s2.cover.open_claim === null;
  console.log(`DAO_RESULT|${upheldOk && deniedOk ? "PASS" : "FAIL"}|upheld=${upheldOk}|denied=${deniedOk}|uphold_secs=${upSecs.toFixed(1)}|deny_secs=${dn.secs.toFixed(1)}|payout=${payout}`);
  if (!upheldOk || !deniedOk) process.exitCode = 1;
}

async function cleanup(s: State) {
  if (!s.cell) throw new Error("no mandate");
  const before = await snapshot(s.cell);
  if (before.cover.state !== "Active") return say(`cover is ${before.cover.state}: nothing to do`);
  const r = await decide(s, `Void the test cover on mandate ${s.cell}, releasing the lock`, "void_cover", { root: s.cell, invoice_hash: sha("DAO-2") });
  const after = await snapshot(s.cell);
  say(`  cover ${after.cover.state}; guarantor's NEAR exposure ${fmt(before.stake.exposure)} -> ${fmt(after.stake.exposure)}; proposal ${r.status}`);
  if (!r.ok) process.exitCode = 1;
}

const cmd = process.argv[2] ?? "all";
const steps: Record<string, (s: State) => Promise<unknown>> = { create, mandate, rule, cleanup };
const s = load();
for (const name of cmd === "all" ? Object.keys(steps) : [cmd]) {
  if (!steps[name]) throw new Error(`unknown step ${name}`);
  say(`--- ${name}`);
  await steps[name](s);
}
