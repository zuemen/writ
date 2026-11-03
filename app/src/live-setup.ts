/**
 * make live-agent: the one mandate behind the site's "Fool the model". USDC-denominated, cover only, no credit terms, no hires.
 * What it does, in order:
 *   1 issues a mandate to the seller only: n links of 0.01 USDC, at most 3 a payment, a low daily rate so one script can't burn every link in a burst
 *   2 signs cover terms: limit n x unit, the most the budget can ever pay, so links run out before the limit does; the company's share 20%; fee 2% per 30 days; claim window 10 minutes, so a stale stop cycles out; a named arbiter who is not the owner
 *   3 funds the vault in USDC, tops up the guarantor's stake if it is short, activates cover
 *   4 pays INV-1 once, so "Pay INV-1 again" has something to be refused and the arbiter has something to check
 *   5 adds two restricted keys: the company's (file_claim, clear_agent, claim_timeout) and the arbiter's (resolve_claim)
 * Anyone can use those keys and the next budget links: they ship with the page. A payment can only reach the seller in the mandate, and a ruling only moves money to the company's account.
 * Writes .demo-testnet/live.json. It holds keys and stays out of the repo. This script never prints a key.
 */
import { rmSync } from "node:fs";
import { join } from "node:path";
import { KeyPair, actions, teraToGas, type KeyPairString } from "near-api-js";
import { DEMO, DEMO_WINDOWS, NEAR, ROOT, RPC, as, call, view, writeJson } from "./near.js";
import { A, activateCover, balance, pay, register } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";
import { contextHash } from "./sdk.js";

const say = (s: string) => console.log(`  ${s}`);
const USDC = process.env.WRIT_LIVE_ASSET ?? "3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af"; // Circle's testnet USDC
const N = Number(process.env.WRIT_LIVE_N ?? 150);
const DAYS = Number(process.env.WRIT_LIVE_DAYS ?? 60);
const DAILY = Number(process.env.WRIT_LIVE_DAILY ?? Math.max(5, Math.ceil(N / 10)));
const CLAIM_WINDOW = Number(process.env.WRIT_LIVE_CLAIM_WINDOW ?? 600);
const KEY_ALLOWANCE = process.env.WRIT_LIVE_KEY_ALLOWANCE ?? "5"; // NEAR. A stranger can burn it, at no cost to them, by sending bad calls
const UNIT = 10_000n; // 0.01 USDC
const MAX_LINKS = 3n;
const PREMIUM_BPS = 200n;
const LIMIT = BigInt(N) * UNIT; // the contract's ceiling. With a 20% share, payouts can never reach it, so a script can't exhaust the cover
const SPARE = BigInt(process.env.WRIT_LIVE_SPARE_STAKE ?? "500000"); // free stake left over for the credit story, which draws on the same stake
const usd = (v: bigint) => `${(Number(v) / 1e6).toFixed(4)} USDC`;

const a = A();
const arbiter = a.arbiter ?? a.regulator; // never the owner: the contract refuses COVER_ARBITER
if (LIMIT < 10n * MAX_LINKS * UNIT) throw new Error(`WRIT_LIVE_N=${N} is too small: the limit must be at least 10 maximum payments (${usd(10n * MAX_LINKS * UNIT)})`);

const periods = BigInt(Math.ceil(DAYS / 30));
const fee = (LIMIT * PREMIUM_BPS * periods) / 10_000n;
const vault = BigInt(N) * UNIT + fee;
const depositNear = (0.35 + 0.005 * N + 0.02).toFixed(3); // 0.35 + 0.001 per link + 0.004 per link of cover records, with a margin; a token mandate without credit gets the excess back

const bal = async (id: string) => BigInt((await view(USDC, "ft_balance_of", { account_id: id })) as string);
const stakeOf = async (): Promise<{ amount: bigint; exposure: bigint }> => {
  const s: any = await view(a.writ.id, "stake_of", { account: a.verifier.id, asset: USDC }).catch(() => null);
  return { amount: BigInt(s?.amount ?? "0"), exposure: BigInt(s?.exposure ?? "0") };
};
async function ft(from: { id: string; sk: KeyPairString }, method: string, args: object, gas: `${number}` = "120") {
  const r = await call(as(from.id, from.sk), USDC, method, args, { deposit: method === "storage_deposit" ? NEAR("0.0125") : 1n, gas: teraToGas(gas) });
  if (r.error) throw new Error(`${method}: ${r.error}`);
  return r;
}

// ---------------- check first: a credential can only be used once ----------------
const s0 = await stakeOf();
const free0 = s0.amount > s0.exposure ? s0.amount - s0.exposure : 0n;
const need = LIMIT + SPARE;
const topUp = free0 + fee >= need ? 0n : need - free0 - fee;
const verifierUsdc = await bal(a.verifier.id).catch(() => 0n);
const toVerifier = verifierUsdc >= topUp ? 0n : topUp - verifierUsdc;
const acmeUsdc = await bal(a.acme.id);
say(`plan: mandate of ${N} links at ${usd(UNIT)}, ${DAILY} a day, claim window ${CLAIM_WINDOW} s, cover limit ${usd(LIMIT)}, fee ${usd(fee)} for ${DAYS} days, vault ${usd(vault)}, stake top-up ${usd(topUp)}, register deposit ${depositNear} NEAR`);
if (acmeUsdc < vault + toVerifier) {
  console.error(`${a.acme.id} holds ${usd(acmeUsdc)} and needs ${usd(vault + toVerifier)}. Get testnet USDC from https://faucet.circle.com (network: NEAR Testnet), then run this again.`);
  process.exit(2);
}
// Gas for the page's keys comes out of these accounts, whatever the allowance says.
for (const who of [a.acme, arbiter]) {
  const have = await balance(who.id);
  if (have < NEAR("1")) console.warn(`  warning: ${who.id} holds under 1 NEAR, and the page's restricted key pays gas from it`);
}

// ---------------- the token must know the contract, the seller and the guarantor ----------------
for (const id of [a.writ.id, a.merchant.id, a.verifier.id]) {
  const known = await view(USDC, "storage_balance_of", { account_id: id }).catch(() => null);
  if (!known) await ft(a.acme, "storage_deposit", { account_id: id, registration_only: true }, "30");
}

// ---------------- 1 + 2: mandate and cover terms ----------------
for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", String(N), "--unit", UNIT.toString(), "--daily", String(DAILY), "--max-links", MAX_LINKS.toString(), "--days", String(DAYS), "--max-strikes", "0", "--asset", USDC,
  "--contract", a.writ.id, "--cover-limit", LIMIT.toString(), "--cover-deductible-bps", "2000", "--cover-premium-bps", PREMIUM_BPS.toString(), "--cover-claim-window", String(CLAIM_WINDOW), "--cover-arbiter", arbiter.id);
py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);

const reg = await register(depositNear);
if (!reg.ok) throw new Error("register failed: " + reg.error);
const cell = String(reg.cell);
say(`mandate #${cell} registered, tx ${reg.hash}; arbiter ${arbiter.id}, guarantor ${a.verifier.id}`);

// ---------------- 3: money ----------------
const funded = await ft(a.acme, "ft_transfer_call", { receiver_id: a.writ.id, amount: vault.toString(), msg: `fund:${cell}` });
const c: any = await view(a.writ.id, "get_cell", { cell });
if (BigInt(c.vault) < vault) throw new Error(`the vault holds ${usd(BigInt(c.vault))}: the funding was refused`); // a refused deposit is a refund, not a panic
say(`vault funded with ${usd(vault)}, tx ${funded.hash}`);

if (topUp > 0n) {
  if (toVerifier > 0n) await ft(a.acme, "ft_transfer", { receiver_id: a.verifier.id, amount: toVerifier.toString() }, "30");
  const r = await ft(a.verifier, "ft_transfer_call", { receiver_id: a.writ.id, amount: topUp.toString(), msg: "stake" });
  say(`guarantor staked ${usd(topUp)}, tx ${r.hash}`);
}
const act = await activateCover(cell);
if (act.error) throw new Error("activate_cover: " + act.error);
const cover: any = await view(a.writ.id, "cover_of", { cell });
say(`cover ${cover.state}: ${usd(BigInt(cover.remaining))} locked, fee ${usd(BigInt(cover.premium))} paid, tx ${act.hash}`);

// ---------------- 4: INV-1 is paid, under active cover, with its context ----------------
const inv1 = `INV-1  PO-77 paper stock, 1 link. Pay to ${a.merchant.id}.`;
const model = "setup-script";
const first = await pay(cell, 1, a.merchant.id, "INV-1", contextHash(inv1, model, { invoice_id: "INV-1", payee: a.merchant.id, links: 1 }));
if (!first.value?.Paid) throw new Error("INV-1 failed: " + JSON.stringify(first.value ?? first.error));
say(`INV-1 paid, tx ${first.hash}`);

// ---------------- 5: restricted keys, on the page ----------------
async function restrictedKey(owner: { id: string; sk: KeyPairString }, methods: string[]) {
  const kp = KeyPair.fromRandom("ed25519");
  await as(owner.id, owner.sk).signAndSendTransaction({
    receiverId: owner.id,
    actions: [actions.addFunctionCallAccessKey(kp.getPublicKey(), a.writ.id, methods, NEAR(KEY_ALLOWANCE))],
    waitUntil: "FINAL",
  });
  say(`restricted key on ${owner.id}, allowance ${KEY_ALLOWANCE} NEAR: ${methods.join(", ")}`);
  return { id: owner.id, sk: kp.toString() as KeyPairString };
}
const funder_key = await restrictedKey(a.acme, ["file_claim", "clear_agent", "claim_timeout"]);
const arbiter_key = await restrictedKey(arbiter, ["resolve_claim"]);

const windows: any = await view(a.writ.id, "windows").catch(() => null); // older deployments have no such view
const links: string[] = [""];
for (let k = 1; k <= N; k++) links.push(releaseLink(k));
writeJson(join(DEMO, "live.json"), {
  cell, agent_sk: keriPrivate().agent_near_secret_key, links, unit: UNIT.toString(), asset: USDC, contract: a.writ.id, rpc: RPC,
  funder_key, arbiter_key, inv1_paid_hash: first.hash, dispute_secs: Number(windows?.dispute_timeout ?? DEMO_WINDOWS(0).dispute_timeout),
});
say(`wrote ${join(DEMO, "live.json")} (keys inside, not printed)`);
