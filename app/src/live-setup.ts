/**
 * make live-agent: agent for the site's "Fool a live model": a small but real budget, the next chain link is published with the page.
 * So payments the model decides on are really ruled on by the contract: a clean invoice really pays the supplier, a changed payee is SCOPE, a repeat is DUPLICATE, inflation is PER_TX.
 * Anyone can spend with these links, but only to the supplier in the mandate, at most 3 links per payment. Private keys stay in .demo-testnet/, not in the repo.
 */
import { rmSync } from "node:fs";
import { join } from "node:path";
import { DEMO, ROOT, RPC, writeJson } from "./near.js";
import { A, pay, register } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const N = Number(process.env.WRIT_LIVE_N ?? 100);
const a = A();
for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", String(N), "--unit", "1e20", "--daily", String(N), "--max-links", "3", "--days", "30", "--max-strikes", "0");
py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);

const reg = await register(process.env.WRIT_LIVE_AGENT_DEPOSIT ?? "0.50");
if (!reg.ok) throw new Error("register failed: " + reg.error);
console.log(`  live agent cell #${reg.cell} tx ${reg.hash}`);

// First really pay one invoice, so the "repeat payment" has something to be blocked
const first = await pay(reg.cell, 1, a.merchant.id, "INV-1");
if (!first.value?.Paid) throw new Error("first payment failed: " + JSON.stringify(first));
console.log(`  first payment tx ${first.hash}`);

const links: string[] = [""];
for (let k = 1; k <= N; k++) links.push(releaseLink(k));
writeJson(join(DEMO, "live.json"), { cell: reg.cell, agent_sk: keriPrivate().agent_near_secret_key, links, unit: "100000000000000000000", contract: a.writ.id, rpc: RPC });
console.log("  wrote live.json");
