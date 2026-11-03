/**
 * make bounty: open a "public key" cell on testnet: maxStrikes = 0, repeated rejections do not delete the key, so anyone can keep trying.
 * First really pay once, leaving a published chain link. Settings are written to .demo-testnet/bounty.json (contains the agent private key; for the hosted page only, not in the repo).
 */
import { rmSync } from "node:fs";
import { join } from "node:path";
import { DEMO, ROOT, RPC, writeJson } from "./near.js";
import { A, pay, register } from "./flow.js";
import { keriPrivate, py, releaseLink } from "./keri.js";

const a = A();
for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
const init = py("issuer.py", "init", "--scope", a.merchant.id, "--rail", a.acme.id, "--n", "50", "--unit", "1e23", "--daily", "20", "--days", "30", "--max-strikes", "0");
py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);

const reg = await register(process.env.WRIT_BOUNTY_DEPOSIT ?? "4.5");
if (!reg.ok) throw new Error("register failed: " + reg.error);
console.log(`  bounty cell #${reg.cell} tx ${reg.hash}`);

const first = await pay(reg.cell, 1, a.merchant.id, "INV-BOUNTY-1");
if (!first.value?.Paid) throw new Error("first payment failed: " + JSON.stringify(first));
console.log(`  first real payment tx ${first.hash}`);

writeJson(join(DEMO, "bounty.json"), {
  rpc: RPC,
  contract: a.writ.id,
  cell: reg.cell,
  merchant: a.merchant.id,
  agent_pk: reg.agent_pk,
  agent_sk: keriPrivate().agent_near_secret_key,
  spent_link: releaseLink(1),
  first_payment_tx: first.hash,
});
console.log("  wrote bounty.json");
