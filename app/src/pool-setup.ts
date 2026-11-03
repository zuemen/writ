/**
 * make pool: pre-open a batch of real organization trees for the site, so visitors can run the whole flow without a server.
 * Each tree has its own KERI chain (root, QVI, legal entity, ECR, AMC) and two real hire levels. Pre-generated: chain links and the ECR revocation event signed by HR.
 * Only when a visitor presses the button does the browser send them on chain; the transactions are real, only the off-chain signatures are made in advance.
 * A separate relayer key that can only call revoke_by_kel is created for the page.
 * Results are written to .demo-testnet/pool.json (contains private keys; for the hosted page only, not in the repo).
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
// Credit is priced in a stablecoin: Circle's testnet USDC. The guarantor's stake and the company's vault are USDC; storage and hiring fees come from the root cell's NEAR reserve
const USDC = process.env.WRIT_POOL_ASSET ?? "3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af";
const MICRO = 1_000_000n;
async function ft(from: { id: string; sk: KeyPairString }, method: string, args: object, gas = "120") {
  const r = await call(as(from.id, from.sk), USDC, method, args, { deposit: method === "storage_deposit" ? NEAR("0.0125") : 1n, gas: teraToGas(gas) });
  if (r.error) throw new Error(`${method}: ${r.error}`);
  return r;
}
const path = join(DEMO, "pool.json");
const pool: any = existsSync(path) ? readJson(path) : { rpc: RPC, contract: a.writ.id, merchant: a.merchant.id, cells: [] };
pool.asset = { id: USDC, symbol: "USDC", decimals: 6 };

if (!pool.relayer) {
  const kp = KeyPair.fromRandom("ed25519");
  const id = `relay-${a.writ.id.split(".")[0]}.${a.owner.id}`;
  const full = KeyPair.fromRandom("ed25519");
  await as(a.owner.id, a.owner.sk).signAndSendTransaction({
    receiverId: id,
    actions: [
      actions.createAccount(),
      actions.transfer(NEAR("0.4")),
      actions.addFullAccessKey(full.getPublicKey()),
      actions.addFunctionCallAccessKey(kp.getPublicKey(), a.writ.id, ["revoke_by_kel"], NEAR("0.3")),
    ],
    waitUntil: "FINAL",
  });
  pool.relayer = { id, sk: kp.toString() as KeyPairString };
  writeJson(path, pool);
  console.log(`  relayer ${id}`);
}

// PayWord chain: links[0] = w0, paying k links hands over links[k]
function chain(n: number) {
  const links: Buffer[] = new Array(n + 1);
  links[n] = randomBytes(32);
  for (let k = n - 1; k >= 0; k--) links[k] = createHash("sha256").update(links[k + 1]).digest();
  return links.map((l) => l.toString("hex"));
}
const agentAcct = (sk: string) => as(a.writ.id, sk as KeyPairString);

// The visitor plays the seller; the guarantor's steps are automated on the page. Both are restricted keys that can only call these methods.
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
  // Store a loose seller rule first (the deposit needs funds, which a restricted key cannot bring); later the visitor's rules are changed with the restricted key
  const sp = await call(as(a.merchant.id, a.merchant.sk), a.writ.id, "set_seller_policy", { policy: { max_amount: (100n * MICRO).toString(), max_tenor_secs: "5184000", min_bond_bps: 0, max_defaults: 1000, guarantors: [], asset: USDC, max_fee_bps: 10000, arbiters: [] } }, { deposit: NEAR("0.015") });
  if (sp.error) throw new Error("set_seller_policy: " + sp.error);
  for (const id of [a.writ.id, a.verifier.id, a.merchant.id]) await ft(a.acme, "storage_deposit", { account_id: id, registration_only: true }, "30");
  await ft(a.acme, "ft_transfer", { receiver_id: a.verifier.id, amount: (BigInt(process.env.WRIT_STAKE_USDC ?? "1500000")).toString() }, "30");
  writeJson(path, pool);
}

for (let i = 0; i < COUNT; i++) {
  for (const d of ["keri/.keystore", "keri/bundle", "keri/registrar"]) rmSync(join(ROOT, d), { recursive: true, force: true });
  // Employee -> accounts-payable agent (two payees)
  const init = py("issuer.py", "init", "--scope", `${a.merchant.id},${a.supplier.id}`, "--rail", a.acme.id, "--n", "20", "--unit", "10000", "--daily", "20", "--days", "30", "--asset", USDC, "--fee-payer", "Seller", "--seller-cap-bps", "5000",
    "--credit-limit", "300000", "--bond-bps", "2500", "--premium-bps", "200", "--min-tenor", "5", "--max-tenor", "5184000", "--arbiter", a.regulator.id, "--contract", a.writ.id);
  py("verify.py", "pin", "--root", JSON.parse(init.slice(init.indexOf("{"), init.lastIndexOf("}") + 1)).root);
  // NEAR reserve: cell opening fee 0.37 + two hires + receipt storage
  const reg = await register(process.env.WRIT_POOL_DEPOSIT ?? "0.78");
  if (!reg.ok) throw new Error("register failed: " + reg.error);
  // Vault 0.095 USDC: hiring takes 0.06, leaving 0.035, enough to lock a 25% bond; on non-payment the big order is paid out, and after the child cell is reclaimed 0.005 is still owed to the guarantor, so disclosure is reachable
  await ft(a.acme, "ft_transfer_call", { receiver_id: a.writ.id, amount: "95000", msg: `fund:${reg.cell}` });
  if (!pool.staked) {
    await ft(a.verifier, "ft_transfer_call", { receiver_id: a.writ.id, amount: process.env.WRIT_STAKE_USDC ?? "1500000", msg: "stake" });
    pool.staked = true;
    writeJson(path, pool);
  }
  const rootSk = keriPrivate().agent_near_secret_key;
  const c: any = await view(a.writ.id, "get_cell", { cell: reg.cell });
  const { lei, salt } = JSON.parse(py("verify.py", "reveal", "--amc", c.amc_said));
    const orderLinks = { small: releaseLink(7), large: releaseLink(16) };

  // Accounts-payable agent -> purchasing agent (can pay only one payee, 6 links)
  const midKey = KeyPair.fromRandom("ed25519");
  const midChain = chain(6);
  const h1 = await call(agentAcct(rootSk), a.writ.id, "hire", {
    preimage: releaseLink(6), j: 6,
    child: { agent_pk: midKey.getPublicKey().toString(), w0: midChain[0], scope: [a.merchant.id], valid_until: c.valid_until, daily_links: 6, max_links: 3 },
  }, { gas: teraToGas("60") });
  if (!h1.value?.Hired) throw new Error("hire 1: " + JSON.stringify(h1));

  // Purchasing agent -> inquiry agent (3 links)
  const leafKey = KeyPair.fromRandom("ed25519");
  const leafChain = chain(3);
  const h2 = await call(agentAcct(midKey.toString()), a.writ.id, "hire", {
    preimage: midChain[3], j: 3,
    child: { agent_pk: leafKey.getPublicKey().toString(), w0: leafChain[0], scope: [a.merchant.id], valid_until: c.valid_until, daily_links: 3, max_links: 2 },
  }, { gas: teraToGas("60") });
  if (!h2.value?.Hired) throw new Error("hire 2: " + JSON.stringify(h2));

  // HR revokes the employee's ECR (signed off-chain, goes on chain when the visitor presses the button)
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
