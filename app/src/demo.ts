/**
 * make demo: reproducible version of the 60-second story (local sandbox, no API key needed).
 *   1 Verifier checks the whole KERI chain in a fresh keystore, signs an attestation
 *   2 Legal entity opens a cell and deposits; the contract installs the agent's KERI key as a function-call key
 *   3 Merchant sees five predicates (LEI sealed)
 *   4 Agent pays (PayWord link, one hash check per payment)
 *   5 Invoice hides a prompt injection, agent pays the attacker, contract rejects it (with tx hash), attacker receives 0
 *   6 Regulator requests disclosure, public waiting period, verifier discloses the LEI (contract checks the commitment)
 *   7 Staff member leaves: HR revokes his ECR in KERI, anyone submits the signed ixn, contract deletes the key
 *   8 Agent pays again, rejected at the protocol layer
 * Each step is written to .demo/timeline.json. Prints one DEMO_RESULT line at the end for machine checking.
 */
import { join } from "node:path";
import { DEMO, fmt, view, writeJson } from "./near.js";
import { A, INJECTED_INVOICE, balance, pay, present, register, releaseUnseal, requestUnseal, revoke, verifierCheck } from "./flow.js";

const a = A();
const timeline: any[] = [];
const say = (step: string, line: string, extra: object = {}) => {
  console.log(`${step.padEnd(2)} ${line}`);
  timeline.push({ step, line, ...extra });
  writeJson(join(DEMO, "timeline.json"), timeline);
};

const reg = await register("5");
for (const c of reg.checks) say("1", `verifier ${c}`);
if (!reg.ok) throw new Error("register failed: " + reg.error);
const cell = reg.cell;
say("2", `${a.acme.id} registers cell #${cell} with 5 NEAR; attestation verified on-chain (ed25519_verify)`, { hash: reg.hash });
say("2", `agent key ${reg.agent_pk} is now a function-call key on ${a.writ.id} (agent methods only)`);

const p: any = await present(cell);
say("3", `merchant sees: not_revoked=${p.not_revoked} not_expired=${p.not_expired} used=${p.within_limit.used}/${p.within_limit.of} scope=${p.scope} lei=${p.lei}`);

const m0 = await balance(a.merchant.id);
const r1 = await pay(cell, 3, a.merchant.id, "INV-0042");
say("4", `agent pays INV-0042 (3 links) → ${JSON.stringify(r1.value)}`, { hash: r1.hash });
const merchantGain = (await balance(a.merchant.id)) - m0;
say("4", `merchant +${fmt(merchantGain)}`);

say("5", `INV-0043 contains: ${INJECTED_INVOICE(a.attacker.id).split("\n")[1]}`);
const a0 = await balance(a.attacker.id);
const r2 = await pay(cell, 2, a.attacker.id, "INV-0043");
const attackerGain = (await balance(a.attacker.id)) - a0;
say("5", `agent obeys: spend(to=${a.attacker.id}) → ${JSON.stringify(r2.value)}`, { hash: r2.hash });
say("5", `attacker +${fmt(attackerGain)}`);
const dup = await pay(cell, 3, a.merchant.id, "INV-0042");
say("5", `injection asks to pay INV-0042 again → ${JSON.stringify(dup.value)}`, { hash: dup.hash });

// 6. Regulator disclosure request: only the LEI is disclosed, and the disclosure itself is a public transaction
const u1 = await requestUnseal(cell);
say("6", `${a.regulator.id} requests disclosure (reason hash of "${u1.reason}") → public, waiting period starts`, { hash: u1.hash });
const tooEarly = await releaseUnseal(cell);
say("6", `verifier tries to disclose immediately → ${tooEarly.error}`);
await new Promise((r) => setTimeout(r, (Number(process.env.WRIT_UNSEAL_SECS ?? 10) + 1) * 1000));
const u2 = await releaseUnseal(cell);
say("6", `after the waiting period, verifier discloses; contract checks sha256(LEI|salt) == commitment → ${u2.error ?? "LEI " + u2.lei}`, { hash: u2.hash });
const p2: any = await present(cell);
say("6", `present(): lei=${p2.lei}`);

say("7", "treasury officer leaves; HR revokes the officer's ECR in KERI (TEL rev anchored by the legal entity's KEL ixn), off-chain; the officer's key is not needed");
const r3 = await revoke(cell);
if (r3.error) throw new Error("revoke_by_kel: " + r3.error);
say("7", `${a.merchant.id} submits the signed ixn (sn=${r3.rev.ixn_sn}) and opens the ECR commitment → key deleted`, { hash: r3.hash });

const r4 = await pay(cell, 1, a.merchant.id, "INV-0044");
say("8", `agent tries again → ${r4.tag} (${r4.error})`);
const vc = verifierCheck();
say("8", `verifier re-check: ${vc.ok ? "valid" : "REFUSED — " + vc.out[0]}`);
const s: any = await view(a.writ.id, "stats");
say("=", `stats ${JSON.stringify(s)}`);

const ok = dup.value?.Rejected?.reason === "DUPLICATE" && !!r1.value?.Paid && r2.value?.Rejected?.reason === "SCOPE" && tooEarly.error === "TOO_EARLY" && p2.lei === u2.lei && attackerGain === 0n && !r3.error && r4.tag === "MANDATE REVOKED" && !vc.ok;
console.log("The chain held only commitments to the company until a public, time-delayed disclosure. The agent lost its key once the signed revocation reached the contract.");
console.log(`\nDEMO_RESULT|${ok ? "PASS" : "FAIL"}|paid=${!!r1.value?.Paid}|injection=${r2.value?.Rejected?.reason}|attacker_gain=${attackerGain}|disclosed=${p2.lei === u2.lei}|revoked=${r4.tag}`);
process.exit(ok ? 0 : 1);
