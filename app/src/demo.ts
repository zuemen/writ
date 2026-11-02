/**
 * make demo —— 60 秒故事的可重現版本（本機 sandbox，不需要任何 API key）。
 *   1 驗證者在全新 keystore 驗整條 KERI 鏈 → 簽 attestation
 *   2 法人開格入金；合約把 agent 的 KERI 鑰匙掛成 function-call key
 *   3 商家看五個謂詞（LEI 封著）
 *   4 agent 付款（PayWord 鏈節，每筆一個雜湊檢查）
 *   5 發票藏 prompt injection → agent 付給攻擊者 → 合約拒絕（有 tx hash），攻擊者 0 入帳
 *   6 監理方調閱 → 公開等待期 → 驗證者揭露 LEI（合約比對承諾）
 *   7 職員離職：HR 在 KERI 撤銷他的 ECR → 任何人提交簽過的 ixn → 合約刪鑰匙
 *   8 agent 再付 → 協定層拒絕
 * 每一步寫進 .demo/timeline.json。結尾印 DEMO_RESULT 一行給機器檢查。
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
say("2", `agent key ${reg.agent_pk} is now a function-call key on ${a.writ.id} (method: spend)`);

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

// 6. 監理調閱：只揭露 LEI，而且揭露本身是公開交易
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
