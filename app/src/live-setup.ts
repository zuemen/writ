/**
 * make live-agent —— 網站「Fool a live model」用的 agent：預算很小但是真的，下一個鏈節隨網頁公開。
 * 所以模型決定的付款會真的被合約裁定：乾淨發票真的付給供應商，換收款人是 SCOPE，重付是 DUPLICATE，灌水是 PER_TX。
 * 任何人都能拿這些鏈節花錢，但只能付給 mandate 裡的供應商，每筆最多 3 節。私鑰只在 .demo-testnet/，不進 repo。
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

// 先真的付一張，讓「重付」有東西可以被擋
const first = await pay(reg.cell, 1, a.merchant.id, "INV-1");
if (!first.value?.Paid) throw new Error("first payment failed: " + JSON.stringify(first));
console.log(`  first payment tx ${first.hash}`);

const links: string[] = [""];
for (let k = 1; k <= N; k++) links.push(releaseLink(k));
writeJson(join(DEMO, "live.json"), { cell: reg.cell, agent_sk: keriPrivate().agent_near_secret_key, links, unit: "100000000000000000000", contract: a.writ.id, rpc: RPC });
console.log("  wrote live.json");
