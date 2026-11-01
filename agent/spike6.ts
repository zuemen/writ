/**
 * Spike 6 —— agent 端（TypeScript, near-api-js v7）
 *
 * 證明：用「任意 KeyPair」當「合約帳號」的 signer 送 function call（Keypom 模式），
 * 並把四種失敗分開貼標，demo 才不會把「gas 用完」讀成「被攻破」。
 *
 * 用法：
 *   RPC=http://127.0.0.1:3030 CONTRACT=sealed.test.near OWNER_KEY=ed25519:... npx tsx spike6.ts
 * OWNER_KEY 是合約帳號的 full-access key（sandbox 裡就是 validator key；testnet 上是你自己的帳號 key）。
 */
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, teraToGas, nearToYocto, type KeyPairString } from "near-api-js";

const RPC = process.env.RPC ?? "http://127.0.0.1:3030";
const CONTRACT = process.env.CONTRACT!;
const OWNER_KEY = process.env.OWNER_KEY! as KeyPairString;

const provider = new JsonRpcProvider({ url: RPC });
/** 合約的 NearToken 參數是「字串」yocto；nearToYocto 回 bigint，JSON 不能直接序列化。 */
const y = (n: string) => nearToYocto(n).toString();

/** 把 RPC／執行錯誤翻成 demo 字卡用的標籤。四種都要能分開。 */
export function label(err: unknown): { tag: string; detail: string } {
  const s = JSON.stringify(err, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) + String(err) + String((err as any)?.message ?? "");
  if (/AccessKeyNotFound|AccessKeyDoesNotExist/.test(s)) return { tag: "MANDATE REVOKED", detail: "key no longer on contract account (protocol layer, no tx hash)" };
  if (/NotEnoughAllowance/.test(s)) return { tag: "GAS ALLOWANCE EXHAUSTED", detail: "not a policy event — call refresh_key" };
  if (/MethodNameMismatch|ReceiverMismatch|DepositWithFunctionCall/.test(s)) return { tag: "PROTOCOL BLOCKED", detail: "function-call key limits (protocol layer, no tx hash)" };
  return { tag: "UNKNOWN", detail: s.slice(0, 300) };
}

async function main() {
  // ---- owner（驗證者）：合約帳號自己的 full-access key ----
  const owner = new Account(CONTRACT, provider, KeyPairSigner.fromSecretKey(OWNER_KEY));

  // ---- agent：一把全新的 Ed25519 鑰匙（正式版：這就是 KERI 委派 AID 的簽章鑰）----
  const agentKp = KeyPair.fromRandom("ed25519");
  const agentPk = agentKp.getPublicKey().toString();
  console.log("[spike6] agent pk:", agentPk);

  // 1. owner 開格：合約在自己帳號上掛 FC key 給 agent
  await owner.callFunction({ contractId: CONTRACT, methodName: "register",
    args: { agent_pk: agentPk, label: "ts-agent", allowance_yocto: y("1") }, gas: teraToGas("30") });
  console.log("[spike6] register ✓");

  // 2. agent 以「合約帳號」身分、用自己的鑰匙簽 —— 這就是 Keypom 模式
  const agent = new Account(CONTRACT, provider, new KeyPairSigner(agentKp));
  const paid = await agent.callFunction({ contractId: CONTRACT, methodName: "spend",
    args: { to: "merchant.test.near", amount: y("0.01") }, gas: teraToGas("30") });
  console.log("[spike6] spend →", JSON.stringify(paid));

  // 3. 注入攻擊：付給攻擊者 → 合約回 Rejected（交易成功、有 hash、事件留下）
  const rej = await agent.callFunction({ contractId: CONTRACT, methodName: "spend",
    args: { to: "attacker.test.near", amount: y("0.01") }, gas: teraToGas("30") });
  console.log("[spike6] injected spend → POLICY REJECTED:", JSON.stringify(rej));

  // 4. agent 鑰匙呼叫非白名單方法 → 協定層擋
  try {
    await agent.callFunction({ contractId: CONTRACT, methodName: "register",
      args: { agent_pk: agentPk, label: "x", allowance_yocto: null }, gas: teraToGas("30") });
  } catch (e) { console.log("[spike6] agent→register:", label(e)); }

  // 5. agent 鑰匙附 deposit → 協定層擋
  try {
    await agent.callFunction({ contractId: CONTRACT, methodName: "spend",
      args: { to: "merchant.test.near", amount: y("0.01") }, gas: teraToGas("30"), deposit: "1" });
  } catch (e) { console.log("[spike6] agent attaches 1 yocto:", label(e)); }

  // 6. owner 撤銷 → 下一筆 agent 交易在協定層死
  const rv = await owner.callFunction({ contractId: CONTRACT, methodName: "revoke", args: { agent_pk: agentPk }, gas: teraToGas("30") });
  console.log("[spike6] revoke ✓ (this one HAS a tx hash — the on-chain evidence of revocation)");
  try {
    await agent.callFunction({ contractId: CONTRACT, methodName: "spend",
      args: { to: "merchant.test.near", amount: y("0.01") }, gas: teraToGas("30") });
  } catch (e) { console.log("[spike6] after revoke:", label(e)); }

  // 7. 1 yocto allowance → NotEnoughAllowance（必須和撤銷分開貼標）
  await owner.callFunction({ contractId: CONTRACT, methodName: "register",
    args: { agent_pk: agentPk, label: "ts-agent-2", allowance_yocto: "1" }, gas: teraToGas("30") });
  try {
    await agent.callFunction({ contractId: CONTRACT, methodName: "spend",
      args: { to: "merchant.test.near", amount: y("0.01") }, gas: teraToGas("30") });
  } catch (e) { console.log("[spike6] tiny allowance:", label(e)); }
}

main().catch((e) => { console.error("FATAL", e); process.exit(1); });
