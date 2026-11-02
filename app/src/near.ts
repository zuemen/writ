/**
 * Writ 鏈下共用：連線、帳號、呼叫（一律拿到 tx hash 與回傳值）、四種失敗貼標。
 */
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas, type KeyPairString } from "near-api-js";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DEMO = join(ROOT, ".demo");
export const RPC = process.env.NEAR_RPC ?? "http://127.0.0.1:3030";
export const provider = new JsonRpcProvider({ url: RPC });

export const readJson = (p: string) => JSON.parse(readFileSync(p, "utf8"));
export const writeJson = (p: string, o: unknown) => {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(o, null, 1));
};

/** .demo/accounts.json：setup 建立的帳號與私鑰（只在本機 sandbox；.gitignore） */
export function accounts(): Record<string, { id: string; sk: KeyPairString }> {
  const p = join(DEMO, "accounts.json");
  if (!existsSync(p)) throw new Error("run `make demo-setup` first (.demo/accounts.json missing)");
  return readJson(p);
}

export function as(id: string, sk: KeyPairString) {
  return new Account(id, provider, KeyPairSigner.fromSecretKey(sk));
}

export type CallOut = { hash?: string; value?: any; logs: string[]; error?: string; tag?: string };

/** 送一筆 function call。不丟例外：協定層拒絕回 tag，合約 panic 回 error，成功回 value。 */
export async function call(
  acct: Account, contractId: string, method: string, args: object,
  opts: { gas?: bigint; deposit?: bigint } = {},
): Promise<CallOut> {
  try {
    const r: any = await acct.signAndSendTransaction({
      receiverId: contractId,
      actions: [actions.functionCall(method, args, opts.gas ?? teraToGas("50"), opts.deposit ?? 0n)],
      throwOnFailure: false,
      waitUntil: "FINAL",
    });
    const logs: string[] = [r.transaction_outcome, ...(r.receipts_outcome ?? [])].flatMap((o: any) => o?.outcome?.logs ?? []);
    const st = r.status;
    if (st?.SuccessValue !== undefined) {
      const raw = Buffer.from(st.SuccessValue, "base64").toString("utf8");
      return { hash: r.transaction.hash, value: raw ? JSON.parse(raw) : null, logs };
    }
    const err = JSON.stringify(st?.Failure ?? st);
    const m = err.match(/Smart contract panicked: ([^"\\]+)/);
    return { hash: r.transaction.hash, logs, error: m ? m[1] : err.slice(0, 300) };
  } catch (e) {
    return { logs: [], ...label(e) };
  }
}

export async function view(contractId: string, method: string, args: object = {}) {
  return provider.callFunction({ contractId, method, args });
}

/** 協定層拒絕（沒有 tx hash）→ demo 字卡。四種要分開，gas 用完不能被讀成「被攻破」。 */
export function label(err: unknown): { tag: string; error: string } {
  const s = JSON.stringify(err, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) + String(err) + String((err as any)?.message ?? "");
  const pick = (t: string) => ({ tag: t, error: (s.match(/(AccessKeyNotFound|NotEnoughAllowance|MethodNameMismatch|ReceiverMismatch|DepositWithFunctionCall|RequiresFullAccess)/) ?? [""])[0] });
  if (/AccessKeyNotFound|AccessKeyDoesNotExist|does not exist while viewing|Can't find access key/i.test(s)) return pick("MANDATE REVOKED");
  if (/NotEnoughAllowance/.test(s)) return pick("GAS ALLOWANCE EXHAUSTED");
  if (/MethodNameMismatch|ReceiverMismatch|DepositWithFunctionCall|RequiresFullAccess/.test(s)) return pick("PROTOCOL BLOCKED");
  return { tag: "UNKNOWN", error: s.slice(0, 300) };
}

/** 解析 NEP-297 事件 */
export const events = (logs: string[]) =>
  logs.filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11)));

export const NEAR = (n: string | number) => BigInt(Math.round(Number(n) * 1e6)) * 10n ** 18n;
export const fmt = (yocto: string | bigint) => (Number(BigInt(yocto) / 10n ** 18n) / 1e6).toFixed(3) + " NEAR";
