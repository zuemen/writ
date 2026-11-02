/**
 * 給 agent 開發者用的最小介面：把付款結果分成四種，不用自己解析 nearcore 錯誤。
 *
 *   const agent = new WritAgent({ contract, rpc, agentKey });
 *   const r = await agent.pay({ invoice: "INV-0042", to: "supplier.near", links: 1, preimage });
 *   if (r.outcome === "rejected") console.log(r.reason); // SCOPE, DUPLICATE, PER_TX, ...
 */
import { createHash } from "node:crypto";
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas, type KeyPairString } from "near-api-js";

export type PayResult =
  | { outcome: "paid"; amount: string; remainingLinks: number; txHash: string }
  /** 合約拒絕：交易成功、有 hash，理由是 EXPIRED／SCOPE／INVOICE／DUPLICATE／PER_TX／LIMIT／CHAIN／RATE／FUNDS／TRANSFER_FAILED */
  | { outcome: "rejected"; reason: string; strikes: number; tripped: boolean; txHash: string }
  /** 鑰匙已被撤銷或 tripwire 刪除，連交易都送不出去 */
  | { outcome: "revoked"; detail: string }
  /** gas 額度用完：不是政策事件，法人 refresh_key 後可繼續 */
  | { outcome: "out_of_gas"; detail: string }
  /** 其他錯誤（網路、協定層拒絕）：不要當成付款已失敗或已成功 */
  | { outcome: "error"; detail: string };

export type PayRequest = { invoice: string; to: string; links: number; preimage: string };

export class WritAgent {
  private account: Account;
  constructor(private cfg: { contract: string; rpc: string; agentKey: KeyPairString }) {
    this.account = new Account(cfg.contract, new JsonRpcProvider({ url: cfg.rpc }), KeyPairSigner.fromSecretKey(cfg.agentKey));
  }

  async pay({ invoice, to, links, preimage }: PayRequest): Promise<PayResult> {
    const invoice_hash = createHash("sha256").update(invoice).digest("hex");
    try {
      const r: any = await this.account.signAndSendTransaction({
        receiverId: this.cfg.contract,
        actions: [actions.functionCall("spend", { preimage, j: links, to, invoice_hash }, teraToGas("50"), 0n)],
        throwOnFailure: false,
        waitUntil: "FINAL",
      });
      const raw = r.status?.SuccessValue;
      if (raw === undefined) return { outcome: "error", detail: JSON.stringify(r.status?.Failure ?? r.status).slice(0, 300) };
      const v = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
      if (v.Paid) return { outcome: "paid", amount: v.Paid.amount, remainingLinks: v.Paid.remaining_links, txHash: r.transaction.hash };
      return { outcome: "rejected", reason: v.Rejected.reason, strikes: v.Rejected.strikes, tripped: v.Rejected.tripped, txHash: r.transaction.hash };
    } catch (e) {
      const s = `${JSON.stringify(e, (_k, v) => (typeof v === "bigint" ? v.toString() : v))} ${String(e)}`;
      if (/AccessKeyNotFound|AccessKeyDoesNotExist|does not exist|Can't find access key/i.test(s)) return { outcome: "revoked", detail: "agent key is no longer on the contract account" };
      if (/NotEnoughAllowance|allowance/i.test(s)) return { outcome: "out_of_gas", detail: "gas allowance exhausted; the funder can call refresh_key" };
      return { outcome: "error", detail: s.slice(0, 300) };
    }
  }
}
