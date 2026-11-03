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

/** 賣方的自動授信規則。guarantors 空陣列 = 任何保證人都接受。 */
export type SellerPolicy = { max_amount: string; max_tenor_secs: string; min_bond_bps: number; max_defaults: number; guarantors: string[]; asset: string | null; max_fee_bps: number; arbiters: string[] };
/** check_order 的回傳。ok = 現在 accept_credit 會成功；reasons 列出所有不符合的（ORDER_TOO_LARGE、BOND_SHORT、...）。 */
export type OrderCheck = { ok: boolean; would_accept: boolean; reasons: string[]; order: Record<string, unknown> };
/** 代幣樹帶錢進來的 ft_transfer_call msg，與合約 ft_on_transfer 的格式一致。 */
export const ftMsg = {
  fund: (cell: string) => `fund:${cell}`,
  stake: () => "stake",
  settle: (credit: string) => `settle:${credit}`,
  dispute: (credit: string, reasonHash: string) => `dispute:${credit}:${reasonHash}`,
  reimburse: (credit: string) => `reimburse:${credit}`,
};

/** 賣方這邊的三個動作：問規則、設規則、接受或交貨（finalAmount = 用量單的實際金額）。 */
export class WritSeller {
  private account: Account;
  private provider: JsonRpcProvider;
  constructor(private cfg: { contract: string; rpc: string; account: string; key: KeyPairString }) {
    this.provider = new JsonRpcProvider({ url: cfg.rpc });
    this.account = new Account(cfg.account, this.provider, KeyPairSigner.fromSecretKey(cfg.key));
  }
  private send(method: string, args: object, deposit = 0n) {
    return this.account.signAndSendTransaction({ receiverId: this.cfg.contract, actions: [actions.functionCall(method, args, teraToGas("100"), deposit)], waitUntil: "FINAL" });
  }
  check(credit: string, policy?: SellerPolicy): Promise<OrderCheck> {
    return this.provider.callFunction({ contractId: this.cfg.contract, method: "check_order", args: policy ? { credit, policy } : { credit } }) as Promise<OrderCheck>;
  }
  /** 第一次設定要附 0.015 NEAR 儲存押金（deposit），之後改規則不用。 */
  setPolicy(policy: SellerPolicy | null, deposit = 0n) {
    return this.send("set_seller_policy", { policy }, deposit);
  }
  accept(credit: string) {
    return this.send("accept_credit", { credit });
  }
  deliver(credit: string, deliveryHash: string, finalAmount?: string) {
    return this.send("mark_delivered", finalAmount ? { credit, delivery_hash: deliveryHash, final_amount: finalAmount } : { credit, delivery_hash: deliveryHash });
  }
}

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
        actions: [actions.functionCall("spend", { preimage, j: links, to, invoice_hash }, teraToGas("80"), 0n)],
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
