/**
 * Minimal interface for agent developers: payment results come in a few kinds, so you do not have to parse nearcore errors.
 *
 *   const agent = new WritAgent({ contract, rpc, agentKey });
 *   const r = await agent.pay({ invoice: "INV-0042", to: "supplier.near", links: 1, preimage });
 *   if (r.outcome === "rejected") console.log(r.reason); // SCOPE, DUPLICATE, PER_TX, ...
 */
import { createHash } from "node:crypto";
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas, type KeyPairString } from "near-api-js";

export type PayResult =
  | { outcome: "paid"; amount: string; remainingLinks: number; txHash: string }
  /** The contract refused: the transaction succeeded and has a hash. reason is EXPIRED, SUSPENDED, FROZEN, SCOPE, INVOICE, DUPLICATE, PER_TX, LIMIT, CHAIN, RATE, FUNDS or TRANSFER_FAILED. */
  | { outcome: "rejected"; reason: string; strikes: number; tripped: boolean; txHash: string }
  /** The key was revoked or deleted by the tripwire, so no transaction can be sent. */
  | { outcome: "revoked"; detail: string }
  /** The gas allowance ran out. Not a policy event; the funder can call refresh_key and the agent continues. */
  | { outcome: "out_of_gas"; detail: string }
  /** Any other error (network, protocol refusal). Do not treat it as the payment having failed or succeeded. */
  | { outcome: "error"; detail: string };

export type PayRequest = { invoice: string; to: string; links: number; preimage: string };

/** A seller's automatic credit rule. asset is required (null means NEAR). Empty guarantors or arbiters means any. */
export type SellerPolicy = { max_amount: string; max_tenor_secs: string; min_bond_bps: number; max_defaults: number; guarantors: string[]; asset: string | null; max_fee_bps: number; arbiters: string[] };
/** Result of check_order. ok: the rule asked about, order state and money all pass. would_accept: accept_credit would succeed now, under the stored rule. reasons lists every failure (ORDER_TOO_LARGE, BOND_SHORT, ...). */
export type OrderCheck = { ok: boolean; would_accept: boolean; reasons: string[]; order: Record<string, unknown> };
/** The ft_transfer_call msg for bringing money into a token tree; the same format as the contract's ft_on_transfer. */
export const ftMsg = {
  fund: (cell: string) => `fund:${cell}`,
  stake: () => "stake",
  settle: (credit: string) => `settle:${credit}`,
  dispute: (credit: string, reasonHash: string) => `dispute:${credit}:${reasonHash}`,
  reimburse: (credit: string) => `reimburse:${credit}`,
};

/** The seller's actions: ask about a rule, set a rule, accept, or deliver (finalAmount is a usage order's actual amount). */
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
  /** The first time needs the 0.015 NEAR storage deposit (deposit); later changes do not, and any excess is sent back. */
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
