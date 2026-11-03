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
  /** The contract refused: the transaction succeeded and has a hash. reason is EXPIRED, SUSPENDED, FROZEN, UNDER_CLAIM, NOT_CLEARED, SCOPE, INVOICE, DUPLICATE, PER_TX, LIMIT, CHAIN, RATE, FUNDS or TRANSFER_FAILED. */
  | { outcome: "rejected"; reason: string; strikes: number; tripped: boolean; txHash: string }
  /** The key was revoked or deleted by the tripwire, so no transaction can be sent. */
  | { outcome: "revoked"; detail: string }
  /** The gas allowance ran out. Not a policy event; the funder can call refresh_key and the agent continues. */
  | { outcome: "out_of_gas"; detail: string }
  /** Any other error (network, protocol refusal). Do not treat it as the payment having failed or succeeded. */
  | { outcome: "error"; detail: string };

/** contextHash (optional): binds the invoice and the model's decision to the payment, so a claim can show them later. See contextHash below. */
export type PayRequest = { invoice: string; to: string; links: number; preimage: string; contextHash?: string };

/** sha256(invoice text ‖ model ‖ JSON of the call). Anyone with the three can recompute it. */
export const contextHash = (invoiceText: string, model: string, call: unknown) =>
  createHash("sha256").update(`${invoiceText}\n${model}\n${JSON.stringify(call)}`).digest("hex");

/** Hash of the invoice id, as the contract keys it. */
const invoiceHash = (invoice: string) => createHash("sha256").update(invoice).digest("hex");

/** One account's cover actions. Which methods work depends on who the account is: guarantor, company (funder) or arbiter. None of them takes a deposit. */
export class WritCover {
  private account: Account;
  private provider: JsonRpcProvider;
  constructor(private cfg: { contract: string; rpc: string; account: string; key: KeyPairString }) {
    this.provider = new JsonRpcProvider({ url: cfg.rpc });
    this.account = new Account(cfg.account, this.provider, KeyPairSigner.fromSecretKey(cfg.key));
  }
  private send(method: string, args: object) {
    return this.account.signAndSendTransaction({ receiverId: this.cfg.contract, actions: [actions.functionCall(method, args, teraToGas("100"), 0n)], waitUntil: "FINAL" });
  }
  /** Guarantor: take the fee, lock the limit. Fails with PREMIUM_SHORT or GUARANTOR_CAPACITY and nothing changes. */
  activate(root: string) { return this.send("activate_cover", { root }); }
  /** Company: claim on one payment. The whole tree stops until the arbiter rules or runs out of time. */
  fileClaim(root: string, invoice: string, evidenceHash: string) { return this.send("file_claim", { root, invoice_hash: invoiceHash(invoice), evidence_hash: evidenceHash }); }
  /** Arbiter: rule before dispute_timeout. loss is at most the amount paid. */
  resolveClaim(root: string, invoice: string, ruling: "Deny" | { Uphold: { loss: string } }, rulingHash: string) { return this.send("resolve_claim", { root, invoice_hash: invoiceHash(invoice), ruling, ruling_hash: rulingHash }); }
  /** Arbiter: end the cover because a denied claim was fraud. */
  voidCover(root: string, invoice: string) { return this.send("void_cover", { root, invoice_hash: invoiceHash(invoice) }); }
  /** Anyone, after dispute_timeout. Nothing is paid; the company can file again inside the window. */
  claimTimeout(root: string) { return this.send("claim_timeout", { root }); }
  /** Company: after an upheld claim. A record, not a security control. */
  clearAgent(root: string) { return this.send("clear_agent", { root }); }
  /** Guarantor: after valid_until + claim_window. */
  release(root: string) { return this.send("release_cover", { root }); }
  /** `cell` can be any cell in the tree. Null if it has no cover. */
  coverOf(cell: string): Promise<Record<string, unknown> | null> {
    return this.provider.callFunction({ contractId: this.cfg.contract, method: "cover_of", args: { cell } }) as Promise<Record<string, unknown> | null>;
  }
  paymentOf(cell: string, invoice: string): Promise<Record<string, unknown> | null> {
    return this.provider.callFunction({ contractId: this.cfg.contract, method: "payment_of", args: { cell, invoice_hash: invoiceHash(invoice) } }) as Promise<Record<string, unknown> | null>;
  }
}

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
  /** What a seller reads before anything else. `cell` is the mandate id the agent gives you. */
  riskCard(cell: string): Promise<Record<string, unknown> | null> {
    return this.provider.callFunction({ contractId: this.cfg.contract, method: "risk_card", args: { cell } }) as Promise<Record<string, unknown> | null>;
  }
  /** After delivery, the due date and the inspection window, with no approval needed. */
  claimDefault(credit: string) {
    return this.send("claim_default", { credit });
  }
  /** Pass the token account for a token order, or null for NEAR. */
  withdraw(asset: string | null = null) {
    return this.send("withdraw", { asset });
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

  /** Order on credit: spends budget links, moves no money. dueAt is Unix nanoseconds as a string. */
  openCredit(req: { invoice: string; to: string; links: number; preimage: string; dueAt: string }) {
    const invoice_hash = createHash("sha256").update(req.invoice).digest("hex");
    return this.account.signAndSendTransaction({ receiverId: this.cfg.contract, actions: [actions.functionCall("open_credit", { preimage: req.preimage, j: req.links, to: req.to, invoice_hash, due_at: req.dueAt }, teraToGas("50"), 0n)], throwOnFailure: false, waitUntil: "FINAL" } as any);
  }
  /** Settle an accepted order from this agent's vault. */
  settle(credit: string) {
    return this.account.signAndSendTransaction({ receiverId: this.cfg.contract, actions: [actions.functionCall("settle", { credit }, teraToGas("50"), 0n)], throwOnFailure: false, waitUntil: "FINAL" } as any);
  }

  async pay({ invoice, to, links, preimage, contextHash }: PayRequest): Promise<PayResult> {
    const invoice_hash = invoiceHash(invoice);
    try {
      const r: any = await this.account.signAndSendTransaction({
        receiverId: this.cfg.contract,
        actions: [actions.functionCall("spend", contextHash ? { preimage, j: links, to, invoice_hash, context_hash: contextHash } : { preimage, j: links, to, invoice_hash }, teraToGas("80"), 0n)],
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
