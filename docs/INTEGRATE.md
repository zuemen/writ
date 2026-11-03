# Integrate

For a company and a guarantor using cover first, then sellers. Nobody uses this in production yet: it runs on testnet at `{CONTRACT}`, and this guide has not been timed with an outside developer.

The commands use [NEAR CLI](https://github.com/near/near-cli-rs). Numbers and amounts in the JSON are examples. `U64` and `U128` values are strings; amounts are in the order's asset (yoctoNEAR, 1 NEAR = 10^24, or the token's smallest unit). Terms are in [ARCHITECTURE.md](ARCHITECTURE.md#terms); every method is in [CONTRACT.md](CONTRACT.md), every error in [ERRORS.md](ERRORS.md).

## Cover: a company and a guarantor

**A scenario, not a customer.** A vendor sells an accounts-payable agent. A prospect's auditor asks: if the agent pays a bill it shouldn't have, inside its limits, who repays it? The vendor's contract caps its liability, and nobody has read the prospect's crime policy for this case.

So the vendor signs a Writ mandate for this customer: $60,000 locked, the customer keeps 20% of each loss, and an outside accountant named as arbiter. The auditor can read all of that with one call to `cover_of`, without trusting the vendor's balance sheet. If the agent is fooled and the seller won't refund, the customer files, the agents stop, the accountant rules, and the customer is repaid from the lock.

It costs the vendor $2,760–8,520 a year in locked money, plus $4,000 if one $5,000 payment is fooled. Every number here is an assumption. We haven't asked a vendor, an auditor or an accountant.

You run an agent that pays invoices. You want a named party to repay what it gets fooled into paying inside its limits. Exact methods are in [CONTRACT.md](CONTRACT.md#cover-methods); `make cover-demo` runs all of this on a sandbox, and `app/src/cover-demo.ts` is the shortest worked example.

### Guarantor: agree terms and sign

Check the company's credential chain off-chain, then sign the attestation with `CoverArgs`. `keri/issuer.py init --cover-limit … --cover-arbiter …` has the legal entity sign the terms, and `keri/verify.py attest` refuses terms it didn't sign or the contract would refuse.

| Term | What it does |
|---|---|
| `limit` | The most you pay in total under this mandate. At least 10 maximum payments, at most `n` × `unit`. It stays fully locked in your stake. |
| `deductible_bps` | The company's share of each loss, 10% to 90%. |
| `premium_bps` | Fee on the limit per 30 days. Charged once, at activation, for the whole term. |
| `claim_window` | Seconds after a payment during which it can be claimed. |
| `arbiter` | Who rules. Not the company, you or the contract owner. |
| `terms_hash` | Hash of the terms the arbiter rules on: what is covered and excluded, the seller's chance to respond, the company's statement that it wasn't refunded, transfer of rights. **The repo's text is a placeholder no lawyer has reviewed.** |

Nothing prices this for you: see [ECONOMICS.md](ECONOMICS.md). Offering it for real money may be regulated; get your own licence or legal opinion.

### Company: register and fund

`register` with the signed `args`, attaching more than 0.35 NEAR + 0.005 NEAR × `n`. A token mandate with no credit terms gets the excess back. Then fund the vault with enough for the fee as well:

```json
{"receiver_id":"{CONTRACT}","amount":"1560000","msg":"fund:25"}
```

on `ft_transfer_call`.

### Guarantor: activate

Stake first if you need to: `ft_transfer_call` with msg `stake`. Then, with `{"root":"25"}` on `activate_cover`, the fee moves from the company's vault to you and the limit locks. Payments before this aren't recorded and can't be claimed.

### Agent: pay with context

```json
{"preimage":"<64 hex>","j":1,"to":"seller.testnet","invoice_hash":"<64 hex>","context_hash":"<64 hex>"}
```

on `spend`. `context_hash` is `sha256(invoice text + "\n" + model + "\n" + JSON of the call)`, as `contextHash` in `app/src/sdk.ts`. Keep the three inputs: the arbiter needs them, and the hash shows they weren't changed after the payment.

### Company: claim

| You want to | Call | Args |
|---|---|---|
| Claim on a payment | `file_claim` | `{"root":"25","invoice_hash":"<64 hex>","evidence_hash":"<64 hex>"}` |
| Close a claim the arbiter let lapse | `claim_timeout` | `{"root":"25"}` |
| Say you dealt with your agent, after an upheld claim | `clear_agent` | `{"root":"25"}` |
| Collect what you were paid | `withdraw` | `{"asset":"usdc.testnet"}` |

Filing stops the whole tree with `UNDER_CLAIM`, with no strike. None of these takes a deposit, so a restricted function-call key can hold just these methods.

### Arbiter: rule

`resolve_claim` with `{"root":"25","invoice_hash":"<64 hex>","ruling":{"Uphold":{"loss":"10000"}},"ruling_hash":"<64 hex>"}`, or `"ruling":"Deny"`. Read `payment_of` first: it has the amount, the payee and `context_hash`. `invoice_paid` shows whether an earlier invoice was already paid. Rule inside `dispute_timeout`, or it times out and nothing moves.

### Read who pays

```
near contract call-function as-read-only {CONTRACT} cover_of json-args '{"cell":"25"}' network-config testnet now
```

`risk_card` is null on a mandate with cover and no credit terms; use `cover_of`.

What cover doesn't do is in the [threat model](THREAT_MODEL.md#cover).

# Second use: net-30 for sellers

The same stake can back orders on credit. The rest of this guide is that path.

## Seller

You sell to an AI agent you have never met. You set a rule, check each order against it, and ship if it passes. If the buyer doesn't pay, you claim.

### 1. Read a risk card (nothing from this repo needed)

```
near contract call-function as-read-only {CONTRACT} risk_card json-args '{"cell":"<id>"}' network-config testnet now
```

`<id>` is the mandate id the agent gives you, or the `cell` in its order. The site shows one. If you have only `curl`, this is the same call for mandate 4; the result is an array of bytes holding JSON:

```
curl -s https://test.rpc.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"query","params":{"request_type":"call_function","finality":"final","account_id":"{CONTRACT}","method_name":"risk_card","args_base64":"eyJjZWxsIjoiNCJ9"}}'
```

What to read:

| Field | Tells you |
|---|---|
| `legal_entity` | `"sealed"`, or the LEI once the company has been named. Sealed means from the public ledger: if you need the name for an invoice, get it off-chain. |
| `guarantor`, `guarantor_listed` | Who stands behind the order, and whether it is still on the whitelist. Accepting refuses a delisted guarantor. |
| `guarantor_stake`, `guarantor_exposure`, `guarantor_unstake_at` | Its stake, what is already committed, and whether it has asked to withdraw. |
| `asset` | The order's token; null is NEAR. Your rule names the one asset it accepts. |
| `credit_limit`, `outstanding`, `frozen` | The company's limit, how much of it is open, and whether stop-ship is on. |
| `bond_bps`, `premium_bps`, `fee_payer`, `seller_cap_bps` | Bond, fee per 30 days, who pays it, the guarantor's cap per seller. |
| `settled`, `settled_amount`, `defaults`, `first_seen`, `entity_tag` | The payment record under this guarantor's pseudonym for the company. |
| `arbiter`, `terms_hash` | Who rules a dispute, and the hash of the terms. |

### 2. Set your rule: `set_seller_policy`

The first time attach 0.015 NEAR (`15000000000000000000000` yocto) for storage; later changes need nothing, and any excess is returned.

```json
{"policy":{"asset":null,"max_amount":"1000000000000000000000000","max_tenor_secs":"2592000","min_bond_bps":2000,"max_fee_bps":500,"max_defaults":0,"guarantors":["guarantor.testnet"],"arbiters":[]}}
```

Every field is required. `asset` is the token you accept, or `null` for NEAR, and `max_amount` is in that asset's unit. `max_fee_bps` is the most the fee may be as a share of the amount, whoever pays it. `guarantors` and `arbiters` hold at most 8 each; empty means any. `{"policy":null}` removes the rule and does not return the deposit.

The rule is optional. Without one, only the contract's own checks apply, and nothing checks the asset: read `asset` yourself.

### 3. Check each order: `check_order`

Watch for the `credit_opened` event ([EVENTS.md](EVENTS.md)), or take the credit id from the agent.

```
near contract call-function as-read-only {CONTRACT} check_order json-args '{"credit":"7"}' network-config testnet now
```

```json
{"ok":false,"would_accept":false,"reasons":["ORDER_TOO_LARGE","BOND_SHORT"],"order":{"credit":"7","cell":"25","seller":"seller.testnet","status":"Open","asset":null,"amount":"…","seller_receives":"…","due_at":"…","tenor_secs":"…","fee":"…","fee_periods":1,"fee_payer":"Buyer","bond":"…","exposure":"…","guarantor":"…","guarantor_listed":true,"policy_applied":true}}
```

The `order` above is abridged. `would_accept` means `accept_credit` would succeed now, under your stored rule. `reasons` lists every failure, not only the first. To try a different rule without storing it, pass it; `ok` then answers for that rule, while `would_accept` still answers for the stored one:

```json
{"credit":"7","policy":{"asset":null,"max_amount":"2000000000000000000000000","max_tenor_secs":"2592000","min_bond_bps":0,"max_fee_bps":1000,"max_defaults":0,"guarantors":[],"arbiters":[]}}
```

### 4. Accept: `accept_credit`

```json
{"credit":"7"}
```

```
near contract call-function as-transaction {CONTRACT} accept_credit json-args '{"credit":"7"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as seller.testnet network-config testnet sign-with-keychain send
```

The contract locks the bond and the guarantor's exposure. It panics `POLICY:<reason>` if your stored rule fails, and otherwise on the first failure `check_order` would report. A rule passed to `check_order` has no effect here. A buyer-paid fee moves now and is not refunded.

### 5. Ship, then record it: `mark_delivered`

`delivery_hash` is the sha256, in hex, of whatever proves your delivery. The contract only stores it.

```json
{"credit":"7","delivery_hash":"<64 hex>"}
```

For a usage order, where the amount is known only at delivery, add `final_amount`. It must be above 0 and at most the order. Bond and exposure shrink at the same ratio.

```json
{"credit":"7","delivery_hash":"<64 hex>","final_amount":"730000000000000000000000"}
```

Record delivery before due date plus `grace`, or anyone can cancel the order. Only a `Delivered` order can default.

### 6. Get paid: `settle`, or `claim_default`

Normally the agent calls `settle` or the company calls `settle_by_funder`, and nothing is needed from you. Check with `credit_of`:

```json
{"credit":"7"}
```

If `status` is still `Delivered` after due date plus `grace` **and** delivery plus `inspect`, claim, with no one's approval:

```json
{"credit":"7"}
```

on `claim_default`. You are credited the full amount from the vault, bond, then the guarantor's stake.

If the company disputes first, it has escrowed the full amount and the status is `Disputed`. File your proof with `mark_delivered` if you have not. The arbiter rules; if it doesn't, anyone can call `resolve_timeout` after the deadline, and you win with a proof on file.

### 7. Collect: `withdraw`

Money is credited first. Collect it:

```json
{}
```

for NEAR, or for a token:

```json
{"asset":"usdc.testnet"}
```

Check the balance with `claimable_of`, `{"account":"seller.testnet","asset":"usdc.testnet"}`. You must be registered with the token; a failed transfer is credited back, so you can retry. A seller-paid fee has already been taken out. `liability_receipt`, `{"credit":"7"}`, gives the order's record for your books.

### What the seller still carries

Windows differ by deployment and no view returns them ([CONTRACT.md](CONTRACT.md#windows)). The delivery proof is only a hash. Read the [limits](THREAT_MODEL.md#limits) before relying on this.

## Company and agent

### What is and is not packaged

**There is no package on npm.** `app/src/sdk.ts` is one file inside the private `writ-demo` app. To use it, copy it; it needs `near-api-js`. `WritAgent` uses `node:crypto`, so it runs on Node, not in a browser.

| In `app/src/sdk.ts` | Does |
|---|---|
| `WritAgent.pay({invoice, to, links, preimage})` | Calls `spend`, returns one of `paid`, `rejected` (with `reason`), `revoked`, `out_of_gas`, `error` |
| `WritSeller.check(credit, policy?)` | `check_order` |
| `WritSeller.setPolicy(policy, deposit)` | `set_seller_policy` |
| `WritSeller.accept(credit)` | `accept_credit` |
| `WritSeller.deliver(credit, deliveryHash, finalAmount?)` | `mark_delivered` |
| `ftMsg` | `ft_transfer_call` msg strings: `fund`, `stake`, `settle`, `dispute`, `reimburse` |
| `SellerPolicy`, `OrderCheck`, `PayResult`, `PayRequest` | Types |

**Not in the SDK:** `hire` and `dismiss` on the agent; anything for a company or guarantor. Those calls are shown in `app/src/credit-demo.ts` and `app/src/flow.ts`.

```ts
const agent = new WritAgent({ contract, rpc, agentKey });
const r = await agent.pay({ invoice: "INV-0042", to: "seller.testnet", links: 1, preimage });
// r.outcome: "paid" | "rejected" (r.reason: SCOPE, DUPLICATE, PER_TX, ...) | "revoked" | "out_of_gas" | "error"
```

An agent needs the contract account, its own key, and the budget links the employee releases.

### The path

0. **Find a guarantor.** The company agrees limit, bond, fee and terms with a guarantor, which checks its credential chain and stakes. Without one, the mandate still works for prepaid payments, with no credit.
1. **Identity.** The company already holds a vLEI, or starts without one: the contract only checks that a whitelisted verifier signed the attestation, so a verifier may vouch for a mandate by other means, with less assurance.
2. **Issue.** An employee with a role credential issues a mandate to the agent. `keri/issuer.py` shows the sequence; a real deployment would use the company's KERI tooling and a real QVI.
3. **Fund.** The company opens a mandate with `register` and funds it in NEAR or a NEP-141 stablecoin.
4. **Release budget.** The employee's system holds the hash-chain seed and hands links to the agent in small batches (`issuer.py release <k>` in this repo). Stopping the release stops the spending, without touching the chain.
5. **Off-board.** The HR system signs the revocation when someone leaves and submits it, or uses any relayer. Writ ships no relayer; connecting one to an HR system is the main integration work.

### Register

The guarantor signs; the company must submit from the account named in the signature. `keri/verify.py attest` builds `args` for the demo. Fields are in [CONTRACT.md](CONTRACT.md#company-methods).

```json
{"args":{
  "amc_said":"E…","issuer_aid":"E…","issuer_pk":"<64 hex>","agent_pk":"ed25519:…",
  "w0":"<64 hex>","n":50,"unit":"100000000000000000000000",
  "scope":["seller.testnet"],"valid_until":"1830000000000000000",
  "daily_links":20,"max_links":10,"max_strikes":3,
  "lei_commit":"<64 hex>","ecr_commit":"<64 hex>",
  "verifier":"guarantor.testnet","attested_at":"1780000000000000000","signature":"<128 hex>",
  "credit":{"limit":"1000000000000000000000000","bond_bps":2000,"premium_bps":225,
            "min_tenor":"86400","max_tenor":"2592000","terms_hash":"<64 hex>","terms_sig":"<128 hex>",
            "entity_tag":"company-1","arbiter":"arbiter.testnet","fee_payer":"Buyer","seller_cap_bps":2000,"asset":null}
}}
```

Attach more than 0.35 NEAR + 0.001 NEAR × `n`. In a NEAR mandate the rest becomes the vault. For a token mandate add `"asset":"usdc.testnet"` both at the top and in `credit`; the NEAR above the fee becomes `near_reserve`, which pays 0.007 NEAR storage per order and hire fees. Then fund with `ft_transfer_call` on the token, 1 yocto attached:

```json
{"receiver_id":"{CONTRACT}","amount":"5000000","msg":"fund:25"}
```

To add a seller later you need a new attestation and a new mandate: the scope cannot change.

### Order and pay, as the agent

Signed with the agent's function-call key, on the contract account. `preimage` is link `idx + j` from the employee. `invoice_hash` is the sha256 of the invoice, in hex. `due_at` is nanoseconds.

```json
{"preimage":"<64 hex>","j":1,"to":"seller.testnet","invoice_hash":"<64 hex>"}
```

on `spend` pays now.

```json
{"preimage":"<64 hex>","j":1,"to":"seller.testnet","invoice_hash":"<64 hex>","due_at":"1830000000000000000"}
```

on `open_credit` orders on credit and returns `{"CreditOpened":{"cell","credit","amount","due_at"}}`. `{"credit":"7"}` on `settle` pays it. A refusal is a normal result with a reason: [Rejected reasons](ERRORS.md#rejected-reasons). Treat `SCOPE`, `DUPLICATE` and `PER_TX` as a possible injection, and don't retry them.

### As the company

| You want to | Call | Args | Attach |
|---|---|---|---|
| Pay an order | `settle_by_funder` | `{"credit":"7"}` | 0 to use the vault, or the full amount |
| Contest an order | `dispute` | `{"credit":"7","reason_hash":"<64 hex>"}` | the full amount |
| Repay the guarantor and lift stop-ship | `reimburse` | `{"credit":"7"}` | whatever the free vault doesn't cover |
| Stop the agent | `revoke` | `{"cell":"25","evidence":"manual"}` | none |
| Bring back a tripped agent | `reinstate` | `{"cell":"25"}` | 0.25 NEAR |
| Restore gas allowance | `refresh_key` | `{"cell":"25"}` | 0.25 NEAR |
| Collect retained money or a failed refund | `claim_refund` | `{"cell":"25"}` | none |

Token trees send the money through `ft_transfer_call` with msg `settle:7`, `dispute:7:<64 hex>` or `reimburse:7` instead of attaching NEAR.

## Guarantor

A guarantor earns its fee by locking money behind orders it has underwritten. Nobody has done this for real, and [ECONOMICS.md](ECONOMICS.md) gives the model and what it does not show.

### Join and stake

The owner must add you with `set_verifier`. Then, for NEAR, call `stake` with `{}` and the amount attached. For a token, send it with `ft_transfer_call` and msg `stake`; this works only after a mandate you signed in that token is registered, which opens the record. A stake in one asset does not back orders in another.

Withdrawing takes two calls: `request_unstake` with `{}` or `{"asset":"usdc.testnet"}`, then after `unstake_delay`, `withdraw_stake` with `{"amount":"1000000000000000000000000"}` plus `asset` if needed. Only stake above exposure can leave, and sellers can see `guarantor_unstake_at` on the risk card.

### Sign terms

You check the company's credential chain off-chain, then sign the attestation including `CreditArgs` ([fields](CONTRACT.md#company-methods)). What each term does for you:

- `scope` is your list of approved sellers, up to 16. A seller outside it cannot be in an order (`A58`).
- `seller_cap_bps` limits how much of your stake one seller account can reach. It is your main limit on collusion, and 0 turns it off ([threat model](THREAT_MODEL.md#collusion-and-fraud)).
- `bond_bps` is the company's first loss.
- `premium_bps` is per 30 days, on every started period, at most 2000. `fee_payer` chooses who pays it.
- `arbiter` cannot be you or the company.

### Watch your book: `guarantor_book`

```
near contract call-function as-read-only {CONTRACT} guarantor_book json-args '{"account":"guarantor.testnet"}' network-config testnet now
```

Returns `stake`, `exposure`, `utilisation_bps`, `earned`, `claims_paid`, `recovered`, `net_loss`, `loss_ratio_bps` (null before any fee) and `top_sellers` (at most 5). Add `"asset":"usdc.testnet"` for a token book. `top_sellers` is drawn from a list of at most 8, so it is not complete.

### Price

[ECONOMICS.md](ECONOMICS.md) has the formula, a worked $10,000 order, suggested tiers and the guarantor's return. At low loss rates most of the cost is locked money, not losses. It is a model; nobody has been asked to pay these prices.

### When a company doesn't pay

| Step | Call | When |
|---|---|---|
| The seller claims; you pay what the vault and bond don't | none | Automatic, inside `claim_default` |
| Trigger the claim for a silent seller | `claim_default`, `{"credit":"7"}` | After a further `recourse` past the seller's earliest date |
| Cancel an order nobody accepted, or an old undelivered one | `cancel_open`, `{"credit":"7"}` | Open: any time. Accepted: after due date plus `grace` |
| Close the tree and collect what is in it | `enforce_recourse`, `{"credit":"7"}` | After `recourse_until`. It can run again later, to collect released bonds |
| Name the company | `credit_unseal`, `{"credit":"7","lei":"…","salt":"…","ecr":{"le_aid":"…","le_pk":"<64 hex>","ecr_said":"…","salt":"…"}}` | Status `Enforced` |

Naming recovers no money. It is a public record, and whether it has any legal effect depends on an agreement you would need to have off-chain.

## Who would pay, and why

- **The seller** gets paid even if the company doesn't, and can sell to an agent without its company's purchases being public.
- **The company** gets credit for its agents without showing its purchasing to everyone, and pays only on what sellers accept.
- **The guarantor** earns `premium_bps` of every accepted order, on-chain, and its income is accepted volume × fee, against losses it can price from a public payment record. It has its own stake at risk, so it has a reason to check the company.

Nothing here has been priced with a real customer: the 2% in the demo is a placeholder. The first guarantor we would ask is the vendor or platform behind the company's agents, because it knows the agent and gains from the sale. Firms that already underwrite trade credit come after that. This is a hypothesis; nobody has been asked. The contract takes no protocol fee.
