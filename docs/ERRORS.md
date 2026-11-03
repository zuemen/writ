# Errors

Two kinds, from `contract/src/lib.rs`:

- **Panic codes** abort the transaction and undo its state. The code appears in the failure message, as in `Smart contract panicked: NOT_DUE`.
- **Rejected reasons** are normal results. The transaction succeeds, has a hash and logs a `rejected` event, so the refusal stays on the record.

near-sdk adds its own panics: a deposit on a method that is not payable, a call to a `#[private]` callback, and arguments that do not parse. Separately, NEAR itself can refuse an agent key before any contract code runs; those errors are listed in [THREAT_MODEL.md](THREAT_MODEL.md#what-the-agents-key-cannot-do-protocol-layer-no-transaction-is-created). "Funder" is the company's funding account, and "verifier" a whitelisted signer ([terms](ARCHITECTURE.md#terms)).

## Rejected reasons

Who sees them: the agent, as `{"Rejected":{"cell","reason","strikes","tripped"}}`. All but `FROZEN`, `UNDER_CLAIM`, `NOT_CLEARED`, `RESERVE` and `TRANSFER_FAILED` add a strike; `max_strikes` consecutive strikes delete the key. They are checked in the order listed; in `hire`, the `HIRE_*` checks run after `NOT_CLEARED` and before `LIMIT`.

| Reason | From | Means | What to do |
|---|---|---|---|
| `NO_CREDIT` | `open_credit` | This mandate has no credit terms. | Pay with `spend`, or get a mandate with credit. |
| `EXPIRED` | `spend`, `hire`, `open_credit` | Past `valid_until`. | Get a new mandate. |
| `SUSPENDED` | `spend`, `hire`, `open_credit` | A parent up the tree is tripped or closed. | Ask the company to reinstate the parent. |
| `FROZEN` | `spend`, `hire`, `open_credit` | The company owes its guarantor. No strike. | The company repays with `reimburse`; stop buying until then. |
| `UNDER_CLAIM` | `spend`, `hire`, `open_credit` | The company filed a claim and the arbiter has not ruled. It stops the whole tree. No strike. | Wait for the ruling, or for `claim_timeout`. |
| `NOT_CLEARED` | `spend`, `hire`, `open_credit` | A claim was upheld and the company has not called `clear_agent`. It stops the whole tree. No strike. | The company checks its agent and calls `clear_agent`. |
| `SCOPE` | `spend`, `open_credit` | The payee is not in the mandate. | Do not retry. If it came from an invoice, treat it as a possible injection. |
| `INVOICE` | `spend`, `open_credit` | `invoice_hash`, or `context_hash` on `spend`, is not 32 bytes of hex. | Send the sha256 of the invoice, and a proper context hash or none. |
| `DUPLICATE` | `spend`, `open_credit` | This invoice was already paid or ordered in this tree. | Check `invoice_paid`. A real new order needs a new invoice id. |
| `PER_TX` | `spend`, `open_credit` | `j` is above `max_links`. | Ask a person. The cap was signed into the mandate. |
| `LIMIT` | `spend`, `hire`, `open_credit` | `j` is 0, or goes past `n`. | Ask for a new mandate; the budget is used up. |
| `CHAIN` | `spend`, `hire`, `open_credit` | The preimage does not hash to the current chain head in `j` steps. | Ask the employee for link `idx + j`. |
| `RATE` | `spend`, `hire`, `open_credit` | Today's `daily_links` would be exceeded. | Wait for the next UTC day. |
| `CREDIT_LIMIT` | `open_credit` | Outstanding plus this order exceeds `limit`. | Wait for orders to settle. |
| `TENOR` | `open_credit` | `due_at` is outside `min_tenor` and `max_tenor`. | Use a due date inside the terms. |
| `FUNDS` | `spend`, `hire`, `open_credit` | The free vault is short. For `open_credit`, the vault cannot pay the order's storage. | The company funds the vault. |
| `RESERVE` | `hire`, `open_credit` | Token tree only: `near_reserve` cannot pay the hire fee or the order's storage. No strike. | The company adds NEAR with `top_up` on the root. |
| `HIRE_TOKEN` | `hire` | A token mandate with no credit terms cannot hire. | Use a mandate with credit terms, or a NEAR mandate. |
| `HIRE_SCOPE` | `hire` | Child scope is empty, over 16, or wider than the parent's. | Narrow the scope. |
| `HIRE_TERMS` | `hire` | Child expiry, rate or cap is beyond the parent's or invalid, or `w0` is not 32 bytes of hex. | Narrow the terms. |
| `HIRE_DEPTH` | `hire` | Already 3 levels below the root. | Hire from higher up. |
| `HIRE_TREE` | `hire` | The tree already has 16 agents. | Dismiss one. |
| `HIRE_KEY` | `hire` | That key has been used before. Keys are single-use. | Generate a new key. |
| `TRANSFER_FAILED` | `spend`'s callback | The transfer bounced. The vault is refunded, the invoice is free again, but the links stay spent. No strike. | Check the payee account or token registration, then pay with new links. |

## Panic codes

`Who` is who normally sees it.

### Seller: rule

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `POLICY_TOO_LONG` | `set_seller_policy` | Seller | More than 8 guarantors or 8 arbiters in the rule. | Shorten the list. |
| `BAD_POLICY` | `set_seller_policy` | Seller | `min_bond_bps` is above 10000. | Fix the value. |
| `POLICY_STORAGE` | `set_seller_policy` | Seller | First rule needs a 0.015 NEAR deposit. | Attach it. |

### Seller: accepting an order

`check_order` returns these names in `reasons`; `accept_credit` panics on the first. Rule reasons are prefixed there: `POLICY:<reason>`.

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NO_CREDIT` | any method taking `credit` | Anyone | No order with that id. | Check the id. |
| `ONLY_SELLER` | `accept_credit`, `mark_delivered`, `claim_default` | Other accounts | Only the order's seller, or the guarantor on a stale claim. | Sign with the seller's account. |
| `NOT_OPEN` | `accept_credit` | Seller | Already accepted, cancelled or ended. | Read `credit_of`. |
| `OFFER_EXPIRED` | `accept_credit` | Seller | Past `accept_ttl`. | Ask the agent to order again. |
| `AGENT_NOT_ACTIVE` | `accept_credit` | Seller | The agent was revoked, tripped, or a parent is. | Do not ship. |
| `COMPANY_FROZEN` | `accept_credit` | Seller | Stop-ship: the company owes its guarantor. | Do not ship. |
| `GUARANTOR_DELISTED` | `accept_credit` | Seller | The owner removed this guarantor from the whitelist. | Do not ship. |
| `MANDATE_EXPIRED` | `accept_credit` | Seller | The mandate expired after the order was opened. | Do not ship. |
| `ARBITER_NOT_INDEPENDENT` | `accept_credit`, `register` | Seller, company | The seller is the arbiter; or at registration the arbiter is the guarantor or company. | Use another account. |
| `SELLER_NOT_INDEPENDENT` | `accept_credit` | Seller | The seller is the guarantor or the company. | Use an independent seller. |
| `POLICY:ORDER_TOO_LARGE` | `accept_credit` | Seller | Amount is above your `max_amount`. In `check_order`: `ORDER_TOO_LARGE`. | Change your rule or refuse. |
| `POLICY:TENOR_TOO_LONG` | `accept_credit` | Seller | Due date is beyond your `max_tenor_secs`. In `check_order`: `TENOR_TOO_LONG`. | Change your rule or refuse. |
| `POLICY:BOND_TOO_LOW` | `accept_credit` | Seller | The mandate's bond is below your `min_bond_bps`. In `check_order`: `BOND_TOO_LOW`. | Change your rule or refuse. |
| `POLICY:TOO_MANY_DEFAULTS` | `accept_credit` | Seller | The pseudonym has more defaults than `max_defaults`. In `check_order`: `TOO_MANY_DEFAULTS`. | Change your rule or refuse. |
| `POLICY:GUARANTOR_NOT_APPROVED` | `accept_credit` | Seller | The guarantor is not on your list. In `check_order`: `GUARANTOR_NOT_APPROVED`. | Change your rule or refuse. |
| `POLICY:ASSET_NOT_APPROVED` | `accept_credit` | Seller | The order's asset is not your rule's `asset`. In `check_order`: `ASSET_NOT_APPROVED`. | Refuse, or set a rule for that asset. |
| `POLICY:FEE_TOO_HIGH` | `accept_credit` | Seller | The fee is above your `max_fee_bps` of the amount, whoever pays it. In `check_order`: `FEE_TOO_HIGH`. | Change your rule or refuse. |
| `POLICY:ARBITER_NOT_APPROVED` | `accept_credit` | Seller | The arbiter is not on your list. In `check_order`: `ARBITER_NOT_APPROVED`. | Change your rule or refuse. |
| `PREMIUM_SHORT` | `accept_credit` | Seller | A buyer-paid fee is more than the free vault. | The company funds the vault; retry. |
| `BOND_SHORT` | `accept_credit` | Seller | After the fee, the free vault cannot lock the promised bond. | The company funds the vault; retry. |
| `GUARANTOR_CAPACITY` | `accept_credit` | Seller | The guarantor's free stake is below the exposure. | The guarantor stakes more, or refuse. |
| `SELLER_CONCENTRATION` | `accept_credit` | Seller | This order would take the guarantor past `seller_cap_bps` for you. | Wait for your other orders to end, or refuse. |

### Seller: delivery, claim, withdrawal

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NOT_ACCEPTED` | `mark_delivered` | Seller | Not `Accepted` or `Disputed`, or a proof is already filed. | Read `credit_of`. |
| `FINAL_AMOUNT_NEEDS_ACCEPTED` | `mark_delivered` | Seller | `final_amount` is not allowed during a dispute. | Omit it. |
| `BAD_FINAL_AMOUNT` | `mark_delivered` | Seller | `final_amount` is 0 or above the order. | Bill within the order. |
| `DISPUTE_CLOSED` | `mark_delivered` | Seller | The arbiter's time ran out before the proof. | Too late; call `resolve_timeout`. |
| `NOT_DELIVERED` | `claim_default` | Seller | No claim without `Delivered`. | Call `mark_delivered`, or read `credit_of`. |
| `NOT_DUE` | `claim_default`, `cancel_open` | Seller, anyone | Due date plus `grace` has not passed. | Wait until then. |
| `INSPECTION_OPEN` | `claim_default` | Seller | `inspect` has not passed since delivery. | Wait until then. |
| `GUARANTOR_SHORT` | `claim_default` | Seller | Stake is below what is due. Exposure accounting should prevent this. | Report it: see [SECURITY.md](../SECURITY.md). |
| `NOTHING_TO_WITHDRAW` | `withdraw` | Anyone | No balance for that asset. | Check `claimable_of` and the `asset` parameter. |

### Company

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `DEPOSIT_BELOW_FEE` | `register` | Company | Deposit is not above 0.35 NEAR + 0.001 NEAR per link, plus 0.004 NEAR per link with cover. | Attach more. |
| `BAD_LIMITS` | `register` | Company | `n`, `daily_links` or `max_links` is 0. | Ask the verifier to sign valid limits. |
| `STALE_ATTESTATION` | `register` | Company | Attestation is over 1 hour old. | Get a new one. |
| `BAD_SCOPE` | `register` | Company | Scope is empty or over 16. | Get a new attestation. |
| `ALREADY_EXPIRED` | `register` | Company | `valid_until` has passed. | Get a new attestation. |
| `AMC_ALREADY_USED` | `register` | Company | This AMC has opened a mandate before. | Issue a new AMC. |
| `KEY_IN_USE` | `register`, `reinstate` | Company | Registering: the key has been used. Reinstating: the key is mapped to a mandate. | Use a new key and AMC. |
| `UNKNOWN_VERIFIER` | `register` | Company | The verifier is not on the whitelist. | Use a listed verifier. |
| `BAD_SIGNATURE_ENCODING` | `register` | Company | `signature` is not 64 bytes of hex. | Fix the encoding. |
| `BAD_ATTESTATION` | `register` | Company | The signature does not match the arguments, this contract or the calling account. | Compare with `attestation_preview`; register from the account it was signed for. |
| `CREDIT_ASSET_MISMATCH` | `register` | Company | `credit.asset` is not the mandate's `asset`. | Ask the guarantor to sign matching assets. |
| `BAD_CREDIT_TERMS` | `register` | Company | `bond_bps` or `seller_cap_bps` above 10000, `premium_bps` above 2000, `min_tenor` above `max_tenor`, or `max_tenor` above 10 years. | Ask the guarantor to sign valid terms. |
| `BAD_TERMS_SIG` | `register`, `credit_unseal` | Company, guarantor | `terms_sig` is not 64 bytes of hex. | Fix the signature. |
| `TOKEN_CELL_USE_FT_TRANSFER_CALL` | `top_up` | Company | A token mandate without credit terms, or a sub-agent, takes no NEAR. | Fund with `ft_transfer_call`. |
| `ONLY_FUNDER` | `top_up`, `claim_refund`, `reinstate`, `object_unseal`, `settle_by_funder`, `dispute`, `reimburse`, token equivalents | Other accounts | Only the company's funding account. | Sign with it. |
| `NOTHING_TO_CLAIM` | `claim_refund` | Company | `unclaimed` is 0. | Nothing to do. |
| `REFRESH_UNPAID` | `refresh_key` | Company, verifier | Needs at least 0.25 NEAR. | Attach it. |
| `REINSTATE_UNPAID` | `reinstate` | Company | Needs at least 0.25 NEAR. | Attach it. |
| `NOT_TRIPPED` | `reinstate` | Company | Only a tripped mandate can be reinstated; a revoked one cannot. | Open a new mandate if it was revoked. |
| `NOT_SETTLEABLE` | `settle`, `settle_by_funder` | Agent, company | Not `Accepted` or `Delivered`. | Read `credit_of`. |
| `PARTIAL_DEPOSIT` | `settle_by_funder`, token settlement | Company | The attached amount is neither 0 nor the full amount. | Attach the full amount, or 0 to use the vault. |
| `NOT_DISPUTABLE` | `dispute`, token dispute | Company | Not `Accepted` or `Delivered`. | Too late to dispute. |
| `ESCROW_FULL_AMOUNT` | `dispute`, token dispute | Company | Less than the full amount attached. | Escrow the full amount. |
| `NO_DEBT` | `reimburse`, `enforce_recourse` | Company, guarantor | Nothing is owed on this order. | Nothing to do. |
| `PAY_FULL_DEBT` | `reimburse`, token repayment | Company | Attached plus free vault does not cover the debt. | Attach the remainder. |
| `WRONG_ASSET` | token settle, dispute, reimburse | Company, attacker | Paid in a token other than the mandate's. Tokens return. | Use the mandate's token. |
| `USE_FT_TRANSFER_CALL` | `settle_by_funder`, `dispute`, `reimburse` | Company | NEAR was attached in a token tree. | Use `ft_transfer_call`. |
| `BAD_MSG` | `ft_on_transfer` | Company, guarantor | Bad credit id in `msg`, or `dispute` without a reason hash. Tokens return. | See [msg formats](CONTRACT.md#ft_on_transfer-msg-formats). |

### Agent key

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NOT_AGENT_KEY` | `spend`, `hire`, `dismiss`, `open_credit`, `settle` | Other accounts | Signer or predecessor is not the contract account. | Use the agent's function-call key. |
| `NOT_ACTIVE` | `spend`, `hire`, `open_credit`, `top_up`, `refresh_key`, `update_signers` | Agent, company, verifier | The mandate is not active. | Read `present`. |
| `NOT_PARENT` | `dismiss` | Agent | That sub-agent is not yours. | Only its parent can dismiss it. |
| `NOT_YOUR_CREDIT` | `settle` | Agent | Another agent opened this order. | Sign with that agent, or the company uses `settle_by_funder`. |
| `SUSPENDED` | `settle` | Agent | A parent is tripped or closed. | The company reinstates it, or uses `settle_by_funder`. |
| `REPAY_GUARANTOR_FIRST` | `settle`, `settle_by_funder` without money | Agent, company | While a debt is open the vault repays the guarantor first. | `reimburse`, or settle with attached money. |
| `VAULT_SHORT` | `settle`, `settle_by_funder` | Agent, company | The vault cannot cover the order. Other orders' bonds are not usable. | Fund the vault, or attach the amount. |

### Closing and revocation

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NO_CELL` | most methods taking `cell`; agent methods | Anyone | No such mandate, or the agent key maps to none. | Check the id or key. |
| `ALREADY_CLOSED` | `revoke`, `revoke_by_kel`, `dismiss` | Anyone | Already revoked. | Nothing to do. |
| `NOT_AUTHORIZED` | `revoke`, `refresh_key` | Others | Only the company, the still-listed verifier, or (for `revoke`) the owner. | Sign with one of them. |
| `EVIDENCE_TOO_LONG` | `revoke` | Caller | `evidence` is over 128 bytes. | Shorten it. |
| `BAD_SIG_LEN` | `revoke_by_kel` | Relayer | `signature` is not 64 bytes. | Send the raw signature, base64. |
| `BAD_ECR_OPENING` | `revoke_by_kel`, `credit_unseal` | Relayer, guarantor | The opening does not hash to the commitment. | Send the legal entity's real opening. |
| `BAD_KEL_SIGNATURE` | `revoke_by_kel` | Relayer | Signature does not verify over `ixn`. | Send the signer's real event and signature; after a rotation, the verifier calls `update_signers` first. |
| `BAD_IXN_JSON` | `revoke_by_kel` | Relayer | `ixn` is not JSON. | Send the raw event bytes. |
| `NOT_IXN` | `revoke_by_kel` | Relayer | Event type is not `ixn`. | Only `ixn` events are supported. |
| `WRONG_AID` | `revoke_by_kel` | Relayer | Event's `i` is not the expected identifier. | Use the right identifier's event. |
| `NO_SEALS` | `revoke_by_kel` | Relayer | Event's `a` is not a list. | Use the anchoring event. |
| `NO_REVOCATION_SEAL` | `revoke_by_kel` | Relayer | No seal `{i: SAID, s: "1"}` with a `d`. An issuance anchor is not a revocation. | Use the revocation's anchor. |
| `ONLY_CELL_VERIFIER` | `update_signers`, `release_unseal` | Others | Only that mandate's verifier, while it is listed. | Sign with it. |
| `NOT_ROOT` | `update_signers` | Verifier | Sub-agents have no signers. | Call it on the root. |
| `COVER_ACTIVE` | `update_signers` | Verifier | Signers can't change while cover runs: a guarantor could name itself and skip the fee it owes for revoking. | Wait until cover ends. |

### Guarantor

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NOT_A_VERIFIER` | `stake`, token stake | Guarantor | Not on the whitelist. | Ask the owner. |
| `STAKE_ASSET_UNKNOWN` | token stake | Guarantor, attacker | No stake record yet for that token. Tokens return. | A mandate you signed in that token must be registered first. |
| `NO_STAKE` | `request_unstake`, `withdraw_stake` | Guarantor | No stake in that asset. | Check the `asset` parameter. |
| `UNSTAKE_TOO_EARLY` | `withdraw_stake` | Guarantor | No request, or `unstake_delay` has not passed. | Call `request_unstake` and wait. |
| `STAKE_EXPOSED` | `withdraw_stake` | Guarantor | The amount is above stake minus exposure. | Withdraw less, or wait for orders to end. |
| `OFFER_LIVE` | `cancel_open` | Others | Order is `Open` and inside `accept_ttl`. Only the company or guarantor can cancel now. | Wait. |
| `NOT_CANCELLABLE` | `cancel_open` | Anyone | Not `Open` or `Accepted`. | Delivered orders settle, dispute or default instead. |
| `RECOURSE_OPEN` | `enforce_recourse` | Guarantor | `recourse_until` has not passed. | Wait. |
| `ONLY_GUARANTOR` | `enforce_recourse`, `credit_unseal` | Others | Only the mandate's guarantor. | Sign with it. |
| `NOT_ENFORCED` | `credit_unseal` | Guarantor | Naming needs `Enforced`. Repaid orders stay sealed. | Call `enforce_recourse` first; if it is `Reimbursed`, naming is closed. |
| `LE_DID_NOT_SIGN` | `credit_unseal` | Guarantor | The legal entity's key did not sign these terms and this LEI. | Use the signed LEI; you cannot name another company. |
| `COMMIT_MISMATCH` | `credit_unseal`, `release_unseal` | Guarantor, verifier | `sha256(lei\|salt)` is not the commitment. | Use the committed LEI and salt. |

### Cover

`register` panics with the `COVER_*` codes when the terms the verifier signed break a rule. The other codes come from the claim methods, and from `accept_credit` for `UNDER_CLAIM`.

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `COVER_LIMIT_ZERO` | `register` | Company | `limit` is 0. | Get new terms signed. |
| `COVER_LIMIT_THIN` | `register` | Company | `limit` is under 10 × `max_links` × `unit`, so a few rulings could reach it. | Raise `limit` or lower `max_links`. |
| `COVER_LIMIT_HIGH` | `register` | Company | `limit` is over `n` × `unit`: it would lock money no claim can reach. | Lower `limit`. |
| `COVER_DEDUCTIBLE` | `register` | Company | `deductible_bps` is outside 1000 to 9000. | Fix the terms. |
| `COVER_PREMIUM` | `register` | Company | `premium_bps` is above 2000, or the fee would not leave one maximum payment under what the cover can pay. | Lower the rate or shorten `valid_until`. |
| `COVER_GUARANTOR` | `register` | Company | The company is its own guarantor. | Use another guarantor. |
| `COVER_WINDOW` | `register` | Company | `claim_window` is under 2 × `dispute_timeout` or over 10 years. | Fix the terms. |
| `COVER_TENOR` | `register` | Company | `valid_until` is more than 10 years away. | Shorten it. |
| `COVER_ARBITER` | `register` | Company | The arbiter is the company, the guarantor, the contract owner or the contract account. | Name another. |
| `COVER_SCOPE` | `register` | Company | The scope has the company, the guarantor, the arbiter or the contract account in it. | Remove them. |
| `NO_COVER` | any cover method | Anyone | That id is not a root with cover. | Read `cover_of`; it gives `root`. |
| `COVER_NOT_OFFERED` | `activate_cover` | Guarantor | Already activated, voided or released. | Read `cover_of`. |
| `COVER_NOT_ACTIVE` | `file_claim`, `void_cover`, `release_cover` | Company, arbiter, guarantor | Not activated yet, or already voided or released. | Read `cover_of`. |
| `PREMIUM_SHORT` | `activate_cover`, `accept_credit` | Guarantor, seller | The free vault cannot pay the fee. For cover, nothing changes and it stays `Offered`. | The company funds the vault. |
| `ACTIVATION_TOO_LATE` | `activate_cover` | Guarantor | Past `activate_by`, halfway through the term. Nothing is charged. | A new mandate. |
| `GUARANTOR_CAPACITY` | `activate_cover`, `accept_credit` | Guarantor, seller | Free stake is short. For cover the fee does not count; for orders it does. Orders and cover share one stake. | The guarantor stakes more. |
| `GUARANTOR_DELISTED` | `activate_cover`, `accept_credit` | Guarantor, seller | The guarantor left the whitelist. | Ask the owner, or use another mandate. |
| `MANDATE_EXPIRED` | `activate_cover`, `accept_credit` | Guarantor, seller | Past `valid_until`. | A new mandate. |
| `COMPANY_FROZEN` | `activate_cover`, `accept_credit` | Guarantor, seller | The company owes its guarantor. | The company repays first. |
| `CLAIM_OPEN` | `file_claim`, `void_cover`, `clear_agent`, `release_cover` | Company, arbiter, guarantor | One claim is open, and a tree has at most one. | Wait for the ruling or `claim_timeout`. |
| `COVER_EXHAUSTED` | `file_claim` | Company | The limit has been paid. | Nothing more can be claimed here. |
| `NO_PAYMENT` | `file_claim` | Company | No record: not paid, paid before activation, or the transfer bounced. | Check `payment_of`. |
| `ALREADY_CLAIMED` | `file_claim` | Company | That payment was already ruled on. | One claim per payment. |
| `WINDOW_CLOSED` | `file_claim` | Company | Past `claim_window` after the payment, or after `valid_until` if that came first. | Too late. |
| `NO_OPEN_CLAIM` | `resolve_claim`, `claim_timeout` | Arbiter, anyone | No claim is open, or that invoice is not the open one. | Read `cover_of`. |
| `RULING_TOO_LATE` | `resolve_claim` | Arbiter | Past `dispute_timeout`. | Anyone calls `claim_timeout`; the company can file again. |
| `BAD_LOSS` | `resolve_claim` | Arbiter | `loss` is 0, above the amount paid, or so small the payout rounds to 0. The claim stays open. | Use the real loss. |
| `NOT_DENIED` | `void_cover` | Arbiter | That payment has no denied claim. | Void needs a denial to point at. |
| `ARBITER_STILL_HAS_TIME` | `claim_timeout`, `resolve_timeout` | Anyone | The deadline has not passed. | Wait. |
| `NOTHING_TO_CLEAR` | `clear_agent` | Company | No upheld claim is waiting. | Nothing to do. |
| `TOO_EARLY` | `release_cover`, `release_unseal` | Guarantor, verifier | `valid_until` + `claim_window`, or the disclosure wait, has not passed. Revoking does not change this. | Wait. |
| `ONLY_GUARANTOR` | `activate_cover`, `release_cover`, `enforce_recourse`, `credit_unseal` | Others | Only the mandate's guarantor. | Sign with it. |
| `ONLY_ARBITER` | `resolve_claim`, `void_cover`, `resolve_dispute` | Others | Only the arbiter in the mandate. | Sign with it. |
| `ONLY_FUNDER` | `file_claim`, `clear_agent`, and other company methods | Others | Only the root's funder. | Sign with it. |
| `UNDER_CLAIM` | `accept_credit`, in `check_order` | Seller | A claim is open on the tree, or an upheld one is not cleared. | Wait. |

### Disputes

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `ONLY_ARBITER` | `resolve_dispute` | Others | Only the arbiter in the mandate. | Sign with it, or wait and call `resolve_timeout`. |
| `NOT_DISPUTED` | `resolve_dispute`, `resolve_timeout` | Anyone | Not `Disputed`. | Read `credit_of`. |
| `ARBITER_STILL_HAS_TIME` | `resolve_timeout` | Anyone | The deadline has not passed. | Wait. |

### Supervisor disclosure

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `NOT_SUPERVISOR` | `request_unseal` | Others | Not on the supervisor list. | Ask the owner. |
| `ALREADY_REQUESTED` | `request_unseal` | Supervisor | A live request exists, or the name is already released. | Read `get_unseal`. |
| `NO_REQUEST` | `object_unseal`, `release_unseal` | Company, verifier | No request. | Read `get_unseal`. |
| `ALREADY_RELEASED` | `object_unseal`, `release_unseal` | Company, verifier | The name is already public. | Nothing to do. |
| `REQUESTER_REMOVED` | `release_unseal` | Verifier | The requester left the list. | A listed supervisor must request again. |
| `TOO_EARLY` | `release_unseal` | Verifier | The waiting period has not passed. | Wait. |

### Owner and encoding

| Code | From | Who | Means | What to do |
|---|---|---|---|---|
| `ONLY_OWNER` | `set_verifier`, `set_supervisor` | Others | Only the owner. | Sign with it. |
| `BAD_HEX:<what>` | any method with a 32-byte hex field | Caller | `<what>` is not hex. `<what>` is one of `verifier_pk`, `w0`, `issuer_pk`, `lei_commit`, `ecr_commit`, `terms_hash`, `reason_hash`, `signer_pk`, `le_pk`, `delivery_hash`, `cover_terms_hash`, `evidence_hash`, `ruling_hash`. | Send lowercase hex. |
| `BAD_LEN:<what>` | the same | Caller | `<what>` is not 32 bytes. | Send 32 bytes. |
