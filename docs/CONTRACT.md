# Contract reference

Source: `contract/src/lib.rs` (near-sdk 5.30). Deployed at `writ-net30.testnet`. Errors are in [ERRORS.md](ERRORS.md), events in [EVENTS.md](EVENTS.md), a walk-through in [INTEGRATE.md](INTEGRATE.md).

**API "cell" = mandate.** Every `cell` parameter is a mandate id. Also: "funder" is the company's funding account; "verifier" is a whitelisted account that signs attestations, and a verifier with stake and credit terms is a guarantor; "credit" is an order on credit.

## Calling conventions

- Parameters are named JSON: `{"credit":"7"}`.
- `U64` and `U128` are **strings**: `"7"`, `"1000000000000000000000000"`. Plain `u32` and `u64` are JSON numbers (`j`, `n`, `daily_links`, `max_links`, `max_strikes`, `bond_bps`, `premium_bps`, `seller_cap_bps`, `deductible_bps`, `min_bond_bps`, `max_fee_bps`, `max_defaults`, `unseal_delay_secs`).
- Timestamps are nanoseconds since the Unix epoch, as `U64`. Tenors and windows are seconds, as `U64`.
- Amounts are in the mandate's asset: yoctoNEAR (1 NEAR = 10^24) when `asset` is null, otherwise the token's smallest unit. Fees and storage in the [deposit table](#fees-and-deposits) are always NEAR.
- Hashes are lowercase hex of 32 bytes unless stated. `ixn` and `signature` in `revoke_by_kel` are base64.
- `Option` parameters may be omitted or null. `asset` omitted or null means NEAR.
- Deposit "none" means the method is not payable: near-sdk panics if you attach anything. Above the minimum, a deposit to `refresh_key` or `reinstate` stays in the contract.

## Agent methods

Callable only with a function-call key on the contract account (signer and predecessor must be the contract account). The protocol limits those keys to these five methods and to no deposit.

| Method | Parameters | Effect |
|---|---|---|
| `spend` | `preimage` string, `j` u32, `to` AccountId, `invoice_hash` string, `context_hash` hex string optional | Pays `j × unit` to `to`. Returns `Verdict::Paid` after the transfer succeeded, or `Rejected`. `context_hash` binds the invoice text and the model's decision to the payment; under active cover it is kept with the payment for a later claim. |
| `hire` | `preimage` string, `j` u32, `child` HireArgs | Spends `j` links to open a narrower mandate for a new key. Returns `Hired` or `Rejected`. The hire fee is paid by the root. |
| `dismiss` | `child` U64 | Closes that sub-agent and everything under it. Only its parent. Panics rather than rejects. |
| `open_credit` | `preimage` string, `j` u32, `to` AccountId, `invoice_hash` string, `due_at` U64 | Spends links, takes no money, charges 0.007 NEAR storage to the root. Returns `CreditOpened` or `Rejected`. |
| `settle` | `credit` U64 | Pays the seller from this agent's vault. Only the agent that opened it. Returns `CreditSettled` or panics. |

`preimage` is the hex link `w_{idx+j}` such that `sha256^j(preimage) == w_cur`.

`HireArgs`: `agent_pk` PublicKey, `w0` hex string, `scope` AccountId[], `valid_until` U64, `daily_links` u32, `max_links` u32.

`Verdict` (returned as JSON with one key):

```json
{"Paid":{"cell":"1","amount":"300000000000000000000000","idx":3,"remaining_links":47}}
{"Hired":{"cell":"1","child":"2","links":5,"remaining_links":42}}
{"CreditOpened":{"cell":"1","credit":"7","amount":"100000000000000000000000","due_at":"1790000000000000000"}}
{"CreditSettled":{"credit":"7","amount":"100000000000000000000000"}}
{"Rejected":{"cell":"1","reason":"SCOPE","strikes":1,"tripped":false}}
```

A rejection is a successful transaction with a hash, not a failure.

## Seller methods

| Method | Parameters | Caller | Deposit | Effect |
|---|---|---|---|---|
| `set_seller_policy` | `policy` SellerPolicy or null | any seller | 0.015 NEAR the first time; none after. Excess is returned. Removing the rule does not return the deposit, and setting one again costs it again. | Stores or removes the account's rule. |
| `accept_credit` | `credit` U64 | the order's seller | none | Charges a buyer-paid fee, locks the bond and the guarantor's exposure. |
| `mark_delivered` | `credit` U64, `delivery_hash` hex string, `final_amount` U128 optional | the order's seller | none | Files the proof. `final_amount` shrinks a usage order; only from `Accepted`, greater than 0, at most the order. |
| `claim_default` | `credit` U64 | the order's seller; the guarantor once the seller has been silent past a further `recourse` | none | Pays the seller the full amount from the agent's vault, root vault, bond, then stake. Starts recourse. |
| `withdraw` | `asset` AccountId optional | anyone with a balance | none | Sends everything in `claimable` for that asset. A failed transfer is credited back. |

`SellerPolicy`, all fields required: `asset` AccountId or null (null = NEAR; must be present, because `max_amount` is in this asset), `max_amount` U128, `max_tenor_secs` U64, `min_bond_bps` u32, `max_fee_bps` u32 (the most the fee may be as a share of the amount, whoever pays), `max_defaults` u32, `guarantors` AccountId[] and `arbiters` AccountId[] (at most 8 each; empty means any).

## Company methods

| Method | Parameters | Caller | Deposit | Effect |
|---|---|---|---|---|
| `register` | `args` RegisterArgs | the company; the attestation is signed for this account | more than 0.35 NEAR + 0.001 NEAR × `n`; with cover, 0.004 NEAR × `n` more, in NEAR even on a token mandate | Verifies the attestation, opens the mandate, adds the agent key. NEAR mandate: vault = deposit − fee. Token mandate with credit: the excess becomes `near_reserve`. Token mandate without credit: the excess is returned. A token mandate with credit or cover opens the guarantor's stake record in that token. Each AMC registers once; the attestation must be under 1 hour old. Returns the mandate id as U64. |
| `top_up` | `cell` U64 | funder | any | NEAR mandate: adds to the vault. Token root with credit: adds to `near_reserve`. Other token mandates panic. |
| `settle_by_funder` | `credit` U64 | funder | 0 to pay from the root vault, or at least the order's amount; excess goes to `claimable`. Token trees use `ft_transfer_call`. | Pays the seller. Works after revocation and expiry. |
| `dispute` | `credit` U64, `reason_hash` hex string | funder | at least the order's amount, or `ft_transfer_call` | Stops a default. From `Accepted` or `Delivered`. |
| `reimburse` | `credit` U64 | funder | what the free vault does not cover; excess goes to `claimable` | Repays the guarantor from the free vault first, then the deposit. Unfreezes when no other debt remains. |
| `reinstate` | `cell` U64 | funder | at least 0.25 NEAR | Re-adds the key of a tripped mandate. |
| `refresh_key` | `cell` U64 | funder, or the mandate's still-listed verifier | at least 0.25 NEAR | Re-adds the same key with a fresh gas allowance. |
| `revoke` | `cell` U64, `evidence` string up to 128 bytes | funder, the mandate's still-listed verifier, or owner | none | Deletes the keys of the tree and refunds the vaults, or keeps them in the root while credit is open or a debt remains. |
| `claim_refund` | `cell` U64 | funder | none | Collects `unclaimed`: a failed refund, or retained money released after debts ended. |
| `object_unseal` | `cell` U64 | funder | none | Records a public objection to a supervisor's request. Not a veto. |

`RegisterArgs`:

| Field | Type | Meaning |
|---|---|---|
| `amc_said` | string | The AMC's SAID. The credential itself is not on-chain. |
| `issuer_aid`, `issuer_pk` | string, hex | The employee's KERI identifier and current Ed25519 key. |
| `agent_pk` | PublicKey | `ed25519:<base58>`. Used once, ever. |
| `w0` | hex | Top of the budget chain. |
| `n`, `unit` | u32, U128 | Number of links, value of a link. |
| `scope` | AccountId[] | 1 to 16 accounts. Sellers must be here. |
| `valid_until` | U64 | Expiry. |
| `daily_links`, `max_links`, `max_strikes` | u32 | Daily rate, per-payment cap, strikes before the key is deleted (0 = never). |
| `lei_commit` | hex | `sha256(LEI\|salt)`. |
| `ecr_commit` | hex | `sha256(le_aid\|le_pk\|ecr_said\|salt)`. |
| `verifier` | AccountId | Must be on the whitelist. |
| `attested_at` | U64 | When the verifier checked the chain. |
| `signature` | hex, 64 bytes | The verifier's Ed25519 signature over the attestation message. |
| `asset` | AccountId, optional | NEP-141 settlement token. Omitted = NEAR. |
| `credit` | CreditArgs, optional | Omitted = this mandate cannot buy on credit. |
| `cover` | CoverArgs, optional | Omitted = no fooled-agent cover. |

`CreditArgs`:

| Field | Type | Meaning |
|---|---|---|
| `limit` | U128 | Maximum outstanding. |
| `bond_bps` | u32 | Bond per order, at most 10000. |
| `premium_bps` | u32 | Fee per 30 days or part of it, at most 2000. |
| `min_tenor`, `max_tenor` | U64 | Allowed time to `due_at`, in seconds. `max_tenor` is at most 10 years. |
| `terms_hash` | hex | Hash of the terms the company signed. |
| `terms_sig` | hex, 64 bytes | Legal entity's signature over `writ:terms:v1\ncontract=…\namc=…\nterms=…\nlei=…`. Checked only at naming. |
| `entity_tag` | string | The guarantor's fixed pseudonym for the company. |
| `arbiter` | AccountId | Not the guarantor, the company, or the seller. |
| `fee_payer` | `"Buyer"` or `"Seller"` | Who pays the fee. |
| `seller_cap_bps` | u32 | Largest exposure to one seller, as a share of stake; 0 = no cap. |
| `asset` | AccountId or null | Must equal the mandate's `asset`. |

`CoverArgs`, signed by the verifier, who is the guarantor:

| Field | Type | Meaning |
|---|---|---|
| `limit` | U128 | The most the guarantor pays in total under this mandate. At least 10 × `max_links` × `unit`, at most `n` × `unit`. |
| `deductible_bps` | u32 | The company's share of each loss, 1000 to 9000. |
| `premium_bps` | u32 | Fee on `limit` per 30 days or part of it, at most 2000. Charged once, at activation, for all of `valid_until`. Never refunded. At register the fee must leave one maximum payment under what the cover can pay, which is `limit` or the company's repaid share of `n × unit`, whichever is less. |
| `claim_window` | U64 | Seconds after a payment during which it can be claimed. At least 2 × `dispute_timeout`, at most 10 years. |
| `arbiter` | AccountId | Rules on claims. Not the company, the guarantor or the contract owner. |
| `terms_hash` | hex | Hash of the terms the arbiter rules on: what is covered and excluded, the seller's chance to respond, the company's statement that it was not refunded, transfer of rights. |

With cover, the company cannot be the guarantor, `valid_until` must be within 10 years, the arbiter cannot be the contract account, and `scope` must not contain the company, the guarantor, the arbiter or the contract account. A hired agent's scope can only narrow, so this holds for the whole tree.

The attestation message is `attestation_message` in `lib.rs`: a `writ:attest:v7` line, then `contract=`, `amc=`, `issuer_aid=`, `issuer_pk=`, `agent_pk=`, `w0=`, `n=`, `unit=`, `scope=` (comma-separated), `valid_until=`, `daily_links=`, `max_links=`, `max_strikes=`, `lei_commit=`, `ecr_commit=`, `funder=`, `verifier=`, `attested_at=`, `asset=` (`near` if none), `credit=` (`none`, or the CreditArgs values comma-separated in the order of the table above, with `near` for no asset), `cover=` (`none`, or `limit,deductible_bps,premium_bps,claim_window,arbiter,terms_hash`). Check yours with the view `attestation_preview`.

`keri/issuer.py init --cover-limit … --cover-arbiter …` has the legal entity sign the cover terms (`writ:cover:v1\ncontract=…\namc=…\ncover=…`) into `keri/bundle/cover.json`. They are not in the AMC, whose schema does not change. `keri/verify.py attest` refuses terms the legal entity did not sign or the contract would refuse.

## Guarantor methods

| Method | Parameters | Caller | Deposit | Effect |
|---|---|---|---|---|
| `stake` | none | a whitelisted verifier | the amount to stake | Adds NEAR stake. Token stake goes through `ft_transfer_call`. |
| `request_unstake` | `asset` AccountId optional | guarantor | none | Starts `unstake_delay`. |
| `withdraw_stake` | `amount` U128, `asset` AccountId optional | guarantor | none | Up to stake minus exposure, after the delay. Each withdrawal needs a new request. |
| `enforce_recourse` | `credit` U64 | guarantor | none | After `recourse_until`, closes the tree and repays from what is left in it. Ends in `Enforced` or, if that cleared the debt, `Reimbursed`. Can run again. |
| `credit_unseal` | `credit` U64, `lei` string, `salt` string, `ecr` EcrOpening | guarantor | none | From `Enforced`: names the company. |
| `update_signers` | `cell` U64, `issuer_aid` string, `issuer_pk` hex, `ecr_commit` hex | the mandate's still-listed verifier | none | After a key rotation. Root mandates only. |
| `release_unseal` | `cell` U64, `lei` string, `salt` string | the mandate's still-listed verifier | none | After a supervisor's request and the waiting period. |

`EcrOpening`: `le_aid`, `le_pk` (hex), `ecr_said`, `salt`, all strings.

## Cover methods

The contract cannot tell whether an agent was fooled. A named arbiter decides, and the limit caps what a wrong or bought ruling costs. None of these takes a deposit, so restricted keys can call them. `root` is the root mandate.

| Method | Parameters | Caller | Needs | Effect |
|---|---|---|---|---|
| `activate_cover` | `root` U64 | the guarantor, still on the whitelist | cover `Offered`; root `Active` and not expired; in the first half of the term since register (`activate_by`); no debt to the guarantor; free vault at least the fee; stake − exposure at least `limit`, not counting the fee | Fee = `limit` × `premium_bps` / 10000 × started 30-day periods to `valid_until`, at most `limit`. Moves it from the root's vault to the stake and `earned`. Adds `limit` to `exposure`. Cover becomes `Active`. All or nothing. |
| `file_claim` | `root` U64, `invoice_hash` hex, `evidence_hash` hex | funder | cover `Active`; no open claim; `paid` below `limit`; a payment recorded under active cover with no claim yet; inside the window, which runs from the earlier of the payment and `valid_until` | Opens the claim. The whole tree is refused with `UNDER_CLAIM`. `evidence_hash` goes only to the event. |
| `resolve_claim` | `root` U64, `invoice_hash` hex, `ruling` Ruling, `ruling_hash` hex | arbiter | this is the open claim; up to and including `dispute_timeout` after filing | Uphold: 0 < `loss` ≤ the amount paid, and the payout must not round to 0. Pays `loss` × (10000 − `deductible_bps`) / 10000 rounded down, at most what is locked, from the stake and from `exposure`. Goes to the root's vault if the tree has open credit or a debt, otherwise to the company's `claimable`. The tree is then refused with `NOT_CLEARED`. Deny: nothing moves. |
| `void_cover` | `root` U64, `invoice_hash` hex | arbiter | cover `Active`; no open claim; that payment's claim was denied | Fraud found: cover ends, the lock comes back, the fee stays. Becomes `Voided`. Later payments are not recorded. |
| `claim_timeout` | `root` U64 | anyone | an open claim, past `dispute_timeout` | The payment goes back to no claim, `timed_out` + 1, nothing moves. It can be filed again inside its window. |
| `clear_agent` | `root` U64 | funder | an upheld claim to clear; no open claim | The tree works again. A record, not a security control; the guarantor's control is `revoke`. |
| `release_cover` | `root` U64 | the guarantor, listed or not | cover `Active`; no open claim; past `valid_until` + `claim_window` | The lock comes back. Becomes `Released`. Revoking the mandate does not bring this forward. |

`Ruling` is `"Deny"` or `{"Uphold":{"loss":"…"}}`. `CoverState` is `Offered`, `Active`, `Voided` or `Released`.

While a claim stops a tree, `spend`, `hire` and `open_credit` return `Rejected` with no strike, and `accept_credit` panics `UNDER_CLAIM`. `settle` and `settle_by_funder` still work: stopping them would manufacture a default. A sub-agent's payment is claimed on its root, and dismissing the sub-agent does not lift the stop.

Only a payment whose money arrived while cover was `Active` is recorded. A transfer that bounced, a payment before activation, an order on credit, and a callback landing after release or void leave no record, so they cannot be claimed.

## Other methods

| Method | Parameters | Caller | Deposit | Effect |
|---|---|---|---|---|
| `new` | `owner` AccountId, `unseal_delay_secs` u64 optional, `windows` Windows optional | the contract account, in the deploy batch | none | Initializes. |
| `set_verifier` | `account` AccountId, `pk_hex` hex optional | owner | none | Adds a verifier and its Ed25519 key, or removes it when `pk_hex` is omitted. |
| `set_supervisor` | `account` AccountId, `enabled` bool | owner | none | Adds or removes a supervisor. |
| `request_unseal` | `cell` U64, `reason_hash` hex | supervisor | none | Public request; the waiting period starts. |
| `revoke_by_kel` | `cell` U64, `ixn` base64, `signature` base64, `ecr` EcrOpening optional | anyone | none | Verifies a KERI revocation anchor: the AMC by the employee, or the ECR by the legal entity when `ecr` opens the commitment. Then closes as `revoke` does. |
| `cancel_open` | `credit` U64 | `Open`: funder or guarantor, or anyone after `accept_ttl`. `Accepted`: anyone after due plus `grace`. | none | Releases limit, bond and exposure, and frees the invoice. Links are not refunded. |
| `resolve_dispute` | `credit` U64, `to_seller` bool | arbiter | none | Rules on a dispute. |
| `resolve_timeout` | `credit` U64 | anyone, after the dispute deadline | none | The seller wins with a delivery proof, otherwise the company. |
| `ft_on_transfer` | `sender_id` AccountId, `amount` U128, `msg` string | a NEP-141 token, through `ft_transfer_call` | see [below](#ft_on_transfer-msg-formats) | Token entry point. |
| `on_transfer`, `on_refund`, `on_withdraw` | internal | the contract itself (`#[private]`) | none | Callbacks. Other callers panic. |

## Views

Free to call. `Option` results are JSON null when the item does not exist.

| View | Parameters | Returns |
|---|---|---|
| `risk_card` | `cell` U64 | `asset`, `near_reserve`, `legal_entity` ("sealed" or the LEI), `lei_commit`, `guarantor`, `guarantor_listed`, `guarantor_stake`, `guarantor_exposure`, `guarantor_unstake_at`, `credit_limit`, `outstanding`, `bond_bps`, `premium_bps`, `fee_payer`, `seller_cap_bps`, `guarantor_earned`, `bond_available`, `min_tenor`, `max_tenor`, `terms_hash`, `arbiter`, `entity_tag`, `settled`, `settled_amount`, `defaults`, `first_seen`, `frozen`, `status`. Null if the mandate has no credit terms. |
| `check_order` | `credit` U64, `policy` SellerPolicy optional | `{ok, would_accept, reasons, order}`. `would_accept` means `accept_credit` would succeed now, always under the stored rule. `ok` means no reason was found under the rule asked about: `policy` if passed, otherwise the stored rule. `reasons` lists every failure. After acceptance, `fee`, `fee_periods`, `bond` and `exposure` are the values fixed on the order. `order` has `credit`, `cell`, `seller`, `status`, `asset`, `amount`, `original_amount`, `seller_receives`, `due_at`, `tenor_secs`, `fee`, `fee_periods`, `fee_payer`, `bond`, `bond_bps`, `exposure`, `guarantor`, `guarantor_listed`, `guarantor_stake`, `guarantor_total_exposure`, `entity_tag`, `settled`, `defaults`, `terms_hash`, `arbiter`, `policy_applied`. Panics `NO_CREDIT` for an unknown id. |
| `seller_policy` | `seller` AccountId | SellerPolicy or null. |
| `credit_of` | `credit` U64 | The Credit: `id`, `cell`, `root`, `seller`, `amount`, `original_amount`, `asset`, `invoice_hash`, `opened_at`, `due_at`, `status`, `bond_locked`, `exposure`, `fee`, `fee_periods`, `delivery_hash`, `delivered_at`, `dispute_escrow`, `debt`, `recourse_until`. |
| `liability_receipt` | `credit` U64 | `credit`, `status`, `seller`, `amount`, `asset`, `due_at`, `invoice_hash`, `agent_path`, `amc_said`, `guarantor`, `terms_hash`, `entity_tag`, `lei_commit`, `legal_entity`. |
| `claimable_of` | `account` AccountId, `asset` AccountId optional | U128. |
| `stake_of` | `account` AccountId, `asset` AccountId optional | `amount`, `exposure`, `unstake_at`, `earned`, `claims_paid` (all payments from the stake), `recovered`, `sellers`, `cover_paid` (the part of `claims_paid` on cover claims; nobody owes it back). `exposure` counts orders and locked cover together. |
| `guarantor_book` | `account` AccountId, `asset` AccountId optional | `asset`, `stake`, `exposure`, `utilisation_bps`, `earned`, `claims_paid`, `cover_paid`, `recovered`, `net_loss`, `loss_ratio_bps` (null before any fee), `top_sellers` (at most 5 `{seller, exposure}`). |
| `cover_of` | `cell` U64, any mandate in the tree | `root`, `asset`, `state`, `guarantor`, `arbiter`, `limit`, `remaining` (what is locked now), `paid`, `premium`, `deductible_bps`, `premium_bps`, `claim_window`, `terms_hash`, `upheld`, `denied`, `timed_out`, `open_claim` (invoice hash or null), `needs_clear`, `guarantor_stake`, `guarantor_exposure`, `guarantor_unstake_at`, `dispute_timeout`, `root_valid_until`, `activate_by`, `premium_if_activated_now` (null unless `Offered`). Null if the tree has no cover. |
| `payment_of` | `cell` U64, any mandate in the tree, `invoice_hash` hex | `cell` (the mandate that paid), `to`, `amount`, `paid_at`, `context_hash`, `claim`: `"None"`, `{"Open":{"filed_at"}}`, `{"Upheld":{"loss","payout","ruling_hash"}}` or `{"Denied":{"ruling_hash"}}`. Null if not recorded. |
| `present` | `cell` U64 | `cell`, `chain_valid`, `credit`, `cover` (true only while cover is `Active`; other states are in `cover_of`), `verifier`, `not_revoked`, `not_expired`, `within_limit`, `scope`, `amc_said`, `lei`, `lei_commit`, `status`, `parent`, `children`, `depth`. |
| `get_cell` | `cell` U64 | The whole mandate record. |
| `cell_of` | `agent_pk` PublicKey | Mandate id or null. |
| `get_unseal` | `cell` U64 | `requester`, `reason_hash`, `requested_at`, `objected`, `lei`. |
| `invoice_paid` | `cell` U64, `invoice_hash` hex | True only after the money moved. |
| `token_total` | `asset` AccountId | The contract's books for that token. Its balance should be at least this. |
| `solvency` | none | `vault_total`, `balance`, `storage`, `solvent`. NEAR only. |
| `stats` | none | `cells`, `paid`, `paid_yocto`, `rejected`, `tripped`, `revoked`. |
| `windows` | none | This deployment's windows, in seconds: `accept_ttl`, `inspect`, `grace`, `recourse`, `dispute_timeout`, `unstake_delay`. |
| `verifiers` | none | `[account, pk_hex]` pairs. |
| `owner` | none | The owner account. |
| `attestation_preview` | `args` RegisterArgs, `funder` AccountId | The exact string the verifier must sign. |
| `contract_source_metadata` | none | NEP-330: `version` `0.2.0`, `link`, `standards`. Generated by near-sdk. |

## `ft_on_transfer` msg formats

Send with `ft_transfer_call` on the token (1 yoctoNEAR attached, as NEP-141 requires). `msg` is trimmed first.

| `msg` | Sender | Effect | When it does not apply |
|---|---|---|---|
| `<cell id>` or `fund:<cell id>` | funder | Adds to the vault. | Wrong token, wrong sender, mandate not active, or an unparsable id: tokens are returned without a panic, and `deposit_refused` is logged if the mandate exists. |
| `stake` | guarantor | Adds to its stake in that token. | Panics `NOT_A_VERIFIER` or `STAKE_ASSET_UNKNOWN`: the stake record opens when a verifier signs its first mandate in that token. |
| `settle:<credit id>` | funder | Settles; at least the full amount; excess goes to `claimable`. | Panics, tokens return. |
| `dispute:<credit id>:<reason_hash>` | funder | Disputes; at least the full amount in escrow. | Panics, tokens return. |
| `reimburse:<credit id>` | funder | Repays the guarantor; free vault first; excess goes to `claimable`. | Panics, tokens return. |

A panic returns the tokens through NEP-141's `ft_resolve_transfer`.

## Windows

Seconds, set once by `new`. The view `windows` returns them, and demo deployments use short values (`DEMO_WINDOWS` in `app/src/near.ts`).

| Window | Default | Controls |
|---|---|---|
| `accept_ttl` | 86400 (1 day) | How long an order can wait for acceptance. |
| `inspect` | 259200 (3 days) | Delivery to the earliest default. |
| `grace` | 259200 (3 days) | Due date to the earliest default; also to the earliest cancel of an undelivered order. |
| `recourse` | 1209600 (14 days) | Default to the earliest `enforce_recourse`; also how long a seller can stay silent before the guarantor can claim for it. |
| `dispute_timeout` | 1209600 (14 days) | How long the arbiter has, on disputes and on cover claims. |
| `unstake_delay` | 2592000 (30 days) | Request to withdrawal of stake. |
| `unseal_delay_secs` (separate parameter) | 120 | Supervisor's request to `release_unseal`. |

## Fees and deposits

| Item | Amount | Paid by |
|---|---|---|
| Register | 0.35 NEAR + 0.001 NEAR per link | Attached by the company |
| Cover records | 0.004 NEAR per link, on a mandate with cover. The largest record, measured in the bench (`B44`), is 355 bytes, or 0.00355 NEAR | Attached by the company at register |
| Cover fee | see `activate_cover`, in the mandate's asset | Root vault, to the guarantor |
| Hire | 0.1 NEAR allowance + 0.02 NEAR storage + 0.001 NEAR per link | Root vault, or `near_reserve` in a token tree |
| Order storage | 0.007 NEAR, not refunded | Root vault, or `near_reserve` in a token tree |
| Seller's rule | 0.015 NEAR once | Attached by the seller |
| Key allowance | 0.25 NEAR for a root agent, 0.1 NEAR for a sub-agent | Covered by the fees above; `refresh_key` and `reinstate` attach 0.25 NEAR |

## Limits in code

16 accounts in a scope; 3 levels of hires below the root; 16 agents in a tree; 8 guarantors and 8 arbiters in a seller's rule; `max_tenor` of 10 years; 8 sellers in the guarantor's book; `evidence` up to 128 bytes; attestation under 1 hour old; one open claim per tree; cover limit at least 10 maximum payments.
