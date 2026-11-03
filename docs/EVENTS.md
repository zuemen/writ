# Events

Every event is a NEP-297 log line:

```
EVENT_JSON:{"standard":"writ","version":"1.0.0","event":"credit_opened","data":[{"credit":"7","cell":"1","seller":"seller.testnet","amount":"100000000000000000000000","due_at":"1790000000000000000"}]}
```

`data` always holds one object. Field values are strings unless marked. A transaction that panics logs nothing. "Cell" in a field name is the API's word for a mandate ([CONTRACT.md](CONTRACT.md)).

## Mandates and payments

| Event | Fields | Emitted by |
|---|---|---|
| `registered` | `cell`, `amc_said`, `agent_pk`, `verifier`, `vault`, `near_reserve`, `n` (number), `unit` | `register` |
| `rejected` | `cell`, `reason`, `to` (not from `hire`), `j` (number), `strikes` (number) | `spend`, `hire`, `open_credit`, when policy refuses. See [ERRORS.md](ERRORS.md#rejected-reasons). |
| `tripped` | `cell`, `agent_pk` | The strike that deletes the key, right after `rejected`. |
| `paid` | `cell`, `to`, `amount`, `idx` (number), `invoice` | `spend`'s callback, after the money arrived. |
| `refunded` | `cell`, `amount` | `spend`'s callback, when the transfer failed: the money went back to the vault, or to the company if the mandate closed meanwhile. |
| `retained` | `cell`, `amount` | The same, when the mandate closed and the company still owes: the money stays in the root. |
| `hired` | `cell`, `child`, `links` (number), `agent_pk` | `hire` |
| `revoked` | `cell`, `status` (object, for example `{"Revoked":{"by":"…","evidence":"…"}}`), `refund`, `retained` | Once per mandate closed by `revoke`, `revoke_by_kel`, `dismiss` or `enforce_recourse`. `refund` and `retained` are that mandate's share. |
| `refund_failed` | `cell`, `amount` | A refund bounced; the amount is in `unclaimed`. |
| `refreshed` | `cell` | `refresh_key` |
| `reinstated` | `cell` | `reinstate` |
| `signers_updated` | `cell`, `issuer_pk` | `update_signers` |
| `deposited` | `cell`, `token`, `amount` | `ft_on_transfer`, funding a mandate. |
| `deposit_refused` | `cell`, `token`, `sender` | `ft_on_transfer`, when the token, sender or mandate state is wrong. The tokens are returned. |

## Credit

| Event | Fields | Emitted by |
|---|---|---|
| `credit_opened` | `credit`, `cell`, `seller`, `amount`, `due_at` | `open_credit`. A seller watches this for new orders. |
| `credit_accepted` | `credit`, `bond`, `premium` (charged now; 0 if the seller pays), `fee` (the whole fee), `guarantor_exposure` | `accept_credit` |
| `credit_delivered` | `credit`, `final_amount`, `original_amount` | `mark_delivered`, including during a dispute. |
| `credit_settled` | `credit`, `amount` | `settle`, `settle_by_funder`, a token settlement, or a dispute won by the seller. |
| `credit_disputed` | `credit`, `reason_hash` | `dispute`, or a token dispute. |
| `credit_resolved` | `credit`, `to_seller` (boolean) | `resolve_dispute`, `resolve_timeout`. |
| `credit_defaulted` | `credit`, `guarantor_paid`, `recourse_until` | `claim_default`. `guarantor_paid` of `"0"` means no debt and no freeze. |
| `credit_reimbursed` | `credit` | `reimburse`, or `enforce_recourse` when money in the tree cleared the debt. |
| `credit_enforced` | `credit` | `enforce_recourse` when a debt remains. |
| `credit_unsealed` | `credit`, `lei`, `le_aid` | `credit_unseal`: the company is named. |

## Cover

`cell` is the root mandate. `invoice` is the lowercase invoice hash.

| Event | Fields | Emitted by |
|---|---|---|
| `cover_activated` | `cell`, `guarantor`, `premium`, `limit` | `activate_cover` |
| `claim_filed` | `cell`, `invoice`, `amount`, `evidence_hash` | `file_claim`. The evidence hash is on chain only here. |
| `claim_upheld` | `cell`, `invoice`, `loss`, `payout`, `retained` (boolean: true means it stayed in the root's vault because the tree owes), `ruling_hash` | `resolve_claim` |
| `claim_denied` | `cell`, `invoice`, `ruling_hash` | `resolve_claim` |
| `claim_timed_out` | `cell`, `invoice` | `claim_timeout` |
| `cover_fee_returned` | `cell`, `amount` | `revoke` by the guarantor, when periods have not started |
| `cover_voided` | `cell`, `invoice`, `released` | `void_cover` |
| `agent_cleared` | `cell` | `clear_agent` |
| `cover_released` | `cell`, `released` | `release_cover` |

## Guarantors and sellers

| Event | Fields | Emitted by |
|---|---|---|
| `staked` | `guarantor`, `amount`, `asset` (null = NEAR) | `stake`, or a token stake. |
| `seller_policy_set` | `seller` | `set_seller_policy`, including removal. |

## Disclosure by a supervisor

| Event | Fields | Emitted by |
|---|---|---|
| `unseal_requested` | `cell`, `requester`, `reason_hash`, `releasable_at` | `request_unseal` |
| `unseal_objected` | `cell` | `object_unseal` |
| `unsealed` | `cell`, `lei`, `requester`, `objected` (boolean) | `release_unseal` |

## Methods with no event of their own

An indexer has to read state for these: `cancel_open` (read `credit_of`; status `Cancelled`), `withdraw`, `withdraw_stake`, `request_unstake`, `claim_refund`, `top_up`, `set_verifier`, `set_supervisor`. A failed withdrawal is silently credited back; read `claimable_of`. `dismiss` emits only `revoked`.
