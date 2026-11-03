# Changelog

The contract cannot be upgraded, so each change to it is a new deployment on a new testnet account. Newest first. Taken from the git log.

## {CONTRACT} (cover; not yet deployed from this branch)
- A guarantor that revokes returns the fee for 30-day periods not yet started, up to its free stake (`cover_fee_returned`). It used to keep all of it.

Attestation format `writ:attest:v7`. The direction changes: from net-30 for sellers to who pays when an agent is fooled. Net-30 stays as a second use of the same stake.

- **Fooled-agent cover** (`3e346d2`). `CoverArgs` signed with the mandate; `activate_cover`, `file_claim`, `resolve_claim`, `void_cover`, `claim_timeout`, `clear_agent`, `release_cover`; views `cover_of`, `payment_of`. `spend` takes an optional `context_hash`, kept with the payment under active cover. New rejections `UNDER_CLAIM` and `NOT_CLEARED`, with no strike.
- **Site and setup.** The site's main demo runs on one covered mandate: the visitor fools a real model, files, and rules as the arbiter. `make live-agent` sets up that mandate in USDC with restricted company and arbiter keys. The calculator now prices cover. The worker gives the model `pay_invoice` and `reject_invoice` and a ledger, and caches only answers that pay.
- CI run 41626045777: 125 attacks, 103 integration and 105 unit tests, 36 credential forgeries, `COVER_RESULT|PASS`. A contract audit followed that run, and `838562d` fixes its findings F1 to F6, so these numbers predate that commit.

## writ-net30.testnet

Commits `1bf20c8` to `95875b3`; CI for the stablecoin story in `41991ac`. Attestation format `writ:attest:v6`. Source metadata version `0.2.0`.

- **Hard bond.** Accepting panics `BOND_SHORT` when the free vault after the fee is below what the terms promise. It used to shrink the bond silently and move the gap to the guarantor (`1bf20c8`, `1f4ec8d`).
- **Tenor pricing.** `premium_bps` is per 30 days, charged on every started period from acceptance (`a893e4e`).
- **Fee payer.** `Buyer` or `Seller`, signed into the attestation. A seller-paid fee comes out of the seller's credited amount on every payment path (`c3fae1a`).
- **Usage orders.** `mark_delivered` takes `final_amount`; amount, bond, exposure and outstanding shrink at the promised ratio; links stay spent (`56ecc1b`).
- **Seller rules.** `set_seller_policy`, `seller_policy`, `check_order` reporting every failing reason; `accept_credit` enforces the stored rule with `POLICY:<reason>` (`ff2fb0d`).
- **Seller concentration.** `seller_cap_bps` is signed; accepting refuses `SELLER_CONCENTRATION`; exposure per guarantor and seller is kept on every release and default (`c6b52d0`).
- **Guarantor book.** Claims paid, recovered and a bounded seller list; `guarantor_book` reports utilisation, net loss, loss ratio and top sellers (`ca24e3e`).
- **Credit in a stablecoin.** `CreditArgs.asset`; stakes and claims per asset; `ft_on_transfer` takes `fund:`, `stake`, `settle:`, `dispute:` and `reimburse:`; `near_reserve` pays storage and hire fees in a token tree; `token_total`; token trees with credit terms can hire. NEP-330 source metadata and more `check_order` fields for a seller's UI (`90ddf24`).
- **Audit fixes before the locked deploy (`95875b3`).** A seller's rule also names its asset, a maximum fee and approved arbiters, with `ASSET_NOT_APPROVED`, `FEE_TOO_HIGH` and `ARBITER_NOT_APPROVED`; its storage deposit is 0.015 NEAR and any excess is returned (`A94`, `A95`). `check_order` adds `would_accept` and reports fixed values after acceptance. Accepting refuses a delisted guarantor (`GUARANTOR_DELISTED`, `A96`). `max_tenor` is at most 10 years (`A93`). The fee is capped at the amount. `RESERVE` is a new rejection, with no strike, when a token tree's NEAR reserve runs out. The payment record is kept per asset. Agent methods also require the predecessor to be the contract account. More gas for token transfers.

**API changes from `writ-surety`.** New optional `asset` on `withdraw`, `withdraw_stake`, `request_unstake`, `stake_of`, `claimable_of`. New optional `final_amount` on `mark_delivered`. New `credit` fields `fee_payer`, `seller_cap_bps`, `asset`. New views `check_order`, `seller_policy`, `guarantor_book`, `token_total`. Rule fields as above. Attestations signed for v5 no longer verify.

## writ-surety.testnet

Deployed in `393ec88`, tag `deployed-writ-surety` at `4eac190`. Attestation format `writ:attest:v5`.

- An invoice counts as paid only when money moved; `invoice_paid` is false until then (`d7aa03b`, `393ec88`).
- A ruling for the company keeps its invoice blocked (`393ec88`).
- The `revoked` event reports retained money as `retained`, not as `refund` (`d7aa03b`, `393ec88`).

Tests added between the two deployments, with no contract change: exact-value tests for every money path and deadline (`bb7a86f`), review tests (`fc2b9d4`), and the mutation baseline on the `writ-guarantee` contract (`f5ae1a2`, `cfbef5d`).

## writ-guarantee.testnet

Deployed in `c6830e3`.

- **The guarantor earns a fee.** `premium_bps` is in the signed mandate and paid from the company's vault when the seller accepts (`21bb6c5`).
- The verifier checks the terms signature (`5802145`).
- The credit story on testnet with every transaction (`c6830e3`).

## writ-credit-writ.testnet

Deployed in `7b4eb0a`. First generation with credit.

- **Credit with a named guarantor.** `open_credit`, `accept_credit`, `mark_delivered`, `settle`, `withdraw`, `dispute`, `claim_default`, `reimburse`, `enforce_recourse`, `credit_unseal`, `risk_card`, `liability_receipt`, guarantor stake. Bonds lock per order, the guarantor pays automatically, and identity is revealed only as the last step, with the legal entity's signature preventing framing another company (`1259af9`).
- **Audit rounds.** Inspection window before default, offers die with the mandate, proof during a dispute with a deadline, retained money repays the guarantor first and is released after repayment, spend and hire frozen while owing, failed transfers stay in the tree, entity record bound to the guarantor (`04a72b2`). Settling frozen while the company owes, guarantor and company cannot be the seller, disclosure survives a key rotation, frozen attempts are not strikes, invariant fuzz (`f0e5836`). The demo debt survives sweeping the tree (`2a843a2`).

## Before credit

Prepaid mandates only: `writ-mandate-writ.testnet` (`4e2a7b9`) and `writ.writmvyy7yqe-owner.testnet` (`269d440`).
