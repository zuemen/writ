# Threat model

**Status: testnet only. Not audited. Not for real funds.** To report a problem, see [SECURITY.md](../SECURITY.md).

Terms are defined in [ARCHITECTURE.md](ARCHITECTURE.md#terms). `A..` and `B..` are tests in `contract/tests/bench.rs`, tabulated in [bench.md](bench.md); `F..` are in `keri/test_forgeries.py`.

## Assets

| Asset | Where it lives | Who should control it |
|---|---|---|
| Company's money | Mandate vaults; `near_reserve` in token trees; `unclaimed` | The company, inside the limits it agreed |
| Bond | Locked per order inside the root vault | Released to the order it backs |
| Guarantor's stake | `stakes`, per guarantor and per asset | The guarantor, except what covers open exposure, which counts orders and locked cover together |
| Payment records | One per invoice under active cover, with `context_hash` and the claim's state | The contract; the arbiter's ruling changes the claim |
| Seller's claim | `claimable`, per account and per asset | The seller |
| Budget | Hash-chain seed held by the employee; links released to the agent | The employee |
| Company's name | LEI and salt, off-chain with the guarantor; only `sha256(LEI\|salt)` on-chain | The company, until the conditions for naming are met |
| Agent keys | Function-call keys on the contract account | The contract adds and deletes them |
| Contract's NEAR balance | Pays storage and agent gas | Each mandate's fee pays its own share, except for over-long strings a verifier writes (see Limits) |

## Attackers

| Attacker | Wants to |
|---|---|
| Prompt injection against an honest agent | Redirect, repeat or inflate a payment or an order |
| Whoever steals an agent key | Spend beyond the mandate, reach other methods, hire |
| A stranger | Revoke, claim or disclose what is not theirs, or burn shared storage and gas |
| A dishonest seller | Claim without delivering, claim early, bill more, drain another seller's bond |
| A dishonest company | Default and keep its money, stall, promise a bond it cannot fund, walk away by revoking |
| A company and a straw seller together | Take the guarantor's stake with false orders, or with a fooled payment that wasn't |
| A company making a false claim | Be repaid for a real purchase |
| An arbiter bought by either side | Pay a false claim, or deny a true one and end the cover |
| A dishonest guarantor | Name the wrong company, name early, rule on its own dispute, pull stake that backs orders |
| A fake token contract | Credit itself, or pay in a token it was not asked for |
| Owner, verifier or supervisor acting beyond their role | Move money, or disclose by themselves |

## Assumptions

- NEAR enforces function-call key restrictions before contract code runs, and `ed25519_verify` and `sha256` are correct.
- The verifier really checks the credential chain off-chain before signing. The contract only checks that a whitelisted verifier signed.
- The employee keeps the hash-chain seed, and the guarantor keeps the LEI salt.
- The token named in a mandate behaves as NEP-141 says. The guarantor signs which token; a fake token can only touch its own books (`A89`), but nothing makes the signed token a good one.
- Someone submits a signed revocation event. Writ ships no relayer.
- Any legal effect depends on a real agreement off-chain. The contract cannot enforce anything outside its own balances and keys.

## Trust model

| Who | What you must trust them for | What they cannot do |
|---|---|---|
| Guarantor (a verifier with stake) | checked the company's credential chain before signing; pays first when the vault runs short, so it has its own money at risk | disclose on-chain before the recourse period ends and while a debt stays unpaid (`A49`, `A50`), although it holds the LEI and salt, so the contract cannot stop it telling someone off-chain; withdraw stake that covers open orders (`A60`). **If it also holds the company's legal-entity key it could name that company falsely**: the contract checks the signature; the link between that key and the LEI is checked off-chain |
| Arbiter | ruling a dispute; if it does nothing, the seller wins with a delivery proof and the company otherwise. **On cover, deciding whether the agent was fooled: the contract can't.** If it doesn't rule in time, nothing moves | on credit, be the guarantor, the company or the seller (`ARBITER_NOT_INDEPENDENT`); on cover, be the company, the guarantor or the owner (`A115`); award more than the payment (`A98`); rule late (`A104`) |
| Seller | filing a truthful delivery proof; a false one is a matter for the dispute | claim before due plus the inspection window (`A46`, `A68`); claim without filing a proof (`A52`); bill more than the order (`A82`) |
| Verifier | checked the credential chain before signing; holds the LEI salt; may update signer keys | move money under its own key's rules (see Limits for an unpaid-storage drain), disclose before the waiting period, disclose an LEI other than the committed one (`A18`, `A19`) |
| Owner | the verifier and supervisor whitelists; can revoke a mandate, which returns its money to the company unless credit is open or a debt remains; can delist a guarantor, which stops new acceptances on it (`A96`) but not orders already accepted | touch a mandate's limits. **It can take a guarantor's free stake**: see Limits |
| Company | its own funds; can revoke or reinstate its own mandate | raise the limits the verifier signed (`A13`); swap the asset or fee payer (`A22`, `A81`, `A87`); get its money back past a debt (`A51`, `A70`) |
| Supervisor | requesting disclosure, in public | disclose by itself (`A17`) |
| Agent | nothing | leave scope or budget, pay twice, reach other methods (`A01`–`A11`, `A31`, `A32`) |
| Relayer (anyone) | delivering a revocation; delay here delays revocation | forge one (`A15`, `A24`, `A29`, `A30`, `A34`) |

The contract does not replay KELs. It trusts the verifier's binding of AID to key, then checks one signed anchoring event. Duplicity detection and key-state verification happen off-chain in `keri/verify.py`, with no witnesses or watchers in this demo.

## What is defended

| Threat | Defense | Tests |
|---|---|---|
| False or endless claims | One open claim per tree; one claim per payment; claim window; no claim on a payment before activation; loss at most the amount paid | `A98`, `A101`–`A104`, `A118` |
| Cover taken back, or stake locked twice | Fee for started periods kept, later periods returned if the guarantor revokes, and lock not released early; orders and cover share one exposure; terms signed | `A99`, `A109`, `A110`, `A112`, `A113` |
| Injected payee, amount, repeat or terms | Scope, invoice hash, per-payment cap, tenor range | `A01`, `A20`, `A31`, `A32`, `A57`, `A58`, `A63` |
| Budget invented, replayed, or drained fast | Hash chain, chain length, daily rate, vault check | `A02`–`A05`, `A23`, `A42` |
| Stolen or expired agent key | Protocol limits on the key; expiry; three strikes delete it | `A06`–`A11`, `B01` |
| Forged or replayed attestation | Whitelisted signature over every field, bound to this contract and this company; one per AMC; one hour old at most | `A12`–`A14`, `A22`, `A26`, `A27`, `A33`, `A81`, `A87` |
| Forged or griefing revocation | Signature, identifier and seal checks; commitment opening; caller checks; size limit | `A15`, `A16`, `A24`, `A29`, `A30`, `A34`, `A39` |
| Someone else's key, refund or signer swap | Caller checks | `A35`–`A37`, `A47`, `A55` |
| Removed verifier or supervisor keeps acting | Current whitelist is checked | `A38` |
| Disclosure by the wrong party, early, or of the wrong name | Supervisor list, waiting period, commitment; recourse and enforcement order; legal entity's signature | `A17`–`A19`, `A49`, `A50`, `A61` |
| Seller claims early, without delivery, or twice | Due date, inspection window, delivery proof, status | `A46`, `A52`, `A53`, `A68` |
| Seller or company games a dispute | Full escrow; proof deadline; arbiter gets its time | `A54`, `A69`, `A73`, `A74` |
| Guarantor or company sells to itself | Account check against guarantor and company | `A77` |
| Company walks away from a debt | Money is retained in the tree; repayment comes before anything else; frozen; suspended | `A48`, `A51`, `A70`, `A72`, `A75`, `A76` |
| Retained money gets stuck | Released to `unclaimed` once nothing is owed | `A71` |
| Bond spent, raced, or thinner than promised | Locked per order; hard requirement | `A56`, `A66`, `A79` |
| Guarantee taken without paying for it | Fee checked at acceptance; per-period pricing | `A78`, `A80` |
| Accepting on the guarantor's money after the company has left | Agent, mandate and freeze checks at acceptance | `A67` |
| Order accepted outside the seller's rule, in another asset, with a fee that empties it, or with a friendly arbiter; rule stored for free | Stored rule enforced, including asset, fee and arbiter; storage deposit; excess returned | `A83`, `A84`, `A94`, `A95` |
| A tenor long enough to overflow deadlines, so an order can never end | `max_tenor` is at most 10 years | `A93` |
| Seller bills more than ordered | `final_amount` is at most the order | `A82` |
| Guarantor over-committed, leaving or delisted | Capacity check, exposure blocks withdrawal, per-asset stake, listing checked at acceptance | `A59`, `A60`, `A91`, `A96` |
| Straw seller takes the whole stake | Per-seller cap. **This limits the damage; see [collusion](#collusion-and-fraud)** | `A85` |
| Throwaway sellers make every accept run out of gas | Book keeps 8 sellers | `A86` |
| Sub-agent exceeds its parent, or the tree becomes too big to close | Narrowing checks, depth and size limits, single-use keys, parent suspension | `A40`–`A45`, `A62`, `A64`, `A65` |
| Wrong token, or NEAR standing in for a token | Asset checks on every token path; failed withdrawals credited back once | `A21`, `A25`, `A88`–`A90`, `A92` |
| Funder and agent burn the contract's balance | Refresh and reinstate must attach the allowance | `A28` |
| Refund to a missing account | Kept and claimable | `B02`, `B12`, `B15` |

### What the agent's key cannot do (protocol layer, no transaction is created)

| Attempt | Error | Bench |
|---|---|---|
| call any method outside the five agent methods | `InvalidAccessKeyError::MethodNameMismatch` | A08 |
| attach a deposit (e.g. NEP-141 `ft_transfer` needs 1 yocto) | `DepositWithFunctionCall` | A09 |
| plain `Transfer` from the contract account | `RequiresFullAccess` | A10 |
| call another contract | `ReceiverMismatch` | A11 |
| anything after revocation or tripwire | `AccessKeyNotFound` | A07, B01 |
| run out of gas allowance | `NotEnoughAllowance`: not a policy event; `refresh_key` restores it | none |

## Security review notes

Code reviews after the first bench, done with AI review agents, found problems the tests had missed. All of these are fixed and have a test:

- a revoked mandate could be revived by replaying its attestation, which also reset its budget (`A26`);
- a colluding company and agent could burn the balance that backs other mandates through free `refresh_key` calls (`A28`);
- a forged ECR naming the real legal entity passed the verifier, because only the credential's `i` field was compared (`keri/test_forgeries.py`, F1);
- a holder could show an old bundle to hide a revocation (F7, F8);
- a token refund that failed left the tokens stuck (`B12`), and `Paid` was reported before the transfer outcome was known (`B02`);
- the same invoice could be paid twice, and an injected amount to an in-scope payee had no cap (`A31`, `A32`);
- verifiers and supervisors removed from the whitelist kept their powers (`A38`);
- a seller could mark delivery and claim default in one batch, leaving no time to dispute (`A68`);
- a company could move money to a sub-agent or a friendly seller before its guarantor was repaid (`A70`, `A72`, `A76`);
- money kept in a closed tree stayed stuck after the company repaid, a bug introduced by an earlier fix (`A71`);
- the guarantor or the company could be the seller and manufacture its own default (`A77`);
- a thin vault shrank the bond silently and moved the gap to the guarantor, while the risk card still showed the full bond (`A79`).

`contract/src/fuzz.rs` also drives random call sequences with random failed callbacks and checks the books after every step. CI runs it and the exact-value tests on each push. The mutation story is in [TESTING.md](TESTING.md#mutation-testing).

## Limits

All of these hold for the current contract.

### Cover

- **The contract can't tell if an agent was fooled.** A named arbiter decides, on evidence the contract only hashes. `context_hash` binds the text to the payment, not the text to the truth, and it can be omitted.
- **A bought arbiter hurts both ways, and the limit protects only the guarantor.** Bought by the company, it pays false claims and costs the guarantor up to the limit. Bought by the guarantor, it denies true claims, and after any denial `void_cover` can end the cover at any later time: the lock comes back, the fee stays, and later payments have no cover. The company has no remedy on-chain.
- **The arbiter can be a council, which spreads the risk without removing it.** A [Sputnik DAO ruled on testnet](testnet-dao-arbiter.md) with no contract change. Its policy can change, and the contract can't see who runs it, so a guarantor has to check that itself.
- **Moral hazard is capped, not stopped.** A company that fools its own agent, with a seller it controls, gets the loss minus its share, if the arbiter upholds. The share and the limit are the only brakes; there is no fraud check.
- **Seller refunds are invisible.** If a seller refunds a fooled payment, the contract can't see it, so a company could be repaid twice. The terms ask for a statement; nothing on-chain checks it.
- **No company-wide total.** Each mandate has its own limit. Nothing adds up a company's mandates, or stops it buying cover from several guarantors for one loss.
- **The owner can take a guarantor's free stake.** `set_verifier` overwrites a guarantor's public key with no delay. With the new key, the owner signs an attestation for a mandate naming that guarantor, with no bond and with its own accounts as company and seller, and collects a default. Delisting doesn't stop orders already accepted. Found by reading the code in review, not run. A real deployment needs a timelock or a guarantor's own signature; the deployed contract has neither, and its owner is a demo account.
- **A verifier can spend the contract's shared NEAR on storage.** `update_signers` and `register` take strings with no length limit and no deposit. Enough of it exhausts the balance that other mandates rely on, and later NEAR withdrawals could fail and stay claimable. Found in review; the size per transaction wasn't measured.
- **A guarantor can skip the fee return by setting signers before cover starts.** `update_signers` is blocked only while cover is Active. While it's Offered, the verifier can name itself signer, activate, then revoke by KEL, and no later-period fee goes back. The company sees `signers_updated` and can revoke first.
- **A guarantor can revoke early and keep the fee for the periods already started.** Periods count back from `valid_until` and the guarantor chooses when to activate, so a cover that lived seconds can still keep up to two periods' fee. Later periods go back to the company, out of the guarantor's free stake. A guarantor can withdraw that free stake first, and then returns less: withdrawing takes 30 days by default and the request is public, so a company can watch `unstake_at`. Its lock isn't released early (`A99`), but the agent is stopped. Revoking its own mandate returns the company nothing. Signers can't change while cover runs, so a guarantor can't take the KEL route around this; if the employee's keys rotate, `revoke_by_kel` keeps checking the old ones until cover ends.
- **The fee is charged up front, can come close to the limit, and the guarantor chooses when.** It is taken at activation for every started 30-day period to `valid_until`. At register it must leave one maximum payment under what the cover can pay, and activation must fall in the first half of the term ([CONTRACT.md](CONTRACT.md#cover-methods)). Inside that, a company can't refuse an activation it signed for, except by revoking the mandate.
- **Cover has no loss data behind it.** Full locking is the floor on price, and nobody can compute the rest. See [ECONOMICS.md](ECONOMICS.md).
- **Clearing is a record, not a control.** `clear_agent` says the company dealt with its agent; nothing checks that. The guarantor's control is `revoke`.
- **The demo's windows are short.** Its arbiter has 60 seconds and a payment can be claimed for 10 minutes. The 14 days in [CONTRACT.md](CONTRACT.md#windows) is the contract's default.
- **The public demo hands out the company's and the arbiter's restricted keys.** Anyone can file, rule and clear on the demo's mandate. Money can only go to the company's account and the seller in the mandate; `withdraw`, `revoke` and `void_cover` are not on those keys. Anyone can also burn the keys' gas allowance, or stop the tree for a while by cycling claims; the page closes stale claims itself, and says so when an allowance runs out. A low daily rate keeps one script from spending every link at once.

### Legal

- **This is not a standby letter of credit.** ISP98 Rule 1.07 makes the issuer's obligation independent of the underlying transaction ([ISP98](https://library.iccwbo.org/content/tfb/RULES/tfb-isp98-rules.htm)). Writ's payment depends on delivery, the inspection window and any dispute, and the company can suspend it by escrowing the full amount. It is a conditional payment guarantee. Earlier versions of this project used the wrong term.
- **Naming recovers no money.** A real guarantee has a reimbursement agreement and security behind it. Here `terms_hash` is a placeholder, so disclosure is only the effect of a public default record, and it does nothing against a shell company.
- **The terms are a placeholder.** `terms_hash` commits to demo text no lawyer has reviewed. Whether an on-chain default and disclosure have legal effect depends on a real agreement and a jurisdiction.
- **Whether this is insurance is unknown.** We don't claim to be a licensed product. It takes a fee for a future event and pays a loss, and that depends on the jurisdiction; no lawyer has reviewed it. So it stays on testnet, with no real users. A guarantor would need its own licence or legal opinion; Writ is software.
- **Sealed is not anonymous to your seller.** A seller who must issue an invoice generally needs the customer's name: EU VAT invoices must carry the customer's full name and address, with exceptions for simplified invoices that vary by country ([Art. 226(5)](https://www.legislation.gov.uk/eudr/2006/112/article/226)). The name is sealed from the public ledger, not from your seller; a seller gets it off-chain, and Writ has no method for that exchange. What the seal protects is the company's purchasing record on a public ledger. A seller's sanctions and know-your-customer duties are unchanged, and Writ does nothing to meet them; we have no legal opinion on what they require here.

### Collusion and fraud

- **Collusion is capped, not stopped.** A company and a straw seller it controls inside the mandate's scope can open an order, mark it delivered, not pay and claim default. The seller receives the whole amount; the company loses the bond and any fee; together they take about `(1 − bond) × amount`, minus the fee, from the guarantor. `SELLER_NOT_INDEPENDENT` only stops the same account (`A77`). `seller_cap_bps` limits this per seller account to that share of the stake (`A85`), but 0 turns it off, it is measured when an order is accepted, and one person can hold several accounts in the scope, up to 16 per mandate. What remains is a debt, a freeze and a naming.
- **The delivery proof is a hash.** The contract cannot tell a real delivery from a false one; a dispute handles that, and the arbiter is one account named in the mandate. The guarantor's money rests on this hash when the company does not dispute.
- **Colluding seller and guarantor** can run a false delivery to reach disclosure, if the company does not dispute. The company's defense is the dispute window. The guarantor and the company cannot be the seller themselves (`A77`), but a separate account they control can.
- **Bust-out.** A company can pay on time to build a record, then use its whole `limit` at once. Only `limit`, `max_links`, the budget and the seller's rule stand in the way, and the public record shows how to build a good one.
- **The payment record is per guarantor, asset and pseudonym.** `entity_tag` is chosen by the guarantor, so a record does not follow a company to another guarantor, asset or tag. `defaults` counts any default, including one the vault covered.
- **A seller must be in the signed scope.** The scope holds at most 16 accounts and cannot change after registration, so adding a seller means a new attestation and a new mandate. The guarantor has therefore approved every seller by account. Writ does not let an agent buy on credit from anyone.

### The guarantor and its stake

- **No real guarantor exists yet.** The demo guarantor is a test account and the 2% per 30 days fee is a placeholder. Who would underwrite agents, and at what price, is untested. A fee paid by the buyer is not refunded if an accepted order is later cancelled; a fee paid by the seller is taken only when the seller is paid, and can take the whole payment on a long order.
- **Disclosure takes the guarantor.** Only it holds the salt, so a guarantor that stays quiet reveals nothing, and a debt repaid from money left in the tree reveals nothing. Closing covers one mandate's tree, not every mandate the company has.
- **The guarantor's stake is the real limit.** A guarantor's exposure across mandates cannot exceed its stake while orders are open, but it can request an unstake in advance; the risk card shows `guarantor_unstake_at` so a seller can see it. Stake is per asset. Stake that a claim has used lowers what later orders can draw on.
- **The per-seller cap is the guarantor's choice.** `seller_cap_bps` is signed per mandate and 0 means no cap. A seller's rule cannot require one; a seller should read it on the risk card.
- **A guarantor can close the tree early.** As the mandate's verifier it can `revoke` at any time, which reveals nothing. The recourse period only guards disclosure.
- **The guarantor's book is not complete.** `top_sellers` comes from a list of at most 8 sellers, replacing the smallest when full (`A86`). Totals such as `exposure` and `claims_paid` are complete; the seller list is not.

### Orders and sellers

- **Stop-ship covers one mandate's tree on this contract.** The company's other mandates, and anything it buys off Writ, are not affected. The freeze starts only when the guarantor's stake has paid something; a default covered by the company's own vault freezes nothing.
- **A seller waits.** The seller is paid when the company settles, and can claim no earlier than due date plus `grace` and delivery plus `inspect`. A dispute can hold the money up to `dispute_timeout`, or longer if a late proof extends it.
- **The bond is hard, and it can be 0.** Accepting fails with `BOND_SHORT` if the company cannot lock what the terms promise (`A79`), but `bond_bps` is whatever the guarantor signed. The demo's `make credit-demo` uses 0. A seller who wants one sets `min_bond_bps`.
- **A seller's rule names one asset; it cannot judge it.** `asset` is required and must match the order (`A94`), so a rule accepts one asset at a time. Whether that token is sound is the seller's decision. A seller with no rule gets no asset check at all: it must read `asset` in `check_order` itself.
- **Delisting a guarantor stops new acceptances only.** Accepting then panics `GUARANTOR_DELISTED` (`A96`). Orders already accepted continue, and claims still draw on its stake.
- **The windows differ by deployment.** `new` sets them and `windows()` returns them. Demo deployments use seconds and minutes (`DEMO_WINDOWS` in `app/src/near.ts`), not the defaults in [CONTRACT.md](CONTRACT.md#windows).
- **An invoice id belongs to the mandate, not to one seller.** A hijacked agent that opens credit on a hash to another in-scope seller blocks that hash until the order ends. The company can reissue under a new id.
- **What the demo uses for credit.** The site's selling story runs in Circle's testnet USDC. `make credit-usdc-demo` runs the same flows on a local mock 6-decimal token (`B35`–`B37`), and `make credit-demo` and `docs/testnet-credit.md` run in NEAR. The public-key challenge holds a NEAR budget; the live-model mandate is in USDC.
- **The attack table's gain column reads one test account.** It is `w.attacker`. Where the adversary is the seller (`A46`, `A52`, `A82`, `A85`) that 0 proves nothing; the refusal does. `A85` shows a straw seller is refused above its cap, and can still take value up to it.
- **A token tree's NEAR reserve goes back to the company on close,** even while a debt remains, because it is not an asset that pays claims. It is what remains after storage and hire fees.

### Agents and hire

- **The agent in `make demo` and `make ui` is a script.** It issues the malicious call directly, because the point is the gate, not the model, and a script is reproducible. `make attack-live` runs real LLMs instead and needs an API key; the recorded run used Google's Gemini free tier on a local sandbox, not NEAR AI Cloud, so it makes no TEE claim. Writ does not stop an agent from being fooled. It refuses what breaks the mandate, and cover deals with what doesn't.
- **A prompt-injected payment inside every cap and scope still gets paid** if the invoice is new. The contract doesn't judge the invoice. On a mandate with cover, the company can claim it afterwards, and an arbiter decides.
- **Hire limits.** The root pays hire fees, so a tree tops out at 16 mandates; `hire` is not bound by the per-payment cap, and rates in a tree add up rather than sharing one limit.
- **Sub-agents are enforced by the contract, not by KERI.** A hire is not a credential the verifier checks; the contract enforces that it only narrows. A tripped parent suspends its sub-agents' spending, but their keys stay until someone revokes it. A token mandate with no credit terms cannot hire (`A92`).
- **A compromised agent key can hire**, within the links it holds and the parent's limits. It cannot create budget; hiring moves what the employee released.
- **Malformed `spend` calls cost gas without a strike.** They fail before the policy checks, so the tripwire does not count them. The loss is bounded by the key's allowance, which the fee has already paid for.

### Identity and KERI

- **The agent's KERI key is its NEAR key.** That is the demo's point, but it makes a KERI signing key a hot key, and rotating it means a new function-call key.
- **Mock issuers, official schemas.** The QVI, legal entity and ECR credentials use the official vLEI schemas (`keri/schemas/`, unmodified from WebOfTrust/vLEI, SAIDs asserted). The issuers are mocks: the verifier pins a mock root (`verify.py pin`) standing in for GLEIF's, and no real QVI issued anything. The LEI `WRITDEMO000000000017` is fictional, and the credentials do not claim to be real vLEIs. GLEIF has not published an AMC schema (paper p.45); `keri/common.py` is a proposal.
- **Key rotation and KEL depth.** `revoke_by_kel` checks keys bound at registration until the verifier calls `update_signers`. It checks the signature, `i` and the seal, not `p`, `d` or the rest of the KEL. It takes `ixn` events only, so establishment-only identifiers and seals in `rot` events are not supported, nor are multi-signature identifiers. A signed `ixn` under a key already rotated out still revokes until the update.
- **No witnesses or watchers.** `wits=[]`, and the verifier's temporary keystore has no first-seen memory, so it cannot detect duplicity across runs. The issuer's public status is a local file standing in for a registry endpoint.
- **The LEI commitment is the verifier's own.** It is not bound to the ECR on-chain; the verifier could commit to a different LEI than the credential holds, and only the off-chain chain shows this.
- **Removing a verifier does not close its mandates.** `present` then reports `chain_valid: false`, but payments continue until a revocation.
- **Revocation waits for a submitter.** Whoever holds the signed event can submit it, and this repo ships no relayer. The key stays live, and `present` keeps reporting `not_revoked`, until the event reaches the contract.
- **Single verifier per mandate.** The bench tests NEP-141 with a mock token (`contract/ft-mock`); `make testnet-usdc` ran one real payment in Circle's testnet USDC.

### Privacy

- **Privacy is selective disclosure, not anonymity.** Until a disclosure, only `sha256(LEI|salt)` is on-chain (salt held by the verifier). Funding accounts, the agent key, the employee's public key (`issuer_pk`) and payments are public and linkable on-chain, so anyone who already knows the employee's KERI identifier can link the mandate to them. A revocation event submitted on-chain exposes the signer's AID. Only tier 1 (the LEI) is disclosable; the employee's identity is out of scope.

### The demo and the deployment

- **The public demo holds the secrets a guarantor would keep.** The site's `config.json` has the fictional company's LEI and salt, so the guarantor's step can run in your browser. A real guarantor keeps them private.
- **On the site, only "Fool a real model" uses a model.** That section sends your invoice to Llama 3.3 on Cloudflare Workers AI's free tier and signs what it decides from a covered mandate (`make live-agent`), whose next budget links are public on the page: anyone can spend them, but only to the permitted seller, 3 links at a time, at a low daily rate. The free quota can run out, and the site then says so. Answers that pay are cached for a day by invoice text, and the page says when. The other stories on the site are scripted.
- **The contract cannot be upgraded.** There is no full-access key, so a bug means a new deployment on a new account (see [CHANGELOG.md](../CHANGELOG.md)).
- **Testnet only.** `make testnet` deployed this story; not on mainnet. It needs the faucet, which rate-limits per IP; on a 429 it falls back to sub-accounts of an already funded account.
- **No audit.** The contract was reviewed by AI review agents, an attack bench, a fuzz test of the books and mutation testing, not by an audit firm.

## Other limits to the case for buying this

[ECONOMICS.md](ECONOMICS.md) covers the price questions: a fully reserved guarantee cannot reach an insurer's price, a buyer-paid fee attracts buyers who cannot borrow cheaply, agent payment volume today is tiny, and Writ takes no protocol fee.
