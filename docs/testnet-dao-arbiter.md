# A Sputnik DAO as the cover arbiter, on testnet

Can a DAO rule on claims, with no change to the contract? Yes. On 2026-11-04 a Sputnik DAO upheld one claim and denied another on the deployed [writ-cover.testnet](https://testnet.nearblocks.io/address/writ-cover.testnet). The contract was not changed or redeployed. It only checks that the caller is the named arbiter, and a DAO's call arrives from the DAO's own account.

- DAO: [writ-arbiter-mw0wkr9u.sputnikv2.testnet](https://testnet.nearblocks.io/address/writ-arbiter-mw0wkr9u.sputnikv2.testnet), made by the `sputnikv2.testnet` factory, code version 2.3.1
- Council: `writ-credit-arbiter`, `writ-credit-regulator`, `writ-credit-supplier` (`.testnet`). Default policy: threshold 1/2 of 3, so two votes pass
- Mandate: cell 33, in NEAR. 20 links of 0.01 NEAR, cover limit 0.1 NEAR, company's share 20%, one-day term
- Windows: `dispute_timeout` is 60 seconds on this deployment, shortened for the demo
- Reproduce: `app/src/dao-arbiter-demo.ts`

## Transactions

| Step | Result | Transaction |
|---|---|---|
| Factory creates the DAO | 6 NEAR attached | [view](https://testnet.nearblocks.io/txns/Dd8gHXoUtfRL9Usco7TUqpVfXYTfa7GhDdkjmQW1WcNC) |
| `register` with the DAO as arbiter | Cell 33, accepted | [view](https://testnet.nearblocks.io/txns/6CK1tXiB8ynJh59RNTyW4sZjCdy6512cDFnkMaYQzbmg) |
| `activate_cover` | Limit locked in the guarantor's stake | [view](https://testnet.nearblocks.io/txns/FuF92i1AzXGcHsntGTwzgqjbmbghwXz8hcD4jgP5p9C6) |
| Pay DAO-1 | Paid | [view](https://testnet.nearblocks.io/txns/6VAKeMpyMY2NoJTnfsXSpWJe3YaaJ3Vbc9drMBEXYhTQ) |
| Pay DAO-2 | Paid | [view](https://testnet.nearblocks.io/txns/EtRaZefqHkYGe4qsgsRMfhcDsKddsBAfFnZF5QXn1LS9) |
| `file_claim` DAO-1 | Claim open | [view](https://testnet.nearblocks.io/txns/8e74jvVnjEJERMVdMAuJyKo5YwKGtKovP8QK8xEYziTc) |
| A council member calls `resolve_claim` directly | Refused: ONLY_ARBITER | [view](https://testnet.nearblocks.io/txns/F7wipdP6BNXRW97FYBcBCmZVfsbSrgoX3TjcbEYkEeny) |
| Proposal 0: uphold | Added | [view](https://testnet.nearblocks.io/txns/6jgjWVsJKmELUMJyw6k7QJycufAFt3ynvFvmaMy4ZRzN) |
| Vote 1 of 2 | Still in progress, nothing moves | [view](https://testnet.nearblocks.io/txns/8dgfPyKXV86v17Z3qYTg5oSaw8yewZEsQjW9THNjQP9V) |
| Vote 2 of 2 | Approved, `claim_upheld` | [view](https://testnet.nearblocks.io/txns/BwCc8vKGNJ3VVgkd7Gq6zb8LudYute6qBNLPe5wReFyc) |
| `file_claim` DAO-2 | Claim open | [view](https://testnet.nearblocks.io/txns/213YPVVcEZzANjc399sALu8FZaGjTBRrqK883f2ZRUW8) |
| Proposal 1: deny | Added | [view](https://testnet.nearblocks.io/txns/12TWsV5xAp1FAupUpRwbGtACxPb8LYQjB9yizp4GZM9d) |
| Vote 1 of 2 | Still in progress | [view](https://testnet.nearblocks.io/txns/7GnesNsN5o2ZY4rfuqfaoSkHcjKPtdPMRAepo1LifZvm) |
| Vote 2 of 2 | Approved, `claim_denied` | [view](https://testnet.nearblocks.io/txns/E3jx4z8SZybB7HBT6hA19ZgHn1UN8V7TJdVsjjHgdw7C) |
| Proposal 2: `void_cover` | Added | [view](https://testnet.nearblocks.io/txns/4i55ZeMtfRHx2NMj3kFMRS34yepGzihhargvgemUDmT9) |
| Vote 1 of 2 | Still in progress | [view](https://testnet.nearblocks.io/txns/7eEuKVnkg1gSxaiXRKeqtbj5k27rT4E9L7zqcMyXQLYM) |
| Vote 2 of 2 | Approved, `cover_voided` | [view](https://testnet.nearblocks.io/txns/JDEnA6YJpNoSxDAbxouCWK7nYV7rNUft6UTrqLtiKTMe) |

## Results

Read from `cover_of`, `stake_of`, `claimable_of` and the transaction receipts.

| Check | Upheld, DAO-1 | Denied, DAO-2 |
|---|---|---|
| `resolve_claim` receipt | From the DAO account, succeeded | From the DAO account, succeeded |
| Block time from `file_claim` to `resolve_claim` | 17.4 s, including the refused direct call | 13.3 s |
| Guarantor's NEAR stake | 2.318 to 2.310 | No change |
| Company's claimable | +0.008 NEAR, 80% of the 0.01 NEAR loss | No change |

Both votes were sent by a script, one after the other. That shows the calls fit inside 60 seconds. It says nothing about how long people would take to decide.

Proposal 2 was cleanup: it released the test lock, so `void_cover` here is not a finding of fraud. Afterwards cell 33 reads `Voided`, with 1 upheld, 1 denied, and the guarantor's NEAR exposure at 0. `solvency` reads solvent.

## Limits

- This proves the mechanism, not independent arbitration. The voters are demo accounts, and their keys are all held by the same person.
- The company's account created this DAO and paid for it, though it is not on the council. The contract cannot see this: it only checks that the arbiter is not the company, the guarantor, the owner or the contract itself. Checking who is behind an arbiter is left to the guarantor before it activates cover.
- The contract fixes the arbiter's account, not its members. From the Sputnik source, a council can change its policy by proposal, so members and thresholds can change after the mandate is signed. Not tested here.
- A ruling that arrives after `dispute_timeout` was not tested. From the Sputnik source, a failed call leaves the proposal `Failed` rather than reverting the vote. `claim_timeout` is the contract's path if the arbiter runs out of time.
- A DAO on this factory costs 6 NEAR for code storage, and each proposal needs a 1 NEAR bond under the default policy. The bond comes back when the proposal executes.
