**36 attacks, 36 blocked as expected, attacker gain 0 yoctoNEAR.**

| id | attack / scenario | expected | observed | attacker gain (yocto) |
|---|---|---|---|---|
| A01 | prompt-injected agent pays attacker (out of scope) | Rejected:SCOPE | Rejected:SCOPE | 0 |
| A02 | spend more links than the mandate holds | Rejected:LIMIT | Rejected:LIMIT | 0 |
| A03 | forged hash-chain link (agent invents budget) | Rejected:CHAIN | Rejected:CHAIN | 0 |
| A04 | replay an already-spent link | Rejected:CHAIN | Rejected:CHAIN | 0 |
| A05 | drain faster than the daily rate (valid links) | Rejected:RATE | Rejected:RATE | 0 |
| A06 | spend after the AMC validity window | Rejected:EXPIRED | Rejected:EXPIRED | 0 |
| A07 | injected agent keeps trying (3 strikes) | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| A08 | agent key calls admin method set_verifier | MethodNameMismatch | MethodNameMismatch | 0 |
| A09 | agent attaches deposit (e.g. ft_transfer 1 yocto) | DepositWithFunctionCall | DepositWithFunctionCall | 0 |
| A10 | agent sends a plain Transfer from the contract account | RequiresFullAccess | RequiresFullAccess | 0 |
| A11 | agent key used against another contract | ReceiverMismatch | ReceiverMismatch | 0 |
| A12 | self-signed attestation (not a whitelisted verifier) | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A13 | funder widens the scope after the verifier signed | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A14 | attacker replays someone else's attestation | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A15 | forged KERI revocation event | BAD_KEL_SIGNATURE | BAD_KEL_SIGNATURE | 0 |
| A16 | stranger tries to revoke (griefing) | NOT_AUTHORIZED | NOT_AUTHORIZED | 0 |
| A17 | non-supervisor requests disclosure of the legal entity | NOT_SUPERVISOR | NOT_SUPERVISOR | 0 |
| A18 | verifier discloses before the public waiting period ends | TOO_EARLY | TOO_EARLY | 0 |
| A19 | verifier discloses a different LEI than it committed to | COMMIT_MISMATCH | COMMIT_MISMATCH | 0 |
| A20 | prompt-injected payment from a stablecoin cell | Rejected:SCOPE | Rejected:SCOPE | 0 |
| A21 | foreign token pushed into a cell via ft_transfer_call | refunded, vault unchanged | refunded | 0 |
| A22 | funder swaps the settlement asset after the verifier signed | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A23 | spend more than the vault holds (valid links, within rate) | Rejected:FUNDS | Rejected:FUNDS | 0 |
| A24 | genuine signed KERI event that anchors the AMC issuance, not a revocation | NO_REVOCATION_SEAL | NO_REVOCATION_SEAL | 0 |
| A25 | non-funder pushes the cell's own stablecoin into it | refunded, vault unchanged | refunded | 0 |
| A26 | revoked mandate revived by replaying its own attestation (resets the budget) | AMC_ALREADY_USED | AMC_ALREADY_USED | 0 |
| A27 | attestation signed for another deployment replayed on this contract | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A28 | colluding funder + agent burn gas and refresh for free to drain other cells' vaults | REFRESH_UNPAID | REFRESH_UNPAID | 0 |
| A29 | attacker presents its own key as the legal entity to revoke the mandate | BAD_ECR_OPENING | BAD_ECR_OPENING | 0 |
| A30 | forged ECR revocation event with a valid commitment opening | BAD_KEL_SIGNATURE | BAD_KEL_SIGNATURE | 0 |
| A31 | injection makes the agent pay an in-scope merchant for the same invoice twice | Rejected:DUPLICATE | Rejected:DUPLICATE | 0 |
| A32 | injection inflates the amount paid to an in-scope merchant past the per-payment cap | Rejected:PER_TX | Rejected:PER_TX | 0 |
| A33 | attestation signed before a revocation is used long afterwards | STALE_ATTESTATION | STALE_ATTESTATION | 0 |
| A34 | signed anchoring event from a different KERI identifier | WRONG_AID | WRONG_AID | 0 |
| A35 | stranger re-arms a tripped agent key | ONLY_FUNDER | ONLY_FUNDER | 0 |
| A36 | stranger swaps the keys that may revoke a mandate | ONLY_CELL_VERIFIER | ONLY_CELL_VERIFIER | 0 |
| B00 | legit payment 3+2 links to in-scope merchant | Paid | Paid | 0 |
| B01 | AMC revoked in KERI TEL, ixn submitted by anyone | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| B02 | payment to a non-existent account | vault refunded by callback | refunded | 0 |
| B03 | supervisor request → wait → verifier discloses committed LEI (public tx) | LEI disclosed, objection on record | disclosed | 0 |
| B04 | stablecoin cell: agent pays 3 links in NEP-141 (contract attaches the 1 yocto) | merchant +0.3 tUSDC | merchant +0.3 tUSDC | 0 |
| B05 | boundaries: vault == amount pays, last link spendable, top_up, counters, solvency | all exact | all exact | 0 |
| B06 | gas allowance consumed → funder refresh_key (stranger refused) | allowance restored, agent keeps paying | restored | 0 |
| B07 | HR revokes the employee's ECR in KERI; anyone submits it; employee not needed | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| B08 | three bad invoices trip the key; funder pays to reinstate; agent pays again | Paid after reinstate | Paid after reinstate | 0 |
| B09 | employee rotates keys; verifier updates the signer; new key revokes, old key cannot | key deleted by the new key | key deleted by the new key | 0 |
| B10 | deploy + init + delete full-access key in one batch; owner still manages the whitelist | 0 keys on the contract account | 0 keys on the contract account | 0 |
