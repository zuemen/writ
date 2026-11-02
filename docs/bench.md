**24 attacks, 24 blocked as expected, attacker gain 0 yoctoNEAR.**

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
| B00 | legit payment 3+2 links to in-scope merchant | Paid | Paid | 0 |
| B01 | AMC revoked in KERI TEL, ixn submitted by anyone | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| B02 | payment to a non-existent account | vault refunded by callback | refunded | 0 |
| B03 | supervisor request → wait → verifier discloses committed LEI (public tx) | LEI disclosed, objection on record | disclosed | 0 |
| B04 | stablecoin cell: agent pays 3 links in NEP-141 (contract attaches the 1 yocto) | merchant +0.3 tUSDC | merchant +0.3 tUSDC | 0 |
| B05 | boundaries: vault == amount pays, last link spendable, top_up, counters, solvency | all exact | all exact | 0 |
