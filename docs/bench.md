**119 attacks, 119 blocked as expected, attacker gain 0 yoctoNEAR.**

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
| A100 | company in default gets a claim upheld and withdraws the money past its debt | payout stays in the vault | payout stays in the vault | 0 |
| A101 | company files twenty claims before the arbiter rules on the first | CLAIM_OPEN | CLAIM_OPEN | 0 |
| A102 | company files again on a payment the arbiter denied | ALREADY_CLAIMED | ALREADY_CLAIMED | 0 |
| A103 | company claims on an old payment after the window | WINDOW_CLOSED | WINDOW_CLOSED | 0 |
| A104 | arbiter rules after its time ran out | RULING_TOO_LATE | RULING_TOO_LATE | 0 |
| A105 | arbiter ends a company's cover with no denied claim to point at | NOT_DENIED | NOT_DENIED | 0 |
| A106 | company keeps claiming after the arbiter found fraud | COVER_NOT_ACTIVE | COVER_NOT_ACTIVE | 0 |
| A107 | retrying during its company's claim gets the agent's key deleted | no strike, key stays | no strike, key stays | 0 |
| A108 | seller takes on the guarantor's money while the agent is under a claim | UNDER_CLAIM | UNDER_CLAIM | 0 |
| A109 | cover locks the whole stake, then a seller's order or a withdrawal draws on it again | GUARANTOR_CAPACITY, STAKE_EXPOSED | GUARANTOR_CAPACITY, STAKE_EXPOSED | 0 |
| A11 | agent key used against another contract | ReceiverMismatch | ReceiverMismatch | 0 |
| A110 | an order holds the stake, then the guarantor locks the same stake for cover | GUARANTOR_CAPACITY | GUARANTOR_CAPACITY | 0 |
| A111 | cancelled order and payment on one invoice make two claims; a paid invoice is reopened as an order | one record, DUPLICATE | one record, DUPLICATE | 0 |
| A112 | guarantor activates against a vault that can only pay from a seller's bond | PREMIUM_SHORT | PREMIUM_SHORT | 0 |
| A113 | company changes any cover term after the guarantor signed | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A114 | cover signed over a scope with the arbiter or the company, a thin limit, or under 10% share | COVER_SCOPE, COVER_LIMIT_THIN, COVER_DEDUCTIBLE | COVER_SCOPE, COVER_LIMIT_THIN, COVER_DEDUCTIBLE | 0 |
| A115 | the arbiter is the owner, the guarantor or the company | COVER_ARBITER | COVER_ARBITER | 0 |
| A116 | a mandate with cover opens without paying for its payment records | DEPOSIT_BELOW_FEE | DEPOSIT_BELOW_FEE | 0 |
| A117 | a stranger files, rules on, voids, clears or releases a cover; the company rules on its own claim | ONLY_FUNDER, ONLY_ARBITER, ONLY_GUARANTOR | ONLY_FUNDER, ONLY_ARBITER, ONLY_GUARANTOR | 0 |
| A118 | company claims on a payment made before the cover was active | NO_PAYMENT | NO_PAYMENT | 0 |
| A119 | agent pays with a context hash nobody can check later | Rejected:INVOICE | Rejected:INVOICE | 0 |
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
| A37 | stranger claims a failed refund | ONLY_FUNDER | ONLY_FUNDER | 0 |
| A38 | verifier or supervisor removed from the whitelist keeps acting | REQUESTER_REMOVED, NOT_AUTHORIZED | REQUESTER_REMOVED, NOT_AUTHORIZED | 0 |
| A39 | oversized evidence string used to consume shared storage | EVIDENCE_TOO_LONG | EVIDENCE_TOO_LONG | 0 |
| A40 | sub-agent grants a counterparty it does not have itself | Rejected:HIRE_SCOPE | Rejected:HIRE_SCOPE | 0 |
| A41 | hire with a later expiry or a higher rate than the parent | Rejected:HIRE_TERMS | Rejected:HIRE_TERMS | 0 |
| A42 | agent hires with budget the employee never released | Rejected:CHAIN | Rejected:CHAIN | 0 |
| A43 | an agent dismisses someone else's sub-agent | NOT_PARENT | NOT_PARENT | 0 |
| A44 | chain of hires past the depth limit | Rejected:HIRE_DEPTH | Rejected:HIRE_DEPTH | 0 |
| A45 | hires past the tree size limit | Rejected:HIRE_TREE | Rejected:HIRE_TREE | 0 |
| A46 | seller claims default before the due date | NOT_DUE | NOT_DUE | 0 |
| A47 | stranger claims someone else's default | ONLY_SELLER | ONLY_SELLER | 0 |
| A48 | frozen company keeps buying on credit | Rejected:FROZEN | Rejected:FROZEN | 0 |
| A49 | guarantor cuts the power before the recourse period ends | RECOURSE_OPEN | RECOURSE_OPEN | 0 |
| A50 | guarantor reveals the company before enforcement | NOT_ENFORCED | NOT_ENFORCED | 0 |
| A51 | company revokes its own agent to walk away from a debt and take the vault | vault kept | vault kept | 0 |
| A52 | seller claims default without delivering | NOT_DELIVERED | NOT_DELIVERED | 0 |
| A53 | seller refuses the money, then claims default anyway | settled on the ledger | settled on the ledger | 0 |
| A54 | company disputes for free to stall a debt | ESCROW_FULL_AMOUNT | ESCROW_FULL_AMOUNT | 0 |
| A55 | guarantor decides a dispute it has money in | ONLY_ARBITER | ONLY_ARBITER | 0 |
| A56 | a colluding seller defaults first to drain the bond another seller relies on | first seller's bond intact | first seller's bond intact | 0 |
| A57 | injected order with a due date outside the agreed terms | Rejected:TENOR | Rejected:TENOR | 0 |
| A58 | injected order to a seller outside the mandate | Rejected:SCOPE | Rejected:SCOPE | 0 |
| A59 | seller accepts an order the guarantor has no stake to back | GUARANTOR_CAPACITY | GUARANTOR_CAPACITY | 0 |
| A60 | guarantor pulls its stake while it has exposure | STAKE_EXPOSED | STAKE_EXPOSED | 0 |
| A61 | guarantor commits to another company's LEI, without that company's key, and reveals it | LE_DID_NOT_SIGN | LE_DID_NOT_SIGN | 0 |
| A62 | hire with a huge duplicated scope, to make the tree too expensive to revoke | Rejected:HIRE_SCOPE | Rejected:HIRE_SCOPE | 0 |
| A63 | parent and sub-agent each pay the same invoice | Rejected:DUPLICATE | Rejected:DUPLICATE | 0 |
| A64 | a dismissed key is hired again | Rejected:HIRE_KEY | Rejected:HIRE_KEY | 0 |
| A65 | parent is tripped; its sub-agent keeps spending | Rejected:SUSPENDED | Rejected:SUSPENDED | 0 |
| A66 | agent spends the bond locked for a seller | Rejected:FUNDS | Rejected:FUNDS | 0 |
| A67 | seller accepts an order after the company revoked the agent, on the guarantor's money | AGENT_NOT_ACTIVE | AGENT_NOT_ACTIVE | 0 |
| A68 | seller marks delivery and claims default together, leaving no time to dispute | INSPECTION_OPEN | INSPECTION_OPEN | 0 |
| A69 | company disputes first so the seller cannot record delivery | delivery recorded, seller paid | delivery recorded, seller paid | 0 |
| A70 | company parks money in a sub-agent, defaults, and tries to get it back when the tree closes | money repays the guarantor first | money repays the guarantor first | 0 |
| A71 | money retained in a closed tree gets stuck after the company repays | released to the company | released to the company | 0 |
| A72 | company owes the guarantor and pays a friendly seller from the vault first | REPAY_GUARANTOR_FIRST | REPAY_GUARANTOR_FIRST | 0 |
| A73 | seller files a delivery proof after the arbiter's time ran out | DISPUTE_CLOSED | DISPUTE_CLOSED | 0 |
| A74 | seller files a proof at the last second and collects before the arbiter can look | ARBITER_STILL_HAS_TIME | ARBITER_STILL_HAS_TIME | 0 |
| A75 | sub-agent keeps settling after its parent tripped | SUSPENDED | SUSPENDED | 0 |
| A76 | while the company owes, a sub-agent settles a friendly order from its own vault | REPAY_GUARANTOR_FIRST | REPAY_GUARANTOR_FIRST | 0 |
| A77 | guarantor or company sells to the agent to manufacture a default | SELLER_NOT_INDEPENDENT | SELLER_NOT_INDEPENDENT | 0 |
| A78 | a company with an empty vault takes a guarantee without paying for it | PREMIUM_SHORT | PREMIUM_SHORT | 0 |
| A79 | company with a thin vault gets an order accepted with less bond than the risk card says | BOND_SHORT | BOND_SHORT | 0 |
| A80 | a long order pays the fee of a short one | PREMIUM_SHORT | PREMIUM_SHORT | 0 |
| A81 | company swaps who pays the fee after the guarantor signed | BAD_ATTESTATION | BAD_ATTESTATION | 0 |
| A82 | seller bills more than the order when it marks delivery | BAD_FINAL_AMOUNT | BAD_FINAL_AMOUNT | 0 |
| A83 | seller makes the contract store a rule without paying for the storage | POLICY_STORAGE | POLICY_STORAGE | 0 |
| A84 | an order outside the seller's own rule gets accepted anyway | POLICY:ORDER_TOO_LARGE | POLICY:ORDER_TOO_LARGE | 0 |
| A85 | one straw seller account takes more of the stake than its cap at once | SELLER_CONCENTRATION | SELLER_CONCENTRATION | 0 |
| A86 | throwaway sellers grow the guarantor's record until every accept runs out of gas | list stays at 8 | list stays at 8 | 0 |
| A87 | the credit asset differs from the cell's, or is swapped after the guarantor signed | CREDIT_ASSET_MISMATCH, BAD_ATTESTATION | CREDIT_ASSET_MISMATCH, BAD_ATTESTATION | 0 |
| A88 | company settles a 5-token order with 5,000,000 yoctoNEAR | USE_FT_TRANSFER_CALL | USE_FT_TRANSFER_CALL | 0 |
| A89 | attacker poses as the token, or pays with another token, to settle or stake | WRONG_ASSET, STAKE_ASSET_UNKNOWN | WRONG_ASSET, STAKE_ASSET_UNKNOWN | 0 |
| A90 | a token transfer that fails is used to lose or double the seller's money | credited back once | credited back once | 0 |
| A91 | guarantor backs a stablecoin order with a stake in NEAR | GUARANTOR_CAPACITY | GUARANTOR_CAPACITY | 0 |
| A92 | a plain token cell with no credit terms hires, or takes NEAR it could never return | HIRE_TOKEN, TOKEN_CELL_USE_FT_TRANSFER_CALL | HIRE_TOKEN, TOKEN_CELL_USE_FT_TRANSFER_CALL | 0 |
| A93 | guarantor signs a tenor long enough to overflow the deadlines, so an order can never end | BAD_CREDIT_TERMS | BAD_CREDIT_TERMS | 0 |
| A94 | an order in a scaled or fake asset, with a fee that empties it or a friendly arbiter, passes the seller's rule | ASSET_NOT_APPROVED, FEE_TOO_HIGH, ARBITER_NOT_APPROVED | ASSET_NOT_APPROVED, FEE_TOO_HIGH, ARBITER_NOT_APPROVED | 0 |
| A95 | throwaway accounts make the contract store a row for one yocto each | no row, excess returned | no row, excess returned | 0 |
| A96 | a seller's order is accepted on a guarantor the owner has delisted | GUARANTOR_DELISTED | GUARANTOR_DELISTED | 0 |
| A97 | agent hires a sub-agent, it pays, it is dismissed, the company claims: the stop lands on a closed cell | whole tree UNDER_CLAIM | whole tree UNDER_CLAIM | 0 |
| A98 | the arbiter awards more than the payment | BAD_LOSS | BAD_LOSS | 0 |
| A99 | guarantor collects the fee, revokes and takes its lock back | TOO_EARLY | TOO_EARLY | 0 |
| B00 | legit payment 3+2 links to in-scope merchant | Paid | Paid | 0 |
| B01 | AMC revoked in KERI TEL, ixn submitted by anyone | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| B02 | payment to a non-existent account | Rejected:TRANSFER_FAILED, vault refunded | Rejected:TRANSFER_FAILED, vault refunded | 0 |
| B03 | supervisor request → wait → verifier discloses committed LEI (public tx) | LEI disclosed, objection on record | disclosed | 0 |
| B04 | stablecoin cell: agent pays 3 links in NEP-141 (contract attaches the 1 yocto) | merchant +0.3 tUSDC | merchant +0.3 tUSDC | 0 |
| B05 | boundaries: vault == amount pays, last link spendable, top_up, counters, solvency | all exact | all exact | 0 |
| B06 | gas allowance consumed → funder refresh_key (stranger refused) | allowance restored, agent keeps paying | restored | 0 |
| B07 | HR revokes the employee's ECR in KERI; anyone submits it; employee not needed | key deleted, next call AccessKeyNotFound | AccessKeyNotFound | 0 |
| B08 | three bad invoices trip the key; funder pays to reinstate; agent pays again | Paid after reinstate | Paid after reinstate | 0 |
| B09 | employee rotates keys; verifier updates the signer; new key revokes, old key cannot | key deleted by the new key | key deleted by the new key | 0 |
| B10 | deploy + init + delete full-access key in one batch; owner still manages the whitelist | 0 keys on the contract account | 0 keys on the contract account | 0 |
| B11 | token cell: NEAR above the fee is returned | excess returned | excess returned | 0 |
| B12 | refund fails because the funder left the token; funder re-registers and claims | tokens recovered | tokens recovered | 0 |
| B13 | gas burnt by a payment, whole transaction | under 30 Tgas | 1 link 6 Tgas, 100 links 8 Tgas | 0 |
| B14 | boundaries: j == cap pays, unpaid invoice not on record, maxStrikes 0 never trips, solvency counts storage | all exact | all exact | 0 |
| B15 | NEAR refund fails because the funder account is gone; it is kept, and claimable after the account returns | refund recovered | refund recovered | 0 |
| B16 | agent hires a sub-agent with a narrower mandate; it pays inside it | Paid, parent's links spent | Paid, parent's links spent | 0 |
| B17 | one revocation closes a full tree of 16 agents in one transaction | 16 keys deleted | 16 keys deleted, 18 Tgas | 0 |
| B18 | HR revokes one employee's ECR; the agent, its sub-agent and sub-sub-agent all lose their keys | 3 keys deleted by one signed event | 3 keys deleted by one signed event | 0 |
| B19 | agent buys on credit, seller delivers, company pays on time | paid, identity sealed | paid, identity sealed | 0 |
| B20 | default covered by the company's own vault: seller paid, on the record, identity sealed | paid, sealed | paid, sealed | 0 |
| B21 | company does not pay; the named guarantor's stake covers the seller, no approval needed | seller paid in full | seller paid in full | 0 |
| B22 | recourse period ends unpaid: the whole tree loses its keys and the company is named | key deleted, LEI public | key deleted, LEI public | 0 |
| B23 | company repays the guarantor in time: unfrozen, identity stays sealed | sealed | sealed | 0 |
| B24 | employee fired with a debt open: the debt stands, the rest is returned afterwards | seller paid, refund after | seller paid, refund after | 0 |
| B25 | dispute with full escrow, arbiter and timeout paths; unaccepted offers expire | resolved | resolved | 0 |
| B26 | funder reinstates a tripped parent: its sub-agents work again | Paid | Paid | 0 |
| B27 | undelivered orders release the guarantor; repaying after enforcement stops the reveal | released, stays sealed | released, stays sealed | 0 |
| B28 | released bond repays the guarantor; a silent seller cannot hold exposure open | collected, unblocked | collected, unblocked | 0 |
| B29 | the legal entity rotates its key after signing the terms | reveal still works | reveal still works | 0 |
| B30 | the guarantor earns its fee when the seller accepts; nothing is refunded | fee on the risk card and in the stake | fee on the risk card and in the stake | 0 |
| B31 | the seller pays the fee: nothing at accept, deducted from the invoice when paid | seller -fee, guarantor +fee | seller -fee, guarantor +fee | 0 |
| B32 | usage order: limit 10, seller bills 7.3, bond and exposure follow, only 7.3 settles | 7.3 paid | 7.3 paid | 0 |
| B33 | seller rule: refused with reasons, rule adjusted, order ships | refused, adjusted, accepted | refused, adjusted, accepted | 0 |
| B34 | guarantor book: stake, exposure, earned, claims, recovered, loss ratio, top sellers | adds up | adds up | 0 |
| B35 | credit in a 6-decimal stablecoin: seller pays the fee, usage order, NEAR reserve pays storage | seller received 3.92 of 4 | seller received 3.92 of 4 | 0 |
| B36 | stablecoin default: the token stake pays the seller, the company repays in the token, revoking does not escape | seller whole, debt repaid | seller whole, debt repaid | 0 |
| B37 | token tree: hire, sub-agent pays, disputes in escrow, retention and release per asset | books match the token balance | books match the token balance | 0 |
| B38 | an order's storage, including the per-seller record, is paid by the order | cost <= fee | 776 bytes | 0 |
| B39 | NEP-330 source metadata; check_order gives amount, asset, tenor, bond, exposure, fee, payer | all present | all present | 0 |
| B40 | partial loss: paid 3, lost 1, 20% share: the guarantor pays 0.8, no more | 0.8 of a link | 0.8 of a link | 0 |
| B41 | after valid_until + claim_window the lock comes back; the fee stays | Released | Released | 0 |
| B42 | mandate with cover only, in NEAR: fee, lock, payment, claim, repayment, clear, pay again | works end to end | works end to end | 0 |
| B43 | mandate with cover only, in a token, no NEAR reserve: same story, paid in the token | works end to end | works end to end | 0 |
| B44 | storage per payment: longest account, context hash, upheld claim | fee covers it | 355 bytes per record, 4000000000000000000000 yocto per link | 0 |
| B45 | arbiter runs out of time: no payment, no denial, the company can file again, the count is public | filed again | filed again | 0 |
| B46 | a claim on the tree does not stop settling an order | settled | settled | 0 |
