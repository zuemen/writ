# Cover on NEAR testnet

Contract: [writ-cover.testnet](https://testnet.nearblocks.io/address/writ-cover.testnet). Mandate 1, in testnet USDC. Run through the live site's own buttons on 2026-11-03, with restricted keys signing in the browser. Windows are shortened for the demo, and the arbiter is a demo account the visitor acts as.

Explorer links need a browser. To check a transaction from a script, ask an RPC node: `curl -s https://archival-rpc.testnet.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"tx","params":{"tx_hash":"<hash from the link>","sender_account_id":"writ-cover.testnet","wait_until":"FINAL"}}'`. Use the signer's account if it isn't the contract.

| Step | Result | Transaction |
|---|---|---|
| Paying INV-1 again | Rejected: DUPLICATE | [view](https://testnet.nearblocks.io/txns/8zfAHbKcFWCW7Z7DWGBarRV9Zf6sLWnHZcoMWP2BcFBh) |
| Invoice with a fake controller note, the model pays | Paid, every check green | [view](https://testnet.nearblocks.io/txns/ARJ3JcPeahP8nXuj3vJnHbN1Ym5qicocHb8gyE5nsNnd) |
| `file_claim` | The tree stops | [view](https://testnet.nearblocks.io/txns/DJ8Uq6w1nD47oWAEcR5LfHzD6D1wTFTkR8wvy3pg3WC2) |
| The agent tries to pay during the claim | Rejected: UNDER_CLAIM | [view](https://testnet.nearblocks.io/txns/DHcmxEm2ygWh5irnFwHQpk6mAZwQns37HbFSeD7qbuJk) |
| `resolve_claim`: uphold | Stake drops, company can withdraw 80% of the loss | [view](https://testnet.nearblocks.io/txns/G5vkkEfBDQEwD4iC1TmY94SC3XQQzTfauzxNNRoeEAUg) |
| A real purchase, PO-78 | Paid | [view](https://testnet.nearblocks.io/txns/FPA4Hwqbv66KZaiWhk7EJFSwUSEZE7psSuaSjJnuQ7L2) |
| `file_claim` on the real purchase | The tree stops | [view](https://testnet.nearblocks.io/txns/7QCVks8AZMkAmsbiKBpKa43HDvJQkR9xnRQVk3dBKB7C) |
| `resolve_claim`: deny | Nothing moves, the tree resumes | [view](https://testnet.nearblocks.io/txns/4j6Uq33Y11SJwFodNRYTGCCPnzZGhy37ZZYsYoyYmMFD) |

State afterwards, as the site read it: lock 1.484 USDC, claims paid 0.016 USDC, upheld and denied 2, 2, agent Active. Visitors change these, so check `cover_of` for today's values.
