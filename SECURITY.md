# Security

**Status: testnet only. Not audited. Not for real funds.**

The contract was reviewed by AI review agents, an attack bench, a fuzz test of the books and mutation testing, not by an audit firm. The contract cannot be upgraded once deployed, so a bug means a new deployment.

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/zuemen/writ/security/advisories/new). If it is a way to move money on the live demo without a released budget link, an open issue is also fine: everything there is testnet.

Please include the contract account, the calls in order, and the transaction hashes if you have them.

## In scope

- `contract/`: anything that moves money outside the mandate, lets a seller or guarantor be paid twice, leaves money stuck, or names a company without its signature.
- `keri/verify.py`: a forged or stale credential chain it accepts.
- `worker/`: anything that exposes a key or lets a visitor use the model for something other than reading an invoice.

## Out of scope

The private keys on the public site. They are test keys, published on purpose, and restricted on-chain. The threat model and known limits are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
