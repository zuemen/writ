# Sealed Mandate

> Verify once. Enforce every time. Revoke at block speed.

**Status: day 1 of 13 (spikes). Not yet a product.** This README is written for a machine reviewer: every claim below has a command next to it. Claims without a command are marked *planned*.

## What it is

The first public-chain implementation of the **Agent Mandate Credential (AMC)** chain proposed in GLEIF's discussion paper *Agentic AI in Payments: Establishing Interoperable Trust and Control* (2026-08-13, Annex A). A verified legal entity (vLEI) issues a role credential to an employee; the employee issues an AMC to an AI agent whose KERI identifier is a *delegated AID under the employee's key event log*. The agent's Ed25519 key is, at the same time, a **function-call access key on the NEAR contract account** — one key, two worlds.

The NEAR contract holds what the paper calls the mandate *state* that "no single intermediary holds" on open rails: how much of the limit is consumed, whether the counterparty is in scope, whether the mandate has expired, whether it is revoked. Revocation happens in the credential layer (KERI TEL); it is mirrored on-chain by deleting the agent's key, so the next payment fails at the protocol layer.

## What works today (do X → see Y)

Requirements: Rust 1.97 with `wasm32-unknown-unknown`, Node 22, Python 3.11+ (for the KERI mock). First test run downloads the NEAR sandbox binary (network once).

1. `cd contract && make test`
   → 3 tests pass. The log shows:
   - an agent key on the contract account with `method_names: ["spend", "present"]`;
   - a prompt-injected payment to `attacker.test.near` returning `{"Rejected":{"reason":"SCOPE","rejects":1}}` **with a transaction hash**;
   - the agent calling `register` rejected by the protocol: `InvalidAccessKeyError(MethodNameMismatch)`;
   - after `revoke`, the agent's next call rejected: `InvalidAccessKeyError(AccessKeyNotFound)`;
   - a real KERI `ixn` event (issuer's revocation anchor) verified on-chain by `env::ed25519_verify` → `true`.
2. `cd keri && python -m venv .venv && .venv/bin/pip install keri && .venv/bin/python mock_ecosystem.py`
   → prints the LE / employee / delegated-agent AIDs, the ECR and AMC SAIDs, the TEL state `rev sn=1`, and the anchoring `ixn` with seal `{i: <AMC SAID>, s: "1", d: <rev SAID>}`; rewrites `contract/tests/fixtures/`.
3. `cd agent && npm install && RPC=... CONTRACT=... OWNER_KEY=... npx tsx spike6.ts` (against a running sandbox; see `docs/D1_spike_report.md`)
   → the agent CLI labels four distinct failures: `POLICY REJECTED`, `PROTOCOL BLOCKED`, `MANDATE REVOKED`, `GAS ALLOWANCE EXHAUSTED`.

If your environment caps the file-descriptor hard limit below 65535 (some containers), `make test-lowfd` preloads `tools/fakerlimit.so`; see `docs/D1_spike_report.md`.

## Planned (not implemented yet)

Five-predicate `spend` (chain valid / not revoked / within limit via PayWord hash chain / counterparty in scope / not expired), rate limit, tripwire, verifier reading real ACDCs, watcher that mirrors TEL revocation to `delete_key`, attack bench, merchant page, HR dashboard, optional tier-1 commitment disclosure for a supervisor. Nothing here is "anonymous"; the LEI is kept off-chain by selective disclosure, not by zero-knowledge.

## Baseline disclosure

Everything in this repository was written during the hackathon window (from 2026-11-01). Pre-existing libraries by the same author that will be used as baseline later and disclosed when used: `mcp-vlei` (vLEI MCP tooling, Python), `carbon-lei` (TS vLEI verifier).

## License

MIT.
