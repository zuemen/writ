# Contributing

1. Run `make verify`. It must end in `VERIFY_RESULT|PASS`.
2. A change to `contract/` needs a test. A new defense also needs a numbered attack in `contract/tests/bench.rs`, and a new money path needs exact values in `contract/src/exact.rs`.
3. Do not change a number in the docs without the command that produces it.
4. Keep commit subjects under 72 characters.

Never commit a key. Test keys live in `.demo-testnet/`, which is ignored.
