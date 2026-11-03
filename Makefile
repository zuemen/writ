# Writ: one-command targets. Everything except make testnet touches only the local sandbox; no API key needed.
#   make setup   install dependencies, build the contract, download the sandbox (needs network once)
#   make test    contract attack bench, regenerates docs/bench.md
#   make demo    start local sandbox, set up accounts and mock vLEI, run the 60-second story, stop the sandbox
#   make ui      start sandbox, set up, open the web UI (http://localhost:8787)
PY ?= python3

setup: keri/.venv/bin/python app/node_modules
	$(MAKE) -C contract build
	cd contract && cargo test --no-run --quiet
keri/.venv/bin/python:
	$(PY) -m venv keri/.venv && keri/.venv/bin/pip install -q -r keri/requirements.txt
app/node_modules:
	cd app && npm ci

test:
	@if [ "$$(ulimit -Hn)" != "unlimited" ] && [ "$$(ulimit -Hn)" -lt 65535 ]; then $(MAKE) -C contract test-lowfd; else $(MAKE) -C contract test; fi

keri-check: keri/.venv/bin/python
	rm -rf keri/.keystore keri/bundle keri/registrar
	cd keri && .venv/bin/python issuer.py init --scope merchant.test.near --rail acme.test.near > /tmp/writ_init.json
	cd keri && .venv/bin/python verify.py pin --root "$$(.venv/bin/python -c "import json;print(json.load(open('.keystore/state.json'))['root'])")"
	cd keri && .venv/bin/python verify.py check
	cd keri && .venv/bin/python test_forgeries.py

demo: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

ui: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/server.ts

# The full "who is responsible" story: credit sale, on-time payment, default, guarantor payout, recovery, disclosure. Uses real KERI signatures; local sandbox only
credit-demo: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/credit-demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# Same story with a stablecoin: local ft-mock (6 decimals), seller pays the guarantee fee. Local sandbox only
credit-usdc-demo: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/credit-usdc-demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# An agent fooled inside its limits, and the guarantor named beforehand repays part of the loss, in NEAR and in a token. Uses real KERI signatures; local sandbox only
cover-demo: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/cover-demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# Optional: a real LLM as the agent (needs NEARAI_API_KEY). Local sandbox only. Results go to docs/attack-live.md
attack-live: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && WRIT_N=500 WRIT_DAILY=500 WRIT_MAX_STRIKES=0 npx tsx src/setup.ts && npx tsx src/agent-live.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# Optional: a real LLM reads purchase orders and buys on credit. Results go to docs/attack-credit-live.md
attack-credit-live: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && WRIT_N=500 WRIT_DAILY=500 WRIT_MAX_STRIKES=0 npx tsx src/setup.ts && npx tsx src/agent-credit.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# Run one real payment with Circle's testnet USDC (the legal entity must first get tokens from the faucet). Results go to docs/testnet-usdc.md
testnet-usdc: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/usdc-setup.ts

# Open a "public key" cell on testnet and build the web page (run make testnet first). Private keys stay in .demo-testnet/, not in the repo
bounty: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/bounty-setup.ts
	bash scripts/build_site.sh

# The covered mandate behind the site's "Fool the model": USDC, cover only, restricted company and arbiter keys (run make testnet first; acme needs testnet USDC). WRIT_LIVE_N sets the budget links. Private keys stay in .demo-testnet/, not in the repo
live-agent: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/live-setup.ts

# Pre-open a batch of mandate cells for the site (visitors run the full flow in the browser). Private keys stay in .demo-testnet/, not in the repo
pool: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/pool-setup.ts
	bash scripts/build_site.sh

# One command reproduces every claim and prints a scorecard at the end
verify:
	PY=$(PY) bash scripts/verify_all.sh

clean:
	scripts/sandbox.sh stop; rm -rf .demo .sandbox keri/.keystore keri/bundle keri/registrar
.PHONY: setup test keri-check demo ui clean testnet testnet-usdc attack-live bounty pool live-agent verify credit-demo credit-usdc-demo cover-demo credit-testnet attack-credit-live

# Needs the owner's consent: creates accounts on NEAR testnet, deploys, signs transactions (test tokens, free). Results go to docs/testnet.md
testnet: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-setup.ts \
	 && NEAR_RPC=https://test.rpc.fastnear.com WRIT_UNSEAL_SECS=60 WRIT_DEMO_DIR=.demo-testnet npx tsx src/demo.ts \
	 && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-report.ts

# Run the credit story once on testnet and keep the transaction links (run make testnet first)
credit-testnet:
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet WRIT_RECOURSE_SECS=20 WRIT_CREDIT_REPORT=../docs/testnet-credit.md npx tsx src/credit-demo.ts
