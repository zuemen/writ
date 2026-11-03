# Writ —— 一鍵指令。除了 make testnet 以外都只碰本機 sandbox，不需要任何 API key。
#   make setup   安裝依賴、建置合約、下載 sandbox（需網路一次）
#   make test    合約攻擊台 → 重產 docs/bench.md
#   make demo    起本機 sandbox → 布置帳號與 mock vLEI → 跑 60 秒故事 → 關 sandbox
#   make ui      起 sandbox + 布置 + 開網頁（http://localhost:8787）
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

# 「誰負責」的完整故事：賒帳、按時付款、違約、保證人賠付、追償、揭露。用真 KERI 簽章，只碰本機 sandbox
credit-demo: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/credit-demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# 選用：真 LLM 當 agent（需要 NEARAI_API_KEY）。只碰本機 sandbox。結果寫進 docs/attack-live.md
attack-live: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && WRIT_N=500 WRIT_DAILY=500 WRIT_MAX_STRIKES=0 npx tsx src/setup.ts && npx tsx src/agent-live.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# 選用：真 LLM 讀採購單並賒帳。結果寫進 docs/attack-credit-live.md
attack-credit-live: setup
	scripts/sandbox.sh stop; scripts/sandbox.sh start
	cd app && WRIT_N=500 WRIT_DAILY=500 WRIT_MAX_STRIKES=0 npx tsx src/setup.ts && npx tsx src/agent-credit.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

# 用 Circle 的 testnet USDC 跑一筆真實付款（法人要先從 faucet 領幣）。結果寫進 docs/testnet-usdc.md
testnet-usdc: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/usdc-setup.ts

# 在 testnet 開「鑰匙公開」的格並組出網頁（要先跑過 make testnet）。私鑰只在 .demo-testnet/，不進 repo
bounty: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/bounty-setup.ts
	bash scripts/build_site.sh

# 網站「Fool a live model」用的 agent：小額真預算（要先跑過 make testnet）。私鑰只在 .demo-testnet/，不進 repo
live-agent: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/live-setup.ts

# 替網站預開一批委任格（訪客在瀏覽器走完整流程用）。私鑰只在 .demo-testnet/，不進 repo
pool: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/pool-setup.ts
	bash scripts/build_site.sh

# 一個指令重現所有主張，最後印成績單
verify:
	PY=$(PY) bash scripts/verify_all.sh

clean:
	scripts/sandbox.sh stop; rm -rf .demo .sandbox keri/.keystore keri/bundle keri/registrar
.PHONY: setup test keri-check demo ui clean testnet testnet-usdc attack-live bounty pool live-agent verify credit-demo credit-testnet attack-credit-live

# 需要本人同意：會在 NEAR testnet 建帳號、部署、簽交易（測試幣，免費）。結果寫進 docs/testnet.md
testnet: setup
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-setup.ts \
	 && NEAR_RPC=https://test.rpc.fastnear.com WRIT_UNSEAL_SECS=60 WRIT_DEMO_DIR=.demo-testnet npx tsx src/demo.ts \
	 && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-report.ts

# 賒帳故事在 testnet 跑一次，留交易連結（要先 make testnet）
credit-testnet:
	cd app && NEAR_RPC=https://test.rpc.fastnear.com WRIT_DEMO_DIR=.demo-testnet WRIT_RECOURSE_SECS=20 WRIT_CREDIT_REPORT=../docs/testnet-credit.md npx tsx src/credit-demo.ts
