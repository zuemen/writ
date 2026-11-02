# Writ —— 一鍵指令。除了 make testnet 以外都只碰本機 sandbox，不需要任何 API key。
#   make setup   安裝依賴、建置合約、下載 sandbox（需網路一次）
#   make test    合約攻擊台 → 重產 docs/bench.md
#   make demo    起本機 sandbox → 布置帳號與 mock vLEI → 跑 60 秒故事 → 關 sandbox
#   make ui      起 sandbox + 布置 + 開網頁（http://localhost:8787）
PY ?= python3

setup: keri/.venv/bin/python app/node_modules
	$(MAKE) -C contract build
keri/.venv/bin/python:
	$(PY) -m venv keri/.venv && keri/.venv/bin/pip install -q -r keri/requirements.txt
app/node_modules:
	cd app && npm ci

test:
	@if [ "$$(ulimit -Hn)" != "unlimited" ] && [ "$$(ulimit -Hn)" -lt 65535 ]; then $(MAKE) -C contract test-lowfd; else $(MAKE) -C contract test; fi

keri-check: keri/.venv/bin/python
	rm -rf keri/.keystore keri/bundle
	cd keri && .venv/bin/python issuer.py init --scope merchant.test.near --rail acme.test.near >/dev/null
	cd keri && .venv/bin/python verify.py check

demo: setup
	scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/demo.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

ui: setup
	scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/server.ts

# 選用：真 LLM 當 agent（需要 NEARAI_API_KEY）。只碰本機 sandbox。結果寫進 docs/attack-live.md
attack-live: setup
	scripts/sandbox.sh start
	cd app && npx tsx src/setup.ts && npx tsx src/agent-live.ts; status=$$?; cd .. && scripts/sandbox.sh stop; exit $$status

clean:
	scripts/sandbox.sh stop; rm -rf .demo .sandbox keri/.keystore keri/bundle
.PHONY: setup test keri-check demo ui clean testnet attack-live

# 需要本人同意：會在 NEAR testnet 建帳號、部署、簽交易（測試幣，免費）。結果寫進 docs/testnet.md
testnet: setup
	cd app && NEAR_RPC=https://rpc.testnet.near.org WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-setup.ts \
	 && NEAR_RPC=https://rpc.testnet.near.org WRIT_DEMO_DIR=.demo-testnet npx tsx src/demo.ts \
	 && WRIT_DEMO_DIR=.demo-testnet npx tsx src/testnet-report.ts
