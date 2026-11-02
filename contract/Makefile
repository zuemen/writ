# 合約：建置與攻擊台。第一次跑測試會下載 near-sandbox 二進位（需網路一次）。
# .cargo/config.toml 已加 --cfg near（near-sdk 5.30 需要；cargo-near 會自動加，這裡用 plain cargo）。
WASM_OPT := $(wildcard ../app/node_modules/.bin/wasm-opt)
build:
	cargo build --target wasm32-unknown-unknown --release
	mkdir -p res
ifneq ($(WASM_OPT),)
	$(WASM_OPT) -Oz --strip-debug target/wasm32-unknown-unknown/release/writ.wasm -o res/writ.wasm
else
	cp target/wasm32-unknown-unknown/release/writ.wasm res/writ.wasm
endif
	ls -l res/writ.wasm
	sha256sum res/writ.wasm
	cd ft-mock && cargo build --target wasm32-unknown-unknown --release
	cp ft-mock/target/wasm32-unknown-unknown/release/ft_mock.wasm res/ft_mock.wasm

# 跑攻擊台並重產 docs/bench.md；任何測試失敗則 exit 1
test: build
	cargo test --test bench -- --nocapture --test-threads=2 2>&1 | tee /tmp/writ_bench.log | python3 ../scripts/bench_table.py > ../docs/bench.md
	cat ../docs/bench.md
	grep -q "test result: ok" /tmp/writ_bench.log

# 容器裡 fd 硬上限 < 65535 時 neard 拒絕啟動；用 shim 繞過（一般電腦不需要）
test-lowfd: build ../tools/fakerlimit.so
	LD_PRELOAD=$(abspath ../tools/fakerlimit.so) $(MAKE) test-inner
test-inner:
	cargo test --test bench -- --nocapture --test-threads=2 2>&1 | tee /tmp/writ_bench.log | python3 ../scripts/bench_table.py > ../docs/bench.md
	cat ../docs/bench.md
	grep -q "test result: ok" /tmp/writ_bench.log
../tools/fakerlimit.so: ../tools/fakerlimit.c
	gcc -shared -fPIC -o $@ $< -ldl
