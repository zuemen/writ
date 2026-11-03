# Contract: build and attack bench. The first test run downloads the near-sandbox binary (needs network once).
# .cargo/config.toml already adds --cfg near (needed by near-sdk 5.30; cargo-near adds it automatically, here we use plain cargo).
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

# Run the attack bench and regenerate docs/bench.md; exit 1 if any test fails
test: build
	cargo test --lib
	cargo test --test bench -- --nocapture --test-threads=2 2>&1 | tee /tmp/writ_bench.log | python3 ../scripts/bench_table.py > ../docs/bench.md
	cat ../docs/bench.md
	grep "test result" /tmp/writ_bench.log
	grep -q "test result: ok" /tmp/writ_bench.log || { grep -E "panicked|^Error|Error:" /tmp/writ_bench.log | head -20; exit 1; }

# In a container, neard refuses to start when the fd hard limit is < 65535; work around it with a shim (not needed on a normal computer)
test-lowfd: build ../tools/fakerlimit.so
	LD_PRELOAD=$(abspath ../tools/fakerlimit.so) $(MAKE) test-inner
test-inner:
	cargo test --lib
	cargo test --test bench -- --nocapture --test-threads=2 2>&1 | tee /tmp/writ_bench.log | python3 ../scripts/bench_table.py > ../docs/bench.md
	cat ../docs/bench.md
	grep "test result" /tmp/writ_bench.log
	grep -q "test result: ok" /tmp/writ_bench.log || { grep -E "panicked|^Error|Error:" /tmp/writ_bench.log | head -20; exit 1; }
../tools/fakerlimit.so: ../tools/fakerlimit.c
	gcc -shared -fPIC -o $@ $< -ldl
