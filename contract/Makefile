# 合約：建置與測試。sandbox 測試第一次會下載 near-sandbox 二進位（需網路一次）。
build:
	cargo build --target wasm32-unknown-unknown --release
test: build
	cargo test --test sandbox -- --nocapture --test-threads=1
# 容器裡 fd 硬上限 < 65535 時 neard 拒絕啟動；用 shim 繞過（一般電腦不需要）
test-lowfd: build
	LD_PRELOAD=$(PWD)/../tools/fakerlimit.so cargo test --test sandbox -- --nocapture --test-threads=1
