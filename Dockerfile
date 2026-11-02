# 給沒有 Rust／libsodium 的評審環境：docker build -t writ . && docker run --rm writ
# 預設跑 make test（攻擊台）與 make demo（8 步故事）。網頁：docker run --rm -p 8787:8787 writ make ui
# 基底跟 CI 相同（Ubuntu 24.04），near-sandbox 在這個環境驗證過；keripy 的依賴要比內建 3.12.3 新的 Python，用 uv 裝
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsodium23 curl ca-certificates gcc libc6-dev make \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.0 -t wasm32-unknown-unknown
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh  && uv python install 3.12 --install-dir /opt/py  && ln -s "$(ls -d /opt/py/cpython-3.12.*/bin/python3.12 | head -1)" /usr/local/bin/python3
WORKDIR /writ
COPY . .
RUN make setup
CMD ["sh", "-c", "make test && make demo"]
