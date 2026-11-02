# 給沒有 Rust／libsodium 的評審環境：docker build -t writ . && docker run --rm writ
# 預設跑 make test（攻擊台）與 make demo（7 步故事）。網頁：docker run --rm -p 8787:8787 writ make ui
FROM rust:1.97-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip libsodium23 curl ca-certificates gcc make \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
WORKDIR /writ
COPY . .
RUN make setup
CMD ["sh", "-c", "make test && make demo"]
