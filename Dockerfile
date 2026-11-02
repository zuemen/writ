# 給沒有 Rust／libsodium 的評審環境：docker build -t writ . && docker run --rm writ
# 預設跑 make test（攻擊台）與 make demo（8 步故事）。網頁：docker run --rm -p 8787:8787 writ make ui
FROM rust:1.97-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsodium23 curl ca-certificates gcc make rsync \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
# keripy 需要 Python >= 3.12.2，bookworm 內建的不夠新
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh && uv python install 3.12 --install-dir /opt/py
RUN ln -s "$(ls -d /opt/py/cpython-3.12.*/bin/python3.12 | head -1)" /usr/local/bin/python3
WORKDIR /writ
COPY . .
RUN make setup
CMD ["sh", "-c", "make test && make demo"]
