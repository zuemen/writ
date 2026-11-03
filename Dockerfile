# For reviewer environments without Rust/libsodium: docker build -t writ . && docker run --rm writ
# Runs make test (attack bench) and make demo (8-step story) by default. Web UI: docker run --rm -p 8787:8787 writ make ui
# Same base as CI (Ubuntu 24.04); near-sandbox is verified in this environment. keripy needs a newer Python than the bundled 3.12.3, installed with uv
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsodium23 curl ca-certificates gcc libc6-dev make pkg-config libssl-dev \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.0 -c rustfmt -c clippy -t wasm32-unknown-unknown
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh  && uv python install 3.12 --install-dir /opt/py  && ln -s "$(ls -d /opt/py/cpython-3.12.*/bin/python3.12 | head -1)" /usr/local/bin/python3
WORKDIR /writ
COPY . .
RUN make setup
CMD ["sh", "-c", "make test && make demo && make credit-demo"]
