# Devcontainer Dockerfile. Mirrors Dockerfile.repro's base + toolchain
# pins, plus the developer-ergonomic bits (sudo, zsh, codespaces' vscode
# user). Onboarding-targeted; production rebuilds go through
# Dockerfile.repro which is leaner.
FROM debian:bookworm-slim@sha256:b1211f6435efebaa61ce9b8aef79bc44d1a30b66c43e9f44ee2f74dab33e2d5e

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg git pkg-config build-essential libssl-dev \
    sudo zsh \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m -s /bin/zsh $USERNAME \
    && echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
ENV RUST_VERSION=1.80.1

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh; \
    sh /tmp/rustup-init.sh -y --default-toolchain "${RUST_VERSION}" --profile minimal --no-modify-path; \
    rm /tmp/rustup-init.sh; \
    rustup component add rustfmt clippy rust-src rust-analyzer; \
    chmod -R a+rwX /usr/local/rustup /usr/local/cargo

RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    npm install -g corepack@latest; \
    corepack enable; \
    corepack prepare pnpm@9.15.0 --activate

USER $USERNAME
WORKDIR /workspaces/gemma-witness
