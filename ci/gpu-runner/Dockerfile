# GPU-capable self-hosted GitHub Actions runner for the Ceno zkVM.
#
# Modeled on scroll-tech/ceno-reth-benchmark:ci/Dockerfile. This image is purely
# the runner + build prerequisites — it carries NO secrets. The real GPU backend
# is the PRIVATE scroll-tech/ceno-gpu repo, which Cargo.toml's active [patch]
# pulls in as the local path ../ceno-gpu/cuda_hal (the public ceno-gpu-mock dep
# is just the registry placeholder that the patch overrides). The workflow clones
# ceno-gpu to ../ceno-gpu using a deploy key loaded into ssh-agent from GitHub
# secrets; see ci/gpu-runner/README.md for the snippet.
#
# Build:
#   docker build -t ceno-gpu-runner:latest -f ci/gpu-runner/Dockerfile .
#
# Match CUDA to your host driver (`nvidia-smi` top-right = max supported CUDA).
FROM nvidia/cuda:12.8.0-devel-ubuntu24.04

ARG RUNNER_VERSION="2.321.0"
ARG RUNNER_SHA256="ba46ba7ce3a4d7236b16fbe44419fb453bc08f866b24f04d549ec89f1722a29e"
ARG RUST_TOOLCHAIN="nightly-2025-11-20"
ARG DEBIAN_FRONTEND=noninteractive

# OS deps: build toolchain + Ceno CI needs (m4, git-lfs), runner needs (curl/jq),
# and SSH/git so the workflow can clone the private ceno-gpu repo.
# No nvidia-utils here: with `--gpus` the NVIDIA Container Toolkit injects the
# host's nvidia-smi + driver libs at runtime, so pinning a driver userspace in
# the image is redundant and risks mismatching the host driver.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl jq ca-certificates \
        build-essential cmake pkg-config libssl-dev libffi-dev \
        m4 git git-lfs openssh-client \
        sudo tar gzip \
    && git lfs install --system \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash docker \
    && echo "docker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install the actions runner (checksum-verified, like the reference).
RUN mkdir -p /home/docker/actions-runner \
    && cd /home/docker/actions-runner \
    && curl -fsSL -o runner.tar.gz \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    && echo "${RUNNER_SHA256}  runner.tar.gz" | shasum -a 256 -c \
    && tar xzf runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh \
    && chown -R docker:docker /home/docker \
    # Persistent build cache mount point. Creating it owned by `docker` here
    # means the (initially empty) named volume mounted at /cache inherits that
    # ownership on first use, so cargo can write CARGO_TARGET_DIR=/cache/target.
    && mkdir -p /cache/target && chown -R docker:docker /cache

# All cargo git deps are public (fetched over HTTPS, no auth). The only private
# repo is scroll-tech/ceno-gpu, which the workflow clones to ../ceno-gpu over SSH
# using a deploy key loaded into ssh-agent from GitHub secrets — no key or URL
# rewrite is baked into the image. Pre-seed github.com in known_hosts so that
# clone isn't blocked on host-key prompting.
USER docker
RUN git config --global --add safe.directory '*' \
    && mkdir -p /home/docker/.ssh && chmod 700 /home/docker/.ssh \
    && ssh-keyscan github.com >> /home/docker/.ssh/known_hosts

# Rust toolchain pinned to rust-toolchain.toml + riscv guest target + cargo-make.
ENV PATH="/home/docker/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}" --profile minimal \
    && rustup component add rust-src clippy rustfmt \
    && rustup target add riscv32im-unknown-none-elf \
    && cargo install cargo-make --locked

WORKDIR /home/docker/actions-runner

COPY --chown=docker:docker ci/gpu-runner/entrypoint.sh /usr/local/bin/runner-entrypoint.sh
USER root
RUN chmod +x /usr/local/bin/runner-entrypoint.sh
USER docker

ENTRYPOINT ["/usr/local/bin/runner-entrypoint.sh"]
