#!/usr/bin/env bash
# Run the recursion v2 e2e integration test.
# Generates base-layer proof fixtures if they don't exist.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURE_DIR="${CENO_RECURSION_V2_FIXTURE_DIR:-$REPO_ROOT/ceno_recursion_v2/src/imported}"
PROOF_FILE="$FIXTURE_DIR/proof.bin"
VK_FILE="$FIXTURE_DIR/vk.bin"
FORCE_REGEN="${CENO_RECURSION_V2_FORCE_REGEN:-0}"
MAX_CYCLE_PER_SHARD="${CENO_RECURSION_V2_MAX_CYCLE_PER_SHARD:-16000}"
HINTS="${CENO_RECURSION_V2_HINTS:-10}"
PUBLIC_IO="${CENO_RECURSION_V2_PUBLIC_IO:-4191}"

# --- Step 1: ensure fixtures exist ---

if [[ "$FORCE_REGEN" != "1" && -f "$PROOF_FILE" && -f "$VK_FILE" ]]; then
    echo "[fixtures] found:"
    ls -lh "$PROOF_FILE" "$VK_FILE"
else
    echo "[fixtures] generating base-layer proofs (fibonacci, --max-cycle-per-shard=$MAX_CYCLE_PER_SHARD) ..."

    ELF="$REPO_ROOT/examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci"
    if [[ ! -f "$ELF" ]]; then
        echo "[fixtures] building example ELFs..."
        cargo build --release --manifest-path "$REPO_ROOT/examples/Cargo.toml" --examples
    fi

    mkdir -p "$FIXTURE_DIR"
    cargo run --release --package ceno_zkvm --bin e2e -- \
        --platform=ceno \
        --pcs=basefold \
        --max-cycle-per-shard="$MAX_CYCLE_PER_SHARD" \
        --hints="$HINTS" \
        --public-io="$PUBLIC_IO" \
        "$ELF" \
        "$PROOF_FILE" \
        "$VK_FILE"

    echo "[fixtures] generated:"
    ls -lh "$PROOF_FILE" "$VK_FILE"
fi

# --- Step 2: run the e2e integration test ---

echo ""
echo "[test] running recursion v2 e2e tests ..."
cd "$REPO_ROOT/ceno_recursion_v2"
CENO_RECURSION_V2_FIXTURE_DIR="$FIXTURE_DIR" \
RUST_MIN_STACK=33554432 \
cargo test --release \
    'continuation::tests::prover_integration' \
    -- --nocapture
