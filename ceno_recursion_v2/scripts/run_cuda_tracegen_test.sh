#!/usr/bin/env bash
# Run recursion v2 CPU-vs-GPU trace generation comparison tests.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURE_DIR="${1:-${CENO_RECURSION_V2_FIXTURE_DIR:-$REPO_ROOT/ceno_recursion_v2/src/imported}}"
PROOF_FILE="$FIXTURE_DIR/proof.bin"
VK_FILE="$FIXTURE_DIR/vk.bin"
FORCE_REGEN="${CENO_RECURSION_V2_FORCE_REGEN:-0}"
MAX_CYCLE_PER_SHARD="${CENO_RECURSION_V2_MAX_CYCLE_PER_SHARD:-16000}"
HINTS="${CENO_RECURSION_V2_HINTS:-10}"
PUBLIC_IO="${CENO_RECURSION_V2_PUBLIC_IO:-4191}"
PCS="${CENO_RECURSION_V2_PCS:-jagged}"

export CENO_RECURSION_V2_FIXTURE_DIR="$FIXTURE_DIR"

if [[ "$FORCE_REGEN" != "1" && -f "$PROOF_FILE" && -f "$VK_FILE" ]]; then
    echo "[fixtures] found:"
    ls -lh "$PROOF_FILE" "$VK_FILE"
else
    echo "[fixtures] generating base-layer proofs (keccak_syscall, --pcs=$PCS, --max-cycle-per-shard=$MAX_CYCLE_PER_SHARD) ..."

    ELF="$REPO_ROOT/examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall"
    if [[ ! -f "$ELF" ]]; then
        echo "[fixtures] building example ELFs..."
        cargo build --release --manifest-path "$REPO_ROOT/examples/Cargo.toml" --examples
    fi

    mkdir -p "$FIXTURE_DIR"
    cargo run --release --package ceno_zkvm --bin e2e -- \
        --platform=ceno \
        --pcs="$PCS" \
        --max-cycle-per-shard="$MAX_CYCLE_PER_SHARD" \
        --hints="$HINTS" \
        --public-io="$PUBLIC_IO" \
        "$ELF" \
        "$PROOF_FILE" \
        "$VK_FILE"

    echo "[fixtures] generated:"
    ls -lh "$PROOF_FILE" "$VK_FILE"
fi

cd "$REPO_ROOT"
TESTS=(
    system::cuda_tracegen_tests::test_cuda_tracegen_compare_single_fixture_proof
    system::cuda_tracegen_tests::test_cuda_tracegen_compare_multi_fixture_proofs
    system::cuda_tracegen_tests::test_cuda_tracegen_required_heights_match_cpu
)

for test_name in "${TESTS[@]}"; do
    echo ""
    echo "[test] running $test_name ..."
    RUST_MIN_STACK="${RUST_MIN_STACK:-33554432}" \
    cargo test --release --manifest-path ceno_recursion_v2/Cargo.toml \
        --features cuda \
        "$test_name" \
        -- --exact --nocapture
done
