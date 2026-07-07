#!/usr/bin/env bash
# Run recursion v2 CPU-vs-GPU trace generation comparison tests.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURE_DIR="${1:-${CENO_RECURSION_V2_FIXTURE_DIR:-}}"

if [[ -n "$FIXTURE_DIR" ]]; then
    export CENO_RECURSION_V2_FIXTURE_DIR="$FIXTURE_DIR"
    echo "[fixtures] using CENO_RECURSION_V2_FIXTURE_DIR=$CENO_RECURSION_V2_FIXTURE_DIR"
else
    echo "[fixtures] using test defaults: ./src/imported, ./ceno_recursion_v2/src/imported, or repo root"
fi

cd "$REPO_ROOT"
RUST_MIN_STACK="${RUST_MIN_STACK:-33554432}" \
cargo test --manifest-path ceno_recursion_v2/Cargo.toml \
    --features cuda \
    cuda_tracegen \
    -- --nocapture
