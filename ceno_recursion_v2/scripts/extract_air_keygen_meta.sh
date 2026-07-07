#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
RUST_MIN_STACK="${RUST_MIN_STACK:-67108864}" cargo run --release --quiet --bin air_keygen_meta -- "$@"
