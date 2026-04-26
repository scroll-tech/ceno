# WIP Summary: non-pow2 prover storage / GPU tower + PCS follow-up

Date: 2026-04-25

Repos involved
- current repo: `/home/wusm/rust/ceno`
- GPU repo: `/home/wusm/rust/ceno-gpu`
- backend repo: `/home/wusm/rust/gkr-backend`

Primary goal
- Remove prover-side MLE zero padding to next power-of-two.
- Keep prover storage compact by occupied length.
- Verifier semantics stay unchanged.

Design agreed in this WIP
- Raw/original MLE inputs before sumcheck round 0 should use one unified policy:
  - direct/native order
  - occupied length respected
  - this applies to both tower and PCS batch opening
- After round 0:
  - folded values can use the normal later-round in-place buffer layout
- No separate application-specific policy for tower vs PCS.
- For tower specifically:
  - within one tower layer, all MLEs should have the same `num_vars`
  - tower should not rely on a meaningful “small MLE” mixed-size case

What was fixed earlier in this WIP

1. PCS / batch-open path
- Fixed missing round evaluations from GPU V2 sumcheck:
  - `../ceno-gpu/cuda_hal/src/common/sumcheck/generic_v2.rs`
- Fixed compact raw-data handling in batch open and commit/open consistency.
- Fixed an earlier `RootMismatch` by correcting raw trace -> encode padding boundary in batch commit.
- PCS later reached `final_codeword.values[idx] != folded`, then was narrowed further.
- At one point PCS/basefold batch-open `eq` layout mismatch was fixed by using Ceno/direct order.
- CPU e2e for the lightweight repro still passes.

2. Tower witness/materialization direction
- Compact CPU oracle for tower semantics was added in:
  - `../ceno-gpu/cuda_hal/src/common/tower/utils.rs`
- GPU tower build path was refactored toward compact storage in:
  - `../ceno-gpu/cuda_hal/src/common/tower/mod.rs`
  - `../ceno-gpu/cpp/common/tower.cuh`
  - `../ceno-gpu/cpp/bb31/kernels/tower.cu`
  - `../ceno-gpu/cpp/gl64/kernels/tower.cu`
- A lifetime bug causing segfault in GPU tower eval extraction was fixed by retaining owned buffer backing:
  - `../ceno-gpu/cuda_hal/src/common/buffer.rs`
  - `../ceno-gpu/cuda_hal/src/lib.rs`

3. Important debug correction
- There was a previous debug bug caused by cloning the transcript after GPU proving.
- That was fixed.
- Current CPU/GPU prover compares should assume transcript state is cloned before proof generation.

Current CPU/GPU status

CPU baseline
- Command:
  - `cargo run --release --package ceno_zkvm --features sanity-check --bin e2e -- --platform=ceno --max-cycle-per-shard=1000 --hints=2 --public-io=5 --shard-id=0 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci`
- Result:
  - passes

GPU lightweight repro
- Command:
  - `RUST_LOG=error CENO_CONCURRENT_CHIP_PROVING=0 cargo run --release --features gpu --package ceno_zkvm --features sanity-check --bin e2e -- --platform=ceno --max-cycle-per-shard=1000 --hints=2 --public-io=5 --shard-id=0 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci`
- Current result:
  - still fails with tower verification mismatch
  - source:
    - `ceno_zkvm/src/e2e.rs:2347`
    - `VerifyError("mismatch tower evaluation")`

Most important findings from the latest tower debug

1. Tower witness is not the first bad stage
- CPU/GPU tower witness compare did not fail first.
- Tower witness transport/leaf construction is not the main active bug.

2. The earlier isolated layer-2 compare proved:
- `cpu_direct == v1`
- `v2 != cpu_direct`
- This was on a tower layer where all MLEs were full occupied:
  - debug payload showed `mle_shape=[(?, 2, 4), ...]`
  - meaning `num_vars=2`, `len=4` for all MLEs in that isolated layer
- That means the tower failure is not because tower requires mixed-size/small-MLE semantics.

3. The current design conclusion
- Tower should use the same original-input policy as PCS:
  - direct order before round 0
  - later rounds use the in-place buffer
- Do NOT think of this as two policies.

4. Terminology decision
- Do not call later-round folded storage “replay buffer”.
- Call it:
  - in-place buffer
- Round 0:
  - non-in-place, reading original inputs
- Round > 0:
  - in-place

Latest code changes in the current session

In `../ceno-gpu/cuda_hal/src/common/sumcheck/generic_v2.rs`
- Renamed V2 metadata from `compact_layout_flags` to `original_layout_flags`
- This now means:
  - `1` => original round-0 input is direct/native order
- This is intended to make the model explicit and shared across tower + PCS

In `../ceno-gpu/cpp/common/sumcheck/generic_v2.cuh`
- Added `direct_pair_index_v2`
- Changed direct-order round-0 reads for full-size equal-`num_vars` originals to use adjacent pairs:
  - `(2p, 2p+1)`
  - not `(p, p + stride)`
- Restored small-MLE helper mapping back to high-bit based mapping:
  - `suffix_small_index_v2(...)` currently uses:
    - `tid >> (num_vars - 1 - mle_num_vars)`
- Reverted an incorrect attempt to bit-reverse first-fold writes into the in-place buffer
- Current code writes first-fold results contiguously into the in-place buffer

In `../ceno-gpu/cuda_hal/src/common/tower/mod.rs`
- Relaxed tower assertions so layers can be compact-by-occupation, not necessarily full logical length at Rust-side checks

What the latest tower debug showed

Most recent trustworthy mismatch before the last interrupted run
- CPU/GPU tower compare failed at:
  - `ceno_zkvm/src/scheme/gpu/mod.rs:665`
- Message:
  - `CPU/GPU tower sumcheck proof mismatch: first_round=Some(2)`
- Interpretation:
  - earlier proof entries already match
  - divergence starts later, consistent with in-place-buffer semantics rather than original-input semantics

Important caution about last run
- A later run was interrupted before producing a new useful payload.
- So do NOT assume the very latest in-place-buffer edits fixed anything.
- The last reliable signal is still:
  - tower mismatch has moved later than round 0
  - current bug is likely in round > 0 in-place-buffer semantics

Debug helpers currently present in `ceno_zkvm/src/scheme/gpu/mod.rs`
- `debug_compare_tower_cpu_gpu_prover(...)`
- `debug_compare_tower_eq_layers(...)`
- `debug_compare_tower_layer_v1_v2(..., round)`
- currently called for:
  - `round = 2`
  - `round = 3`

Be careful
- Some helpers use fresh local transcripts like:
  - `BasicTranscript::new(b"tower-layer2-debug")`
- These are only valid for isolated V1/V2/CPU direct comparisons.
- They are NOT end-to-end transcript or verifier oracles.

Current best hypothesis
- The active tower bug is now in V2 later-round in-place-buffer semantics, not in:
  - tower witness layout
  - original round-0 direct-order policy
  - transcript clone bugs

Most relevant files to inspect next

Current repo
- `ceno_zkvm/src/scheme/gpu/mod.rs`
- `ceno_zkvm/src/e2e.rs`

GPU repo
- `../ceno-gpu/cuda_hal/src/common/sumcheck/generic_v2.rs`
- `../ceno-gpu/cpp/common/sumcheck/generic_v2.cuh`
- `../ceno-gpu/cuda_hal/src/common/tower/mod.rs`
- `../ceno-gpu/cuda_hal/src/common/tower/utils.rs`
- `../ceno-gpu/cuda_hal/src/lib.rs`
- `../ceno-gpu/cuda_hal/src/common/buffer.rs`

Backend repo
- `../gkr-backend/crates/mpcs/...`
- `../gkr-backend/crates/sumcheck/...`

Recommended next step for the new session
1. Read this file.
2. Keep CPU baseline as source of truth.
3. Continue from the latest tower state, focusing only on later-round in-place-buffer semantics in:
   - `../ceno-gpu/cpp/common/sumcheck/generic_v2.cuh`
4. Run exactly one lightweight GPU repro at a time:
   - `RUST_LOG=error CENO_CONCURRENT_CHIP_PROVING=0 cargo run --release --features gpu --package ceno_zkvm --features sanity-check --bin e2e -- --platform=ceno --max-cycle-per-shard=1000 --hints=2 --public-io=5 --shard-id=0 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci`

Backups / snapshots
- Earlier stash-save/apply snapshots were created in this workstream.
- There is also filesystem snapshot history under:
  - `/home/wusm/rust/ceno/.codex-backups/`


## E2E / validation commands executed in compact tower batch + estimator work

Context
- Full clean was run before validating newly added CUDA kernels, to avoid stale C++/CUDA artifacts.
- Heavy commands used `timeout 1800s` so compilation can be slow, but execution cannot hang indefinitely.
- Logs were written to `/tmp` for later inspection.

Clean/build commands
```bash
cargo clean
cargo clean --manifest-path ../ceno-gpu/cuda_hal/Cargo.toml
```

```bash
cargo build --release --features gpu --package ceno_zkvm --features sanity-check --bin e2e
```
Result
- Passed.
- Elapsed: `4:07.82`.

Lightweight sanity e2e after clean
```bash
RUST_LOG=error CENO_CONCURRENT_CHIP_PROVING=0 target/release/e2e --platform=ceno --max-cycle-per-shard=1000 --hints=2 --public-io=5 --shard-id=0 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci
```
Result
- Passed.
- Elapsed: `0:09.29`.

Cargo check after compact batch/estimator edits
```bash
timeout 300s cargo check --features gpu --package ceno_zkvm --bin e2e
```
Result
- Passed.

Final lightweight sanity e2e after removing temporary debug probe
```bash
RUST_LOG=error CENO_CONCURRENT_CHIP_PROVING=0 target/release/e2e --platform=ceno --max-cycle-per-shard=1000 --hints=2 --public-io=5 --shard-id=0 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci
```
Result
- Passed.
- Elapsed: `0:08.34`.

Heavy e2e command 1: serial proving + GPU mem tracking
```bash
CENO_GPU_MEM_TRACKING=1 CENO_CONCURRENT_CHIP_PROVING=0 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall
```
Executed with timeout/log wrapper:
```bash
/usr/bin/time -f 'elapsed %E' timeout 1800s env CENO_GPU_MEM_TRACKING=1 CENO_CONCURRENT_CHIP_PROVING=0 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall 2>&1 | tee /tmp/ceno-keccak-memtracking-serial.log
```
Initial result
- Failed due strict memory-estimator overestimate, not proof failure.
- Panic:
  - `[memcheck] build_tower_witness_gpu: over-estimate! estimated=146.93MB, actual=126.43MB, diff=20.50MB, margin=10.00MB`
- Elapsed: `1:19.48`.

After estimator fix, rerun with log:
```bash
/usr/bin/time -f 'elapsed %E' timeout 1800s env CENO_GPU_MEM_TRACKING=1 CENO_CONCURRENT_CHIP_PROVING=0 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall 2>&1 | tee /tmp/ceno-keccak-memtracking-serial-after-estimate.log
```
Final result
- Passed.
- Elapsed: `1:15.43`.
- Log: `/tmp/ceno-keccak-memtracking-serial-after-estimate.log`.

Heavy e2e command 2: concurrent chip proving + GPU witgen
```bash
CENO_GPU_MEM_TRACKING=0 CENO_CONCURRENT_CHIP_PROVING=1 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall
```
Executed with timeout/log wrapper before estimator fix:
```bash
/usr/bin/time -f 'elapsed %E' timeout 1800s env CENO_GPU_MEM_TRACKING=0 CENO_CONCURRENT_CHIP_PROVING=1 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall 2>&1 | tee /tmp/ceno-keccak-concurrent-witgen.log
```
Result
- Passed.
- Elapsed: `0:10.02`.
- Final pool peak around `291MB`.
- Log: `/tmp/ceno-keccak-concurrent-witgen.log`.

Executed again after estimator fix:
```bash
/usr/bin/time -f 'elapsed %E' timeout 1800s env CENO_GPU_MEM_TRACKING=0 CENO_CONCURRENT_CHIP_PROVING=1 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall 2>&1 | tee /tmp/ceno-keccak-concurrent-witgen-after-estimate.log
```
Final result
- Passed.
- Elapsed: `0:10.74`.
- Log: `/tmp/ceno-keccak-concurrent-witgen-after-estimate.log`.

Diff hygiene commands
```bash
git diff --check
git -C ../ceno-gpu diff --check
```
Result
- Both passed.

## Restart state: benchmark memcheck under-estimate follow-up

Date: 2026-04-26

Current task
- User reported a remaining GPU memory under-estimate when running the top-entry repo `/home/wusm/rust/ceno-reth-benchmark` against the local `/home/wusm/rust/ceno` repo.
- The benchmark command must use `--rpc-url "$CENO_RPC"`; do not paste or persist concrete RPC URLs in logs or docs.
- In the current shell, `CENO_RPC` was not set, so the benchmark repro could not be completed before restart.

Current repo state
- Main repo: `/home/wusm/rust/ceno`
- Current branch includes commit:
  - `5ecce046 fix mem estimator`
- Important existing fix already present:
  - `ceno_zkvm/src/scheme/gpu/memory.rs` now estimates `build_main_witness` by materialized GKR outputs, not only final tower outputs.
  - This fixed the earlier `Ecall_Keccak` under-estimate where old estimate was around `11.73MB` and actual was `16.00MB`.
- Local root `Cargo.toml` and `Cargo.lock` are dirty from pre-existing dependency/local-path work; do not accidentally revert them unless explicitly requested.

New diagnostic patch added before restart
- Added contextual labels to GPU memcheck output so future failures identify both stage and circuit.
- Files touched:
  - `ceno_zkvm/src/scheme/gpu/memory.rs`
    - added `check_gpu_mem_estimation_with_context(...)`
    - labels now print like `build_main_witness[Ecall_Keccak]`
  - `ceno_zkvm/src/scheme/utils.rs`
    - `build_main_witness` memcheck now includes first GKR layer name
  - `ceno_zkvm/src/scheme/prover.rs`
    - replay/build-tower/prove-tower memchecks now include circuit name in sequential GPU proving path
  - `ceno_zkvm/src/scheme/gpu/mod.rs`
    - prover trait memchecks now include first GKR layer name or task circuit name where available
- This patch is diagnostic/safety oriented; it does not change memory estimates.

Validation already run after diagnostic patch
```bash
cargo fmt --check
```
Result
- Passed.

```bash
timeout 300s cargo check --features gpu --package ceno_zkvm --bin e2e
```
Result
- Passed.

Lightweight memcheck e2e command run after diagnostic patch
```bash
/usr/bin/time -f 'elapsed %E' timeout 900s env CENO_GPU_MEM_TRACKING=1 CENO_CONCURRENT_CHIP_PROVING=0 CENO_GPU_ENABLE_WITGEN=1 cargo run --config net.git-fetch-with-cli=true --release --package ceno_zkvm --features gpu --bin e2e -- --platform=ceno --max-cycle-per-shard=1600 examples/target/riscv32im-ceno-zkvm-elf/release/examples/keccak_syscall 2>&1 | tee /tmp/ceno-light-keccak-context-memcheck.log
```
Result
- Memcheck stages passed; no under-estimate panic.
- The run still fails later at the known verifier assertion in `gkr_iop/src/gkr/layer/zerocheck_layer.rs:306`.
- Useful log examples:
  - `replay_gpu_witness_from_raw[Ecall_Keccak]: estimated=11.23MB, actual=11.23MB`
  - `build_main_witness[Ecall_Keccak]: estimated=32.41MB, actual=32.59MB`
  - `build_tower_witness_gpu[Ecall_Keccak]: estimated=105.83MB, actual=106.01MB`
  - `prove_tower_relation_gpu[Ecall_Keccak]: estimated=36.84MB, actual=37.26MB`
  - `replay_gpu_witness_from_raw[ShardRamCircuit]: estimated=0.38MB, actual=0.38MB`
  - `build_main_witness[ShardRamCircuit_main]: estimated=0.01MB, actual=0.01MB`
  - `build_tower_witness_gpu[ShardRamCircuit]: estimated=0.01MB, actual=0.02MB`

Important conclusion so far
- Lightweight Ceno `keccak_syscall` no longer reproduces the reported memcheck under-estimate.
- The remaining issue appears large-payload/top-entry specific and needs the benchmark repro with `CENO_RPC` exported.
- Because contextual memcheck labels are now in place, the next benchmark run should immediately identify the failing stage and circuit.

Required environment for next session
```bash
export CENO_RPC='<redacted RPC URL>'
```
- The assistant cannot see shell variables unless they are present in the execution environment.
- Verify with:
```bash
if [ -n "${CENO_RPC:-}" ]; then echo 'CENO_RPC is set'; else echo 'CENO_RPC is NOT set'; fi
```

Benchmark repro command to run next
- Workdir: `/home/wusm/rust/ceno-reth-benchmark`
- Use timeout and tee log.
- Keep `--rpc-url "$CENO_RPC"` exactly; do not expand into a persisted command string.

```bash
/usr/bin/time -f 'elapsed %E' timeout 2400s env \
  CENO_GPU_MEM_TRACKING=1 \
  CENO_CONCURRENT_CHIP_PROVING=0 \
  CENO_GPU_ENABLE_WITGEN=1 \
  RUST_MIN_STACK=16777216 \
  RUST_BACKTRACE=1 \
  CYCLE_TRACKER_MAX_DEPTH=4 \
  OUTPUT_PATH=metrics.json \
  CENO_GPU_CACHE_LEVEL=0 \
  RUSTFLAGS='-C target-feature=+avx2' \
  JEMALLOC_SYS_WITH_MALLOC_CONF='retain:true,metadata_thp:always,thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1' \
  RUST_LOG=debug \
  cargo run --features jemalloc --features metrics --features perf-metrics --features gpu --bin ceno-reth-benchmark-bin -- \
    --block-number 23587691 \
    --rpc-url "$CENO_RPC" \
    --cache-dir block_data \
    --mode prove-app \
    --app-proofs ./app_proof.bitcode \
    --shard-id 0 \
    --chain-id 1 \
  2>&1 | tee /tmp/ceno-reth-benchmark-memcheck.log
```

After benchmark fails or completes
1. Extract memcheck failure context:
```bash
rg -n "under-estimate|over-estimate|\\[memcheck\\].*diff=-" /tmp/ceno-reth-benchmark-memcheck.log | tail -120
```
2. The failing line should now include a label like:
   - `build_main_witness[<circuit>]`
   - `build_tower_witness_gpu[<circuit>]`
   - `prove_tower_relation_gpu[<circuit>]`
   - `replay_gpu_witness_from_raw[<circuit>]`
3. Patch only the relevant estimator in `/home/wusm/rust/ceno`.
4. Re-run lightweight Ceno check first:
```bash
cargo fmt --check
timeout 300s cargo check --features gpu --package ceno_zkvm --bin e2e
```
5. Then rerun the benchmark command above.

Security hygiene
- If a concrete RPC URL accidentally appears in any local log, scrub it immediately:
```bash
for f in /tmp/ceno-reth-benchmark-memcheck.log /home/wusm/rust/ceno-reth-benchmark/*.txt /home/wusm/rust/ceno-reth-benchmark/*.log; do
  [ -f "$f" ] || continue
  perl -0pi -e 's#https://eth-mainnet\\.g\\.alchemy\\.com/v2/[^\\s\\x27\\"]+#\\$CENO_RPC#g' "$f"
done
```
- Verify no RPC string remains:
```bash
rg -n 'alchemy|eth-mainnet\.g\.alchemy' /tmp/ceno-reth-benchmark-memcheck.log /home/wusm/rust/ceno-reth-benchmark -g '*.txt' -g '*.log' -g '*.md' -g '*.json' 2>/dev/null || true
```

## Architecture refresher: compact GPU witness / memory-estimator terminology

This section is intended for a fresh session before touching estimators or compact witness code.

Core terminology
- `occupied rows` / `actual rows`:
  - Real number of rows with data for a chip or replay plan.
  - Usually `input.num_instances() << rotation_vars` for normal chip inputs.
  - For replayed GPU witgen, prefer replay-plan-specific real rows when available.
- `logical domain` / `full domain`:
  - Power-of-two domain implied by `num_vars`.
  - Some protocols/verifier semantics still reason over this domain.
  - Prover storage should avoid allocating it when compact storage is sufficient.
- `compact witness`:
  - Device/host storage sized by occupied rows, not full logical domain.
  - This is the intended design for the GPU witgen/prover path.
- `materialized output`:
  - GKR layer output MLE that is actually allocated during `build_main_witness`.
  - `EvalExpression::Single` and `EvalExpression::Linear` materialize; `Zero` does not.
- `final/output GKR layer`:
  - `gkr_circuit.layers[0]` because circuit layers are ordered output-to-input.
  - The `output_mask` is applied only to this final/output layer during tower witness build.
- `internal GKR layers`:
  - Any layer after index 0 in `gkr_circuit.layers`.
  - These do not receive the final tower `output_mask`; all non-zero outputs are materialized.
- `replay path`:
  - GPU witgen can replay raw records into device-backed witness matrices just-in-time.
  - Large replay-heavy chips currently include `Ecall_Keccak` and `ShardRamCircuit`.
- `stage split`:
  - Large replay chips materialize witness multiple times for separate stages to reduce peak VRAM.
  - Estimator must model stage-local peaks, not sum all stages as simultaneously live.

Important module map
- `ceno_zkvm/src/scheme/gpu/memory.rs`
  - Central GPU memory estimator and memcheck assertion logic.
  - Key functions:
    - `estimate_chip_proof_memory`
    - `estimate_trace_bytes`
    - `estimate_main_witness_bytes`
    - `estimate_tower_stage_components`
    - `estimate_main_constraints_bytes`
    - `estimate_replay_materialization_bytes_for_plan`
    - `check_gpu_mem_estimation_with_context`
- `ceno_zkvm/src/scheme/utils.rs`
  - Builds main GKR witness through `build_main_witness` / `gkr_witness`.
  - Owns output materialization mask logic:
    - `tower_output_count`
    - `build_output_materialization_mask`
    - `first_layer_output_group_stage_masks`
  - Critical design point:
    - `output_mask` is applied only to final/output GKR layer.
- `ceno_zkvm/src/scheme/prover.rs`
  - Sequential per-chip GPU proving flow and replay stage splitting.
  - Important stages:
    - replay raw GPU witness
    - build main witness
    - build tower witness
    - prove tower
    - replay again for ECC/main constraints if needed
- `ceno_zkvm/src/scheme/gpu/mod.rs`
  - GPU prover trait implementations and shared helpers.
  - Includes trait-level memchecks for tower/main/ecc/replay helper paths.
- `../ceno-gpu/cuda_hal/src/common/tower/*`
  - GPU tower witness/proof host-side implementation.
- `../ceno-gpu/cpp/common/tower.cuh` and kernel files under `../ceno-gpu/cpp/*/kernels/tower.cu`
  - CUDA tower kernels and compact split logic.
- `../ceno-gpu/cuda_hal/src/common/sumcheck/generic_v2.rs`
  - Rust host-side V2 sumcheck setup.
- `../ceno-gpu/cpp/common/sumcheck/generic_v2.cuh`
  - CUDA V2 sumcheck logic.

Current compact witness design assumptions
- Whole flow target:
  - commit
  - tower prove
  - main prove
  - rotation prove
  - ECC prove
  - batch opening
  - should operate on compact witness storage wherever prover-side full-domain padding is not semantically required.
- Round-0 original inputs:
  - Use direct/native order over real occupied data.
  - Do not invent tower-specific order separate from PCS.
- Later folded rounds:
  - Use normal in-place/folded buffer semantics.
  - Do not call this a replay buffer; call it `in-place buffer`.
- Compact even/odd tails:
  - Avoid branch-per-element loops for odd real lengths.
  - Decide odd/even outside the loop and process the leftover tail separately.
- Cloning policy:
  - Avoid full `clone` / `to_vec` on large witness buffers unless it is intentionally debug-only.

Main witness memory-estimator design
- Old broken model:
  - `tower_output_count(composed_cs) * rows * sizeof(BB31Ext)`.
  - This only counts final tower outputs.
- Correct current model:
  - Count final/output layer materialized tower outputs under the output mask.
  - Plus count all internal layer non-zero outputs because internal layers are not masked.
  - Multiply by real output rows, normally `input.witness.first().evaluations_len()`.
- Why this matters:
  - Multi-layer GKR circuits like `Ecall_Keccak` materialize internal outputs during `build_main_witness`.
  - Single-layer circuits like `ShardRamCircuit_main` usually do not have the same missing-internal-output issue.

Replay / trace estimator design
- Normal non-replay path:
  - Extracted witness and structural MLEs can stay resident across chip proof.
  - Stage peak is resident trace plus max temporary stage.
- Replay-heavy path (`Ecall_Keccak`, `ShardRamCircuit`):
  - Estimate replay materialization from replay plan real rows, not full logical domain.
  - Replay witness is materialized for tower stages, then cleared before tower prove/main stages as designed.
  - Estimator should use max of replay/build/prove/ecc/main stage peaks plus safety margin.
- Structural witness caveat:
  - If structural RMM already has device backing, transport may be view-only and estimate zero new bytes.
  - If not device-backed, estimate structural upload by real rows when possible.

Tower estimator design
- Build stage estimate includes:
  - CUDA tower build temporary allocations from `estimate_build_tower_memory`.
  - Compact product split buffers.
  - Compact logup split buffers.
- Prove stage estimate separates:
  - live tower input buffers
  - local create-proof temporary allocations
- For logup:
  - If table lookup has numerator, numerator buffers are real compact buffers.
  - If no numerator, ones/default numerator should not allocate a full domain buffer.

Scheduler / memcheck relationship
- Sequential + `CENO_GPU_MEM_TRACKING=1`:
  - Runs memcheck assertions stage-by-stage.
  - This is the best mode for estimator debugging.
- Concurrent + mem tracking disabled:
  - Uses estimator for booking/scheduling VRAM, not direct memcheck assertions.
- Booking can include extra safety margin for replay-heavy chips in concurrent mode.
- A stage-local memcheck pass does not automatically prove concurrent booking is optimal, but it strongly validates the per-stage estimator.

Current known caveats
- Lightweight `keccak_syscall` memchecks pass after current estimator fixes.
- The lightweight run still hits a known verifier assertion later at:
  - `gkr_iop/src/gkr/layer/zerocheck_layer.rs:306`
- The remaining reported under-estimate is only known from the top-entry benchmark payload and must be reproduced with `CENO_RPC` exported.
- Do not guess the failing estimator from the old generic label; use the new contextual memcheck label first.

Recommended investigation discipline
1. Reproduce with sequential mem tracking first:
   - `CENO_GPU_MEM_TRACKING=1`
   - `CENO_CONCURRENT_CHIP_PROVING=0`
2. Read the exact contextual label:
   - `build_main_witness[...]`
   - `build_tower_witness_gpu[...]`
   - `prove_tower_relation_gpu[...]`
   - `replay_gpu_witness_from_raw[...]`
3. Patch only the estimator for that stage/circuit class.
4. Validate in `/home/wusm/rust/ceno` first:
   - `cargo fmt --check`
   - `timeout 300s cargo check --features gpu --package ceno_zkvm --bin e2e`
5. Then rerun the top-entry benchmark.
