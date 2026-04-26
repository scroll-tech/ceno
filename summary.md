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
