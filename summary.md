# GPU Batched Main Sumcheck Optimization Handoff

## Current Goal

Optimize the new `prove_batched_main_constraints` path against the previous per-chip main sumcheck baseline. The expected model is that batching should reduce sumcheck kernel invocations and improve GPU utilization, but the current batched path introduced extra overhead from heterogeneous MLE sizes and non-direct layout handling.

## Root-Cause Findings

- Batched main uses one global `max_num_variables`, while chips have heterogeneous `num_vars`.
- The V2 fold kernel previously launched as `num_unique_mles * stride` each round, even when many MLEs were already inactive for that `current_num_vars`.
- This caused substantial overlaunch in large remote runs. Earlier shard-0 diagnostics showed global batched fold work could be about `39x` the per-chip ideal thread work for the fold phase.
- The batched main path also used non-direct MLE layout (`original_layout_flag = 0`) while the older wrapper path uses direct/original layout semantics.
- The remaining larger bottleneck is likely expression-side work/common factoring: the batched main path still passes `None` for common-term factoring and uses full monomial terms.

## Implemented Changes

### ceno

- File: `ceno_zkvm/src/scheme/gpu/mod.rs`
- Change: `prove_batched_main_constraints` now calls `prove_generic_sumcheck_gpu_v2` with direct/original MLE layout flag `1`.
- Reason: avoid unnecessary layout conversion/indirection for batched main MLE inputs.

### ceno-gpu

- File: `cuda_hal/src/common/sumcheck/generic_v2.rs`
- Change: added per-round active-MLE worklist generation based on `host_num_vars_curr == current_num_vars`.
- Change: V2 fold launch size is now `active_mle_indices.len() * stride`, not `num_unique_mles * stride`.
- Change: both host-challenge and GPU-transcript challenge fold paths use the active worklist.

- File: `cpp/common/sumcheck/generic_v2.cuh`
- Change: common V2 fold device routine now receives `active_mle_indices` and `num_active_mles`, maps active index to actual MLE index, and bounds on active work only.

- Files:
  - `cpp/bb31/kernels/sumcheck_generic_v2.cu`
  - `cpp/gl64/kernels/sumcheck_generic_v2.cu`
- Change: BB31 and GL64 kernel wrappers forward active-MLE worklist arguments.

## Validation Completed

Commands that passed:

```bash
cargo fmt --manifest-path ../ceno-gpu/cuda_hal/Cargo.toml --all
cargo fmt
cargo check -p ceno_zkvm --features gpu --config 'patch."https://github.com/scroll-tech/ceno-gpu-mock.git".cuda_hal.path="../ceno-gpu/cuda_hal"'
```

Downstream local sanity passed through `../ceno-reth-benchmark` using local `ceno` and `ceno-gpu` path patches, WITGEN=1, shard 0, block `23587691`, `--chain-id 1`, and the temporary local max-cell validation knob. Benchmark validation edits were restored afterward.

Latest sanity log:

```text
../ceno-reth-benchmark/sanity_23587691_shard0_witgen1_direct_active_fold_20260501_140101.log
```

Latest metrics:

```text
../ceno-reth-benchmark/metrics_23587691_shard0_witgen1_direct_active_fold_20260501_140101.json
```

Success markers:

```text
verifying shard proof: expected_shard_id=0, proof_shard_id=0, chip_groups=61
single shard segment verified without full-trace continuation checks
```

## Local Timing Comparison

Compared against previous local sanity log:

```text
../ceno-reth-benchmark/sanity_23587691_shard0_witgen1_batch_alloc_clamp_20260501_133037.log
```

| Span | Previous | Latest | Delta |
| --- | ---: | ---: | ---: |
| `reth-block` | `76.2s` | `75.0s` | `-1.2s` |
| `app.prove` | `75.7s` | `74.5s` | `-1.2s` |
| `app_prove.inner` | `74.8s` | `73.6s` | `-1.2s` |
| `create_proof_of_shard` | `71.5s` | `70.4s` | `-1.1s` |
| `commit_traces` | `12.2s` | `12.0s` | `-0.2s` |
| `prove_batched_main_constraints` | `14.7s` | `14.6s` | `-0.1s` |
| `pcs_opening` | `2.59s` | `2.51s` | `-0.08s` |
| `app.verify` | `312ms` | `292ms` | `-20ms` |

The local payload is small, so fold overlaunch reduction is not expected to dominate locally. The remote payload should show a clearer benefit because heterogeneous large-MLE fold overlaunch scales with global `max_num_variables`.

## Current Git State Notes

- `ceno` intended commit includes:
  - `ceno_zkvm/src/scheme/gpu/mod.rs`
  - `summary.md`
- `ceno-gpu` intended commit includes:
  - `cuda_hal/src/common/sumcheck/generic_v2.rs`
  - `cpp/common/sumcheck/generic_v2.cuh`
  - `cpp/bb31/kernels/sumcheck_generic_v2.cu`
  - `cpp/gl64/kernels/sumcheck_generic_v2.cu`
- Pre-existing unrelated local change in `ceno_zkvm/src/structs.rs` was intentionally not included.
- `../ceno-reth-benchmark/Cargo.lock` and `crates/host-bench/src/lib.rs` were restored after sanity validation.

## Recommended Next Steps

1. Run or inspect the remote benchmark for this commit pair and compare `prove_batched_main_constraints` against the latest feature run.
2. If batched main is still slower than per-chip baseline, prioritize expression common-term factoring for the batched path.
3. Consider bucketing by `num_var_with_rotation` only if one global sumcheck cannot recover enough performance with active folding and common factoring.
4. Keep V2 active-worklist optimization unless another V2 caller shows regression; it should reduce wasted fold work for any heterogeneous MLE set.

## Local Baseline Vs Current Harness

Purpose: keep a smaller local comparison target for future optimization before waiting for remote CI. Both runs use block `23587691`, `--shard-id 0`, WITGEN=1, `--chain-id 1`, local max-cell validation knob `(1 << 30) * 6 / 4 / 2`, and shared target dir `/home/wusm/rust/ceno-reth-benchmark/target`.

### Pinned Versions

Baseline:

- `ceno-reth-benchmark`: `65a757522a7e`
- `ceno`: `9936d96ed51f`
- `ceno-gpu`: `911741992d4a`
- Worktrees:
  - `/home/wusm/rust/ceno-reth-benchmark-baseline-65a757`
  - `/home/wusm/rust/ceno-baseline-9936d96`
  - `/home/wusm/rust/ceno-gpu-baseline-911741`

Current:

- `ceno-reth-benchmark`: `5da5ed70f2dd`
- `ceno`: `be5a6f57cdc7`
- `ceno-gpu`: `f884a4728b43`
- Worktrees:
  - `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed`
  - `/home/wusm/rust/ceno`
  - `/home/wusm/rust/ceno-gpu`

The isolated benchmark worktrees link these existing inputs:

- `block_data -> ../ceno-reth-benchmark/block_data`
- `app_proof.bitcode -> ../ceno-reth-benchmark/app_proof.bitcode`
- `bin/ceno-client-eth/target -> ../../../ceno-reth-benchmark/bin/ceno-client-eth/target`

### Latest Local Logs

Baseline:

```text
/home/wusm/rust/ceno-reth-benchmark-baseline-65a757/sanity_23587691_shard0_witgen1_baseline_9936d96_911741_20260501_143419.log
```

Current:

```text
/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_current_be5a6f57_f884a472_20260501_143703.log
```

Both passed single-shard verification:

```text
single shard segment verified without full-trace continuation checks
```

### Local Comparison

| Span | Baseline | Current | Delta |
| --- | ---: | ---: | ---: |
| `reth-block` | `70.7s` | `74.8s` | `+4.1s` |
| `app.prove` | `70.2s` | `74.3s` | `+4.1s` |
| `app_prove.inner` | `69.4s` | `73.4s` | `+4.0s` |
| `create_proof_of_shard` | `66.2s` | `70.2s` | `+4.0s` |
| `commit_traces` | `11.7s` | `11.7s` | `0.0s` |
| main sumcheck | `10.788s` total per-chip `prove_main_constraints` | `14.5s` `prove_batched_main_constraints` | `+3.712s` |
| `pcs_opening` | `2.40s` | `2.47s` | `+0.07s` |
| `app.verify` | `304ms` | `294ms` | `-10ms` |

Interpretation:

- The smaller local block still shows current batched main slower than the original per-chip baseline by about `4.1s` E2E.
- The gap is concentrated in main sumcheck: per-chip baseline sums to `10.788s`, current batched main is `14.5s`.
- `commit_traces` is unchanged, so this local harness is useful for validating main-sumcheck optimization direction.
- This is not contradictory with the latest remote improvement: the active-MLE fold optimization improved the feature branch versus the previous feature branch, but current batched main has not yet beaten the original per-chip baseline.
- Next optimization should target batched common-term factoring/expression evaluation overhead, not PCS or trace commit.

### Local Harness Notes

- The first baseline attempt failed due to missing ceno-gpu submodule; fixed with `git -C /home/wusm/rust/ceno-gpu-baseline-911741 submodule update --init --recursive`.
- A later attempt hit disk exhaustion; disposable `/home/wusm/rust/ceno/target` and partial baseline worktree `target` were removed to free space.
- Shared target reuse between benchmark SHAs can reuse incompatible path-crate metadata. If current compile fails with stale `openvm-client-executor` symbols, clean affected packages with:

```bash
cd /home/wusm/rust/ceno-reth-benchmark-current-5da5ed
CARGO_TARGET_DIR=/home/wusm/rust/ceno-reth-benchmark/target cargo clean -p openvm-client-executor -p openvm-reth-benchmark -p ceno-reth-benchmark-bin
```

- After validation, `Cargo.lock` and `crates/host-bench/src/lib.rs` were restored in both isolated benchmark worktrees.

### 2026-05-01 Batched Main Sumcheck Optimization Notes

- `prove_batched_main_constraints` now builds one global `CommonTermPlan` and keeps the verifier-facing shape as one global sumcheck/proof/transcript.
- The best validated default local result remains the common-factored grouped path:
  - log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_bucketed_default_off_20260501_152804.log`
  - metrics: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/metrics_23587691_shard0_witgen1_bucketed_default_off_20260501_152804.json`
  - `reth-block`: `76.0s`
  - `prove_batched_main_constraints`: `14.4s`
- A prototype compact-domain eval-bucket path was tried and removed.
  - It preserved one global sumcheck by accumulating bucket round-polynomial evals on device before transcript squeeze.
  - Validation passed, but performance regressed:
    - log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_bucketed_eval_20260501_152343.log`
    - `reth-block`: `75.5s`
    - `prove_batched_main_constraints`: `15.1s`
  - The environment-gated implementation was deleted rather than kept as a disabled path.
- A group-domain gate in the common-factor CUDA evaluator was tried and removed.
  - It precomputed each common group domain and skipped inactive duplicated lanes before loading common factors.
  - Validation passed, but performance did not improve:
    - log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_group_domain_gate_20260501_162629.log`
    - `reth-block`: `76.1s`
    - `prove_batched_main_constraints`: `14.6s`
  - The CUDA changes were reverted rather than kept because this does not beat the current common-factored path or the original per-chip baseline.
- A host-side domain-bucketed global sumcheck prototype was tried and removed.
  - It kept one global proof/transcript and skipped smaller-domain buckets until their active rounds, but it initialized/ran separate V2 prover states per bucket and accumulated round evals on CPU.
  - Validation passed, but performance regressed:
    - log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_bucketed_global_skip_20260501_170025.log`
    - metrics: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/metrics_23587691_shard0_witgen1_bucketed_global_skip_20260501_170025.json`
    - `reth-block`: `74.8s`
    - `prove_batched_main_constraints`: `15.0s`
  - The CUDA bucket API and Ceno bucket wiring were removed. This confirms the next direction should not be multiple host-managed prover states; any bucket/worklist optimization must be one fused CUDA shape with persistent metadata and one global eval buffer.
- Next viable optimization should not split proofs. It should fuse work inside the one global sumcheck:
  - precompute/upload persistent bucket/worklist metadata instead of per-round small H2D allocations;
  - move toward one CUDA worklist kernel mapping `global_tid -> (work_item, local_tid)`;
  - accumulate each work item into the same global round eval vector before the single transcript squeeze;
  - use thresholds from measured bucket work so late/small rounds stay on the existing grouped common-term kernel.

### Proposed Next Direction: Staggered-Domain Global Sumcheck

Protocol idea:

- Treat each chip/domain bucket as its own lower-dimensional zero-claim sumcheck, but keep one global transcript and one aggregated round polynomial.
- For global rounds where `current_num_vars > bucket_num_vars`, the bucket is not yet active and contributes nothing to the running claim.
- When `current_num_vars == bucket_num_vars`, activate that bucket by adding its initial claim to the verifier/prover running claim.
- For main constraints, each activated bucket initial claim is zero, so activation is protocol-cheap and does not need extra proof data unless future nonzero buckets are introduced.
- After activation, the bucket participates in all subsequent rounds and is folded with the same global transcript challenge.

Correctness distinction:

- Skipping arbitrary individual lower-domain monomial terms is invalid because each term may have a nonzero constant contribution and cancellation only holds across the complete zero-claim expression.
- Skipping a complete lower-domain zero-claim bucket before activation is valid because that sub-sumcheck has not been introduced into the global running claim yet.

Implementation target:

- Do not revive the removed host-side bucket prototype.
- Build one fused CUDA prover state with persistent domain-bucket metadata:
  - buckets sorted by `bucket_num_vars`;
  - per-bucket MLE ranges, term ranges, common-term ranges;
  - activation offsets by global round/domain;
  - one global round eval buffer and one GPU transcript.
- Per round:
  - activate newly eligible zero-claim buckets;
  - eval kernel processes only active buckets/work items;
  - inactive smaller buckets are not traversed;
  - fold kernel folds active MLEs, reusing the existing active-MLE worklist idea.
- Verifier/proof shape should remain one global main proof if zero activations are implicit. If nonzero activations are later needed, the proof/verifier must include or derive those claims at activation rounds.

Expected benefit:

- Avoids global-round eval traversal over lower-domain chips before their active domain starts.
- Attacks the real bottleneck: heterogeneous-domain expression evaluation, not fold.
- Keeps the long-term CUDA shape: one transcript, one eval buffer, persistent worklist metadata, no per-round host orchestration.

## Restore Prompt For Next Session

Use this prompt in the next Codex session:

```text
We are continuing GPU batched main sumcheck optimization. Please read `/home/wusm/rust/ceno/summary.md` first. Workspaces are `/home/wusm/rust/ceno`, `/home/wusm/rust/ceno-gpu`, and `/home/wusm/rust/ceno-reth-benchmark`. The latest committed state includes direct MLE layout for `prove_batched_main_constraints` in ceno (`be5a6f57`) and active-MLE V2 fold worklist optimization in ceno-gpu (`f884a472`). Do not touch the unrelated local `ceno_zkvm/src/structs.rs` change unless explicitly requested. Use the `reth-gpu-sanity` skill for downstream validation, never print `$CENO_RPC`, and restore benchmark validation-only edits after running sanity. For quick local performance checks, use the baseline/current harness documented in `summary.md`: baseline worktrees are `/home/wusm/rust/ceno-reth-benchmark-baseline-65a757`, `/home/wusm/rust/ceno-baseline-9936d96`, `/home/wusm/rust/ceno-gpu-baseline-911741`; current worktree is `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed` with local `/home/wusm/rust/ceno` and `/home/wusm/rust/ceno-gpu`. Latest local result: current is still about `+4.1s` slower E2E than original per-chip baseline on block `23587691` shard 0, with main sumcheck `14.5s` versus per-chip sum `10.788s`. Important failed paths already removed: `CENO_GPU_SUMCHECK_BUCKET_EVAL`, group-domain gate, and host-side bucketed global skip. Next focus: design and implement the staggered-domain global sumcheck plan from `summary.md`: activate complete zero-claim chip/domain buckets only when `current_num_vars == bucket_num_vars`, keep one global transcript/proof, and implement it as one fused CUDA prover state with persistent bucket/worklist metadata, not multiple host-managed prover states.
```

### 2026-05-03 GPU-Feature Correction And Kernel Results

Important correction: several older local sanity numbers in this file were produced without enabling the benchmark `gpu` feature. Those runs can still pass verification, but they do not exercise `ceno_zkvm/src/scheme/gpu` or local `ceno-gpu` changes. Treat the older `70s/14s` local comparison as stale for GPU-prover performance. Current GPU sanity must use `--features 'jemalloc,gpu'` and confirm `CUDA Backend Enabled` appears in the log.

Committed experiment state:

- `ceno`: `27ed8650` (`Experiment staggered batched main sumcheck prover`)
- `ceno-gpu`: `14649f95` (`Add staggered-domain sumcheck V2 entry`)

Current code shape:

- `prove_batched_main_constraints` builds one global `CommonTermPlan` for the batched main path.
- Common groups are sorted by descending `num_var_with_rotation`.
- `active_counts_by_num_vars[current_num_vars]` limits the eval kernel to the active common-group prefix, so smaller-domain inactive groups are not traversed.
- CUDA V2 eval has a `staggered_domain` flag; the batch-main entry currently passes `true`.
- Kernel selection remains the default/auto policy: use `sumcheck_round_perterm` only when `active_num_terms >= 256` and `poly_len <= MIN_LEN_FOR_WARP_REDUCTION`; otherwise use `sumcheck_round`.
- The prover still emits one global sumcheck proof/transcript with `max_num_vars` rounds.
- Verifier is not yet updated for staggered activation, so the GPU-feature staggered run is expected to fail with a main-claim mismatch.

Correct GPU-feature baseline/current comparison on block `23587691`, shard 0, WITGEN=1:

- Baseline log: `/home/wusm/rust/ceno-reth-benchmark-baseline-65a757/sanity_23587691_shard0_witgen1_gpu_feature_baseline_20260503_144417.log`
- Current staggered log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_gpu_feature_stagger_20260503_143633.log`
- Baseline per-chip `prove_main_constraints` sum: `0.746s` across `61` chips.
- Current `prove_batched_main_constraints`: `1.14s`.
- Main-sumcheck gap: current is `+0.394s`, about `+53%` slower.
- Baseline `reth-block`: `8.96s`, verified passed.
- Current `reth-block`: `9.11s`, verifier failed as expected with `main constraint claim mismatch`.

Common factoring validation:

- Log: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_common_factored_no_active_prefix_20260503_151018.log`
- Mode: common-group factoring enabled, but staggered active-prefix disabled for this check.
- Result: verified passed.
- `prove_batched_main_constraints`: `5.71s`.
- Conclusion: common-group factoring shape is algebraically correct. The verifier failure comes from staggered active-prefix/protocol mismatch, not common factoring itself.

Kernel selection experiment on current staggered prover shape:

- Auto/default: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_gpu_feature_stagger_20260503_143633.log`
  - `prove_batched_main_constraints`: `1.14s`
- Forced normal kernel: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_kernel_normal_20260503_151308.log`
  - `prove_batched_main_constraints`: `1.35s`
  - Slower; do not force normal.
- Forced per-term for all small rounds: `/home/wusm/rust/ceno-reth-benchmark-current-5da5ed/sanity_23587691_shard0_witgen1_kernel_perterm_20260503_151514.log`
  - `prove_batched_main_constraints`: `1.13s`
  - Slightly faster locally, but within noise. Keep auto/default unless a larger payload confirms this wins.

Next direction:

1. Implement verifier running-claim activation by `current_num_vars` for the staggered single-global-sumcheck protocol.
2. Preserve the current auto kernel selector by default.
3. After verifier support, remeasure on the larger payload and then consider a threshold tweak only if forced per-term consistently wins.
4. The remaining `+53%` gap is not from scanning inactive smaller-domain groups; active prefix already avoids that. Focus next on matching per-chip prover work for active groups: degree sharing overhead, grouped-kernel register/cache behavior, metadata indirection, and common-factor granularity.
