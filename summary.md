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

## Restore Prompt For Next Session

Use this prompt in the next Codex session:

```text
We are continuing GPU batched main sumcheck optimization. Please read `/home/wusm/rust/ceno/summary.md` first. Workspaces are `/home/wusm/rust/ceno`, `/home/wusm/rust/ceno-gpu`, and `/home/wusm/rust/ceno-reth-benchmark`. The latest committed state should include direct MLE layout for `prove_batched_main_constraints` in ceno and active-MLE V2 fold worklist optimization in ceno-gpu. Do not touch the unrelated local `ceno_zkvm/src/structs.rs` change unless explicitly requested. Use the `reth-gpu-sanity` skill for downstream validation, never print `$CENO_RPC`, and restore benchmark validation-only edits after running sanity. Next focus: compare remote benchmark performance and, if needed, optimize batched expression/common-term factoring.
```
