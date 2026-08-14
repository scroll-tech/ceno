# FullTracer + GPU Witness Optimization Plan

Date: 2026-08-14 (Asia/Singapore)

## Summary

Reduce GPU witness write amplification one mechanism at a time. Validate each
experiment against Reth block `23587691`, and build later work only on accepted
commits.

The initial measured baseline remains the reference: 13.67M `StepRecord`s,
1.77 GiB uploaded, approximately 1.87s witness generation, 649ms FullTracer
ingestion, 825ms opcode assignment, and 507ms ordinary GPU witness expansion.

## Experiment and rollback contract

- Run every experiment in a clean worktree branched from the latest accepted
  milestone. Preserve the existing unrelated `ceno-gpu` sumcheck changes.
- Use three interleaved warm control/candidate trials with `GPU_WITGEN=1`,
  `jemalloc,gpu`, lane scheduling, cached block data, and `--chain-id 1`.
- Accept an experiment only when:
  - Median total witness generation improves by at least 2%.
  - Its targeted phase improves by at least 5%.
  - Median application proving time is no more than 1% slower, treating that
    band as measurement noise.
  - Execution produces exactly two shards with stable boundaries and
    instruction counts.
  - Shard-0 proof and verification succeed, followed by one complete two-shard
    proof validation.
  - GPU memory retains at least 1 GiB headroom and no new fallback, allocation,
    or transfer anomaly appears.
- If a candidate regresses:
  - Profile the regression and allow at most two tuning iterations confined to
    the same mechanism.
  - Tune only parameters intrinsic to that experiment, such as block shape,
    tile dimensions, vector width, chunk size, or staging depth.
  - If it still misses the gate, reject it, discard its code branch, and record
    the result in this document.
  - Never merge a failed implementation or base another optimization on it. If
    an already-published commit must be removed, use `git revert`, not history
    rewriting.
- Treat AOT, scheduler, incremental PCS, and stream-count changes as separate
  controlled experiments rather than combining them with kernel changes.

## Implementation milestones

### M0 — Reproducible baseline

Status: measured; milestone record pending.

- Commit this plan as the initial milestone.
- Recalibrate the two-shard execution boundaries because Ceno is now at
  `bb73003f`, newer than the skill's calibrated `9d5f8c1a`.
- Capture `GPU_WITGEN=0/1` timings, per-chip timers, transfer volumes, CUDA
  utilization, allocation peaks, and the hottest kernels.
- Run the AOT configuration as an isolated control; retain it only if it
  independently passes the same gate.

Initial GPU-witgen measurement identity:

- Ceno: `bb73003f7031f5498b6a2b3b177d54b1d9489fd7`.
- ceno-gpu: `996ef2a1` plus pre-existing unrelated sumcheck worktree changes.
- Benchmark measurement base: `db07e103`.
- GPU: NVIDIA GeForce RTX 5070 Ti, 16,303 MiB, compute capability 12.0,
  70 SMs; driver 570.172.08.
- Workload: block `23587691`, cost limit `2684354560`, cache level 1, `h=23`,
  `CENO_CHIP_PROVING_MODE=lanes`, and four lanes.
- Recalibrated execution: 19,184,568 guest instructions, 76,738,276 cycles,
  two shards, boundaries `[4, 54691232, 76738276]`.
- Shard 0: 13,672,807 executed records plus the pending tracer slot;
  `FullTracer` buffer 1,859,501,888 bytes and runtime H2D 1,773.36 MiB.
- Approximate phase timings: 1.87s witness generation, 649ms FullTracer
  ingestion, 825ms opcode assignment, 507ms summed ordinary GPU expansion,
  140ms initial `StepRecord` H2D, and 301ms address sort/dedup.

The existing measurement is evidence for prioritization, not a completed M0
gate: the required interleaved three-run controls, isolated AOT control, full
profiler inventory, and complete two-shard proof validation must still be
recorded below before M0 is accepted.

### M1 — Eliminate redundant output initialization

Status: pending.

- Prove which witness columns are completely overwritten by expansion kernels.
- Remove or narrow device memset operations only for those ranges.
- Keep explicit initialization for sparse or conditionally written columns.
- Measure memset time, total bytes written, witness time, and application proof
  time.

### M2 — Coalesced column-oriented expansion

Status: pending.

- Assign each CUDA block exclusive ownership of a `(chip, record chunk, column
  group)` output tile.
- Load compact input records once, decode shared fields into registers/shared
  memory, and have warp lanes write consecutive rows of one column.
- Use aligned vector stores where column alignment permits.
- For fixed expansion multiplicity, derive output offsets algebraically.
- For variable multiplicity, use a two-pass count → exclusive scan → scatter
  design. Do not use per-row global atomics or allow multiple blocks to write
  the same output cache line.
- Compare effective write bandwidth, store efficiency, occupancy, atomic
  traffic, and expansion time.

### M3 — Remove cross-thread address and local-slot contention

Status: pending.

- Replace global address-allocation atomics with per-block counts plus
  deterministic scanned offsets.
- Give each block or warp private scratch ranges for local slots, then compact
  once into final columns.
- Keep address and local-slot changes as separate experiments so either can be
  rejected independently.

### M4 — Lookup accumulation

Status: pending.

- Accumulate lookup counts in warp/block-local tables, merge once per key range,
  and defer global updates.
- Test an on-device merge separately from atomic reduction.
- Preserve deterministic lookup ordering and CPU/GPU witness equivalence.

### M5 — Bounded asynchronous pipeline

Status: pending.

- Introduce reusable pinned staging buffers and a fixed two- or three-stage
  upload/expand/write pipeline.
- Bound streams, allocations, and in-flight chunks; do not accept higher
  concurrency that only moves the bottleneck or reduces memory headroom.
- Measure overlap among record upload, expansion kernels, lookup processing, and
  downstream proving.

### M6 — FullTracer compact SoA streaming

Status: pending.

- Replace the 1.77 GiB monolithic `StepRecord` upload with a versioned
  device-facing SoA/POD representation containing only fields consumed by GPU
  witness generation.
- Chunk records at deterministic shard/chip boundaries and double-buffer upload
  with expansion.
- Preserve original record ordering, shard boundaries, CPU fallback behavior,
  and existing witness semantics.
- Evaluate incremental address sorting only after compact streaming is
  independently accepted.

Each rejected milestone leaves the next experiment rebased on the last accepted
milestone. Any later experiment that depended on rejected behavior must be
redesigned against that accepted baseline before testing.

## Milestone record template

After every milestone, append a record containing:

- Status: accepted, tuned, or rejected/rolled back.
- Hypothesis and isolated change.
- Exact Ceno, ceno-gpu, and benchmark commit IDs.
- Build features, environment, shard boundaries, and commands.
- Three-run baseline/candidate timing table.
- Correctness, verification, memory, and profiler results.
- Tuning attempts and final decision.
- Resulting commit IDs and the parent for the next experiment.

## Commit policy

- Initial plan: `docs(gpu): add FullTracer witgen optimization plan`.
- Accepted implementation in its owning repository:
  `perf(witgen): <mechanism>`.
- Accepted milestone record: `docs(gpu): record <mechanism> milestone`.
- Rejected experiment: no code commit is merged; commit only the evidence with
  `docs(gpu): record rejected <mechanism> experiment`.
- Cross-repository changes receive separate owning-repository commits, with the
  final Ceno documentation commit referencing all exact hashes.

## Tests and assumptions

- Run focused CUDA/CPU witness-equivalence tests before the Reth benchmark.
- Confirm logs contain `CUDA Backend Enabled` and do not contain fallback, OOM,
  kernel, proof, or verification errors.
- Use block `23587691`, cost limit `2684354560`, cache level 1, `h=23`,
  `CENO_CHIP_PROVING_MODE=lanes`, and `LANES=4`.
- Use cached inputs and `--chain-id 1`; never print or pass a raw RPC URL.
- Revert benchmark-only `Cargo.lock` changes after validation.
- No public proof or AIR semantics change is intended. New layouts remain
  internal GPU witness interfaces and retain a CPU reference path.
- The unanswered performance-gate preference defaults to the noise-aware
  acceptance thresholds above.

