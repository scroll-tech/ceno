# FullTracer / compact GPU ingress status

Updated: 2026-08-17 (Asia/Singapore)

## Goal and repository anchors

The production path is `GpuReplayTracer`; `FullTracer` remains the selectable
legacy/debug correctness reference. The intended optimization is deterministic
typed-SoA routing followed by ranged asynchronous GPU ingress, while preserving
VM semantics, shard order, proof formats, AIR, and public APIs.

- ceno base: `785319e463c1d6226046fc30d5ce103f41cb3cb8`
- ceno-gpu: `4f2f2100f14c6c4834734fdb824373def08338ee`
- ceno-reth-benchmark: `06461978a42be749bdb6477722f864c819fe9e07`
- local campaign checkpoint (not committed):
  `.codex-campaigns/fulltracer-gpu-ingress.md`

## Implemented: I001 acceptance observability

The current commit contains validation and memory observability only; it does
not yet contain the typed-SoA or pinned-ingress optimization.

- Added private `validation_manifest` support, enabled only by
  `CENO_VALIDATION_MANIFEST_DIR`.
- Captures after all shard witness data and `PublicValues::shard_rw_sum` are
  finalized, without changing `FullTracer`.
- Produces deterministic per-shard canonical fingerprints for public values,
  finalized lookup multiplicities, sorted accessed addresses, chip-sorted
  witness matrices, ordered ShardRAM matrices, continuation matrices, and final
  continuation state.
- Handles both host row-major matrices and GPU col-major device backing,
  including compact-prefix backing with canonical padded rows.
- Keeps accessed-address D2H enabled only for validation runs. The normal GPU
  path receives an invocation-scoped `false` gate and retains its skip behavior.
- Adds synchronized post-witgen `cudaMemGetInfo` reporting and distinguishes it
  from the existing later GPU-pool restoration check.
- When validation and memory reporting are disabled, no hashing, matrix D2H,
  CUDA synchronization, or filesystem work is performed. The original native
  AOT preflight/executor was not modified.

Owned source paths:

- `ceno_zkvm/src/validation_manifest.rs`
- `ceno_zkvm/src/lib.rs`
- `ceno_zkvm/src/e2e.rs`
- `ceno_zkvm/src/instructions/gpu/cache.rs`

## Verification completed

Evaluator verdict for the I001 source refinement: PASS.

- Focused compact-prefix/non-power-of-two canonical equality test: PASS 1/1.
- Focused disabled-gate/no-validation-work test: PASS 1/1.
- CPU validation-manifest suite: PASS 6/6 before the final additions.
- GPU validation-manifest suite: PASS 8/8.
- `cargo check -p ceno_zkvm --features gpu`: PASS in 5m37s.
- Exact ADDI CUDA witness equality: PASS 1/1 with real device-0
  H2D/kernel/D2H execution.
- Exact ADD CUDA witness equality: PASS 1/1 with real device-0
  H2D/kernel/D2H execution.
- Formatting, scoped diff, protected hashes, repository revisions, and local
  `../ceno-gpu/cuda_hal` resolution checks passed.

Detailed local evidence is under:

- `.codex-campaigns/artifacts/fulltracer-gpu-ingress/I001/iteration-2/`
- `.codex-campaigns/artifacts/fulltracer-gpu-ingress/I001/gpu-execution-preflight/`

## Runtime acceptance blocker

The first compact shard-0 cached-block manifest smoke did not start the
benchmark. During final release ThinLTO, the kernel globally OOM-killed rustc:

- timestamp: `2026-08-17T14:55:00+08:00`
- process: rustc PID 920942, worker `lto cgu.12.rcgu`
- anonymous RSS: 17,380,608 KiB
- Cargo result: SIGKILL / exit 101 at 14:55:01
- host: about 67.3 GB RAM, no swap

The timestamped system journal proves global host OOM; this was not a ceno
source error, CUDA error, cgroup hard-limit failure, or timeout. Legacy was not
started, no manifest was emitted, and the prior release binary is stale because
it predates I001.

Diagnosis:
`.codex-campaigns/artifacts/fulltracer-gpu-ingress/I001/shard0-manifest-smoke/sigkill-diagnosis.md`

## Required resume action

The campaign is paused before the single conditional retry. On resume, read the
checkpoint first and re-evaluate the live gate; the interrupted attempt did not
consume the retry.

Retry the identical compact-first shard-0 smoke with the sole addition
`CARGO_BUILD_JOBS=1` only when all checkpoint D026 gates pass, notably:

- `MemAvailable >= 32 GiB`;
- session `memory.current <= 32 GiB`;
- global and session memory PSI `avg10 == 0.00`;
- no competing build/benchmark process;
- at least 14,440,271,872 disk bytes and 1 GiB free VRAM;
- protected revisions, hashes, statuses, lockfile, and path resolution match.

Never perform a second retry. Launch legacy only after compact fully passes and
a fresh resource gate passes. The smoke must then compare the compact and
legacy shard-0 manifests byte-for-byte and confirm synchronized post-witgen
free VRAM. Repeated determinism, shard 1/two-shard equality, pool restoration,
performance medians, application proofs, and recursion proof remain pending.

## Performance status and mandatory trim gate

No performance gain has been demonstrated yet. Existing single warm shard-0
samples (not acceptance medians) show:

- wall-clock: compact 11.00s vs legacy 10.51s, about 4.7% slower;
- witness: compact 2.810s vs legacy 1.999s, about 40.6% slower;
- replay/position: compact 822ms vs legacy 498ms;
- RSS: compact about 5.00 GB vs legacy about 6.18 GB, about 19% lower.

After I001 runtime acceptance, P001 must profile and temporarily trim at most
three evidence-ranked cost centers before I002 starts. Each trim removes one
cost, uses an interleaved three-pair control protocol, and is fully reverted.
At least one trim must demonstrate more than 5% improvement in its target span,
at least 2% total shard-0 witness improvement, and no more than 1% regression
in the unchanged original AOT preflight. If none passes, I002 becomes
`replan_required`; do not implement typed SoA based only on assumed benefit.

## Worktree exclusions

Do not include or overwrite the pre-existing `ceno-gpu.md`, secp256k1 add/double
edits, ceno-gpu sumcheck edits, benchmark `Cargo.toml`/`Cargo.lock`, campaign
artifacts, documentation, logs, proof/profile outputs, or unrelated untracked
files. The benchmark lockfile must be restored only after final validation.

## Appendix: original baseline campaign plan

This appendix preserves the plan supplied at campaign start. It is the baseline
intent, not a claim that the listed work is complete. The current status and
later mandatory P001 profiling/trim gate above govern resumption.

### Summary

Resume from `ceno@785319e4`, `ceno-gpu@4f2f2100`, and benchmark `06461978`.

The production fast sequential tracer is `GpuReplayTracer`; `FullTracer`
remains the legacy/debug correctness reference. Multicore CPU workers classify
and enrich sealed compact chunks into typed per-chip inputs, which are uploaded
asynchronously and consumed directly by GPU kernels.

Create the persistent checkpoint at
`.codex-campaigns/fulltracer-gpu-ingress.md`; the normal
`.codex/campaigns/` path is unavailable because `.codex` is an existing file.
Keep campaign artifacts under
`.codex-campaigns/artifacts/fulltracer-gpu-ingress/` without changing ignore
policy.

### Campaign orchestration

- Start with a fresh `state_keeper` to create the checkpoint, record revisions,
  existing dirty files, baseline evidence, disk/GPU state, and the task graph.
- Use one fresh implementor/evaluator pair per implementation task. Their turns
  are sequential against a stable worktree.
- After every commit or material result, update the checkpoint before another
  mutation.
- After every evaluator verdict, invoke a fresh read-only `iteration_reporter`;
  send only its `ITERATION_DIGEST` and evidence paths to the supervisor and
  state keeper.
- Reuse each task's implementor/evaluator pair for at most three refinement
  iterations. If all three fail, preserve the correctness-passing experiment
  and evidence, mark the task `replan_required`, and report architectural next
  steps rather than immediately rolling it back.
- Commit only owned paths, separately in `ceno` and `ceno-gpu`. Never include
  existing secp, documentation, sumcheck, benchmark manifest, lockfile, or
  unrelated untracked changes.

### Implementation tasks

#### 1. Campaign bootstrap and acceptance observability

- Record current warm baselines and the 256K/512K compact evidence.
- Add validation-only deterministic fingerprints for chip-sorted witness
  matrices, public values, lookup multiplicities, ordered ShardRAM records,
  accessed-address state, continuation matrices, and final continuation state.
- Add synchronized post-witgen free-VRAM reporting using `cudaMemGetInfo`.
- Compare legacy and compact fingerprints in separate runs so timed production
  measurements never use dual recording.
- Reclaim only explicitly identified regenerable build/output artifacts before
  large builds; preserve logs and user files.

#### 2. Preflight counts and deterministic typed SoA routing

- Retain exact per-shard `InsnKind` counts already computed during preflight,
  solely for allocation. Do not create a preflight record journal.
- Replace per-family `Vec<GpuReplayOrdinaryRecord>` production arenas with
  internal typed SoA storage containing only each family's runtime fields and
  decoded immutable-program metadata.
- Workers classify and enrich chunk-local typed columns. A sequence coordinator
  grants per-family offsets in chunk order; workers then fill disjoint final
  ranges without shared-vector appends, final concatenation, or per-chip ordinal
  sorting.
- Preserve `(chunk_sequence, ordinal)` order, the bounded 2–4 chunk queue,
  chunk-boundary backpressure, sparse fallback ordering, and explicit
  unsupported-record failure.
- Instrument replay, classification, offset wait, SoA fill, bytes per
  instruction, and finalization independently.

#### 3. Pinned asynchronous ingress vertical slice

- Add internal `PinnedStagePool`, `GpuReplayIngressSession`, device-family range
  descriptors, and completion tokens/events. Do not expose a public API.
- Default to two 64 MiB pinned buffers on one dedicated H2D stream. Never reuse
  a buffer before its completion event and make consuming compute streams wait
  for the corresponding upload event.
- Allocate final shard-scoped device ranges once from preflight counts and
  upload worker-produced SoA spans directly to assigned offsets while replay
  continues.
- Migrate ADD first and compare its witness, lookup, ShardRAM, ordering, H2D,
  and kernel output against both FullTracer and the existing compact ADD kernel.
- Tune at most three configurations: `2×64 MiB`, `2×128 MiB`, then
  `3×128 MiB`, changing configuration only in response to measured staging or
  transfer stalls.

#### 4. Migrate all ordinary instruction families

- Remove `take_compact_records`, per-dispatch append/sort, compact host
  `StepIndex` construction, `usize → u32` conversion, and
  `upload_compact_steps_cached` from migrated production paths.
- Update kernel wrappers and CUDA kernels to consume typed family views
  directly.
- Migrate and commit in this order: I-type; R-type
  arithmetic/logic/shift/mul/div; branches; loads/stores; jumps and remaining
  ordinary families.
- Each family group receives focused layout tests, legacy-versus-SoA kernel
  equality tests, a scoped commit in each affected repository, evaluator
  review, iteration digest, and checkpoint update.
- Keep complete legacy ingress selectable and unchanged.

#### 5. Sparse special-chip ingress

- First probe ownership around the already-modified secp files and avoid
  overwriting or committing unrelated edits.
- Migrate secp256k1 add/double typed inputs to pinned/ranged ingress, followed by
  Keccak staging.
- Preserve syscall semantics and keep unsupported, exceptional, or dynamic-PC
  execution in the explicit sparse fallback or complete legacy mode.
- Do not change AIR, proof formats, or public interfaces.

#### 6. Cleanup and final acceptance

- Remove obsolete compact AoS caches and temporary migration adapters only
  after every consumer uses typed device ranges.
- Restore benchmark `Cargo.lock` after validation; keep local path-patch wiring
  uncommitted.
- Produce a final Reth performance report with revisions, configuration,
  medians, deltas, fingerprints, proof results, memory headroom, retained
  fallbacks, and remaining risks.
- Mark the campaign complete only after every task passes and the final state
  keeper update records a clean explanation for every unrelated dirty file.

### Verification and performance gates

Use cached block `23587691` with `--chain-id 1`, local path patches, GPU
features, and the circuit-aware two-shard configuration. Never expose an RPC
value.

For every milestone:

- Require `CUDA Backend Enabled`, 19,184,568 instructions, two shards, and
  boundaries `[4, 54691232, 76738276]`.
- Run one excluded warmup per mechanism, then interleave
  `control-1, candidate-1, control-2, candidate-2, control-3, candidate-3`.
- Compare three-run medians for preflight, replay, routing, SoA fill, H2D,
  ordinary kernels, special chips, lookup, continuation, total shard-0 witness,
  proving time, RSS, and VRAM.
- Require targeted-phase improvement above 5%, total shard-0 witness
  improvement of at least 2%, preflight regression no greater than 1%, and
  proof-phase regression no greater than 1%.
- Require byte-identical legacy/compact validation manifests for both shards,
  exact public values and lookup digest, ordered ShardRAM and continuation
  equality, at least 1 GiB post-witgen free VRAM, and restored GPU-pool usage.
- Reject fallback errors, unsupported ordinary records, ordering failures,
  panics, CUDA errors, OOMs, and nondeterministic fingerprints.
- Finish with three interleaved shard-0 application-proof trials, a complete
  two-shard application proof and verification, then full recursion proof and
  verification.

### Assumptions

- The existing 256K chunk size is the starting point; chunk size and staging
  depth receive no more than three evidence-driven tuning iterations per
  mechanism.
- VM semantic execution and predecessor tracking remain serial.
- Workers perform CPU classification/enrichment; GPU kernels perform witness,
  lookup, and ShardRAM expansion from final typed device ranges.
- No post-hoc `StepRecord` packing, preflight witness journal, multi-GPU
  scheduling, or cross-shard overlap will be introduced.
- Root filesystem capacity is an environmental prerequisite for proof
  evaluation; only recoverable build artifacts may be removed without
  additional authority.
