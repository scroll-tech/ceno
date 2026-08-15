# AOT FullTracer + GPU Witness 10x Co-Design Plan

Date: 2026-08-14 (Asia/Singapore)

## Summary and acceptance target

Redesign shard-0 witness generation around one warmed AOT preflight execution
that emits compact, versioned shard journals directly for GPU consumption. The
production GPU path must ultimately remove the second FullTracer replay, the
1.77 GiB `StepRecord` upload, CPU positioning and per-chip index construction,
repeated lookup D2H, and the 33.8M-entry duplicated-address sort.

The accepted warm AOT shard-0 baseline is approximately 1.65s. P0 found that
the original milestone budgets do not fit within 165ms, so the committed
engineering target is revised to a three-trial interleaved median of at most
200ms for the `generate_witness` span. 165ms remains a stretch goal and may not
be restored as a gate without a measured mechanism that closes the remaining
budget. AOT compilation, setup, preflight, witness generation, and proving
remain separately reported. Preflight may regress by at most 10%, combined
preflight plus witness time must materially improve, and application proving
may regress by at most 1%. No proof, AIR, transcript, public-value,
shard-boundary, instruction-count, or witness semantics may change.

## CPU/GPU boundary

The CPU executes the guest through warmed AOT; enforces traps, branches,
syscalls, memory semantics, and shard planning; maintains only the latest-access
state required during execution; emits compact typed records and deterministic
shard descriptors; preserves the FullTracer/CPU path as the correctness
reference and explicit fallback; and restores completed shard proofs to shard
order.

The GPU consumes opcode, access-edge, and syscall arenas; derives chip counts,
offsets, row placement, access-chain annotations, and future-access flags;
expands ordinary, Keccak, secp256k1, continuation, and table witnesses;
aggregates lookup multiplicities; builds ShardRAM inputs without duplicate
per-chip address lists; and keeps witness matrices device-resident through
proving.

## Compact journal ABI

`CompactShardJournalV1` is an internal, versioned device interface containing:

- shard identity, cycle range, step count, public-value inputs, layout
  fingerprint, and typed arena descriptors;
- opcode-family records containing only fields consumed by their GPU kernels;
- one access edge for each actual RS1, RS2, RD, or memory access, with its
  predecessor cycle or slot;
- compact syscall and precompile records; and
- explicit fixed-width device discriminants and no Rust enum, pointer, nested
  `Vec`, serialized proof, or raw `StepRecord` ABI.

AOT and CPU fallback must emit the identical ABI. The target staging design is
two 64 MiB pinned slabs per active device under a 512 MiB global pinned-memory
cap. Slabs seal only at deterministic step boundaries or when full.

## Address-chain design

The new path must not sort the 33.8M duplicated per-chip addresses. It emits
each execution access once, maps cycles to deterministic access slots, and
scatters each successor into its unique predecessor entry on GPU. Per-block
counts and exclusive scans provide compact output offsets. Initialization
addresses are aggregated separately, and only the final unique address set may
be sorted when canonical order requires it. Address-chain derivation and
local-slot privatization remain independent experiments.

## Device ownership and scheduling

`GpuFleet` owns one HAL, memory pool, stream set, and cache set per device. A
`DeviceShardLease` exclusively owns one device from journal ingestion through
proof completion. The same device may not enqueue any H2D, witness,
continuation, or proving work for shard N+1 before shard N releases its lease;
different devices may process different shards concurrently.

Shard `s` is assigned to device `s % device_count`, with proofs collected in
shard order. The default has one CPU AOT emission permit, one global H2D ingress
permit, and device queue depth one. The first release neither splits a shard
across devices nor uses peer-to-peer transfers. NVTX metadata includes device,
shard, journal chunk, and phase. Debug builds reject mixed-shard buffers,
cross-device pointers, and overlapping leases.

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
- Infrastructure milestones may be accepted without a speedup only when they
  are required by the next measured milestone, fully tested, and no more than
  1% slower.
- Change one mechanism per experiment and allow at most two tuning iterations
  intrinsic to that mechanism.
- Treat AOT, scheduler, incremental PCS, stream-count, address-chain, and
  local-slot changes as separate controlled experiments.
- Update this document before implementation and after every milestone with
  exact revisions, commands, timings, correctness, memory, profiler evidence,
  tuning, decision, resulting commits, and the next accepted parent.

## Historical evidence from the superseded kernel-first plan

### H0 — Reproducible baseline

Status: accepted on 2026-08-15.

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

#### Acceptance record

- Revisions: Ceno `a6c01deb344a440c8f7da4de1dfd6f5aa69f776c`
  (code parent `bb73003f7031f5498b6a2b3b177d54b1d9489fd7`), ceno-gpu
  `996ef2a1c1f5648d8ae42b085f630ec84a514d7b`, and benchmark
  `904990f18627f51e85a3a7ed1a364150b3a797d6`. Pre-existing ceno-gpu
  sumcheck worktree changes were preserved and excluded.
- Configuration: release `jemalloc,gpu`; cached block `23587691`;
  `--chain-id 1`; cost limit `2684354560`; cache level 1; `h=23`; lane
  scheduling with four lanes; memory tracking enabled. The AOT control added
  only the `aot` feature.
- The execute calibration reproduced 19,184,568 instructions, 76,738,276
  cycles, exactly two shards, and boundaries `[4, 54691232, 76738276]`.

GPU witness generation was compared with CPU witness generation in the
interleaved order CPU 1, GPU 1, CPU 2, GPU 2, CPU 3, GPU 3. Logs are
`m0_witgen{0,1}_{1,2,3}_20260815.log` in the benchmark worktree.

| Trial | CPU witness | GPU witness | CPU app proof | GPU app proof |
| --- | ---: | ---: | ---: | ---: |
| 1 | 2.58s | 1.80s | 7.3167s | 6.3632s |
| 2 | 2.78s | 1.84s | 7.5571s | 6.2075s |
| 3 | 2.68s | 1.83s | 7.3886s | 6.1947s |
| Median | 2.68s | 1.83s | 7.3886s | 6.2075s |

The accepted GPU configuration improves median shard-0 witness generation by
31.72% and median application proving by 15.99%. Median FullTracer positioning
is 626ms, opcode assignment is 817ms, initial `StepRecord` H2D is 139ms, and
address sort/dedup is 285ms. It uploads 13,672,807 records, 1,773.36 MiB, and
retains the 1,859,501,888-byte host record buffer.

The AOT feature was then tested independently, using separate AOT and non-AOT
binaries from the same sources in the interleaved order control 1, AOT 1,
control 2, AOT 2, control 3, AOT 3. Logs are
`m0_aot_{noaot,aot}_proof_{1,2,3}_20260815.log`.

| Trial | Control witness | AOT witness | Control app proof | AOT app proof | AOT preparation |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.91s | 1.64s | 6.5346s | 5.1608s | 2.50s |
| 2 | 1.82s | 1.65s | 6.4682s | 5.2267s | 2.52s |
| 3 | 1.81s | 1.65s | 6.4252s | 5.1278s | 2.63s |
| Median | 1.82s | 1.65s | 6.4682s | 5.1608s | 2.52s |

AOT improves median witness generation by 9.34%, its FullTracer positioning
target from 630ms to 460ms (26.98%), and application proving by 20.21%, so it
passes the formal gate. It is retained as a warmed/reused-SDK throughput mode.
Its median 2.52s per-process preparation cost makes a single cold proof slower
overall, so non-AOT remains the controlled baseline for kernel experiments;
AOT will not be combined with M2.

Profiler and resource inventory:

- The largest per-chip assignment spans in the representative GPU run were ADD
  150ms, secp256k1 double 128ms, KeccakCore 90.8ms, secp256k1 add 79.8ms,
  ADDI 51.2ms, SW 42.4ms, and LW 33.3ms.
- The shard-0 Nsight profile's hottest kernels were
  `squeeze_challenge_duplex` (13.2%, 432.5ms),
  `eval_mixed_poly_internal_k_per_term_v2` (12.0%, 392.3ms),
  `fold_virtual_poly_v2_and_eval_next_tower_small_mle` (11.2%, 365.1ms),
  BN254 row hashing (9.7%, 317.9ms), virtual-poly evaluation (8.3%,
  272.1ms), and Poseidon2 row hashing (5.7%, 185.2ms). The profile artifacts
  are `scheduler_redesign_shard0_20260813.{nsys-rep,sqlite}` and use the same
  code revisions and workload.
- Nsight recorded 3,677.989 MB H2D, 1,720.870 MB D2D, 108.867 MB D2H, and
  7,417.543 MB of device memset operations for the complete shard-0 profile.
  CUDA API time was dominated by asynchronous H2D calls (60.3%), kernel launch
  calls (21.8%), and asynchronous D2H calls (7.8%).
- One-second `nvidia-smi dmon` sampling peaked at 99% SM and 68% memory-engine
  utilization; active samples averaged 40.1% SM and 13.3% memory utilization.
  This coarse sample is retained in
  `gpu_dmon_fulltracer_witgen1_shard0_23587691_20260814.log`.
- Across the accepted trials, witness cleanup returned to the clean 485 MiB
  baseline. The highest observed peak was 13,245 MiB of 15,850 MiB, leaving
  approximately 2.5 GiB headroom.

Correctness and final decision:

- Every CPU/GPU and AOT/control trial reported `CUDA Backend Enabled`, the
  calibrated instruction count and shard boundaries, successful application
  proof generation, and successful recursion root verification.
- A complete AOT-enabled two-shard proof generated and verified successfully in
  `m0_aot_twoshard_20260815.log`: shard witness times were 1.67s and 553ms,
  application proving was 7.3382s, recursion proving was 2.4007s, root
  verification was 25.0ms, and total proving was 9.7696s.
- No OOM, CUDA, kernel, proof, verification, allocation, transfer, or new
  application-witness fallback anomaly appeared. Existing recursion
  row-major CPU fallbacks were unchanged and outside this milestone.

Decision: accept M0. The parent for M2 remains ceno-gpu
`996ef2a1c1f5648d8ae42b085f630ec84a514d7b` with non-AOT `GPU_WITGEN=1` as
the isolated kernel baseline.

### H1 — Eliminate redundant output initialization

Status: rejected/rolled back on 2026-08-14.

- Prove which witness columns are completely overwritten by expansion kernels.
- Remove or narrow device memset operations only for those ranges.
- Keep explicit initialization for sparse or conditionally written columns.
- Measure memset time, total bytes written, witness time, and application proof
  time.

#### Experiment record

- Hypothesis: ordinary instruction expansion kernels overwrite every logical
  witness cell, so zero-initializing their output allocations is redundant.
- Isolated change: make only the ordinary shared witness allocation
  uninitialized. Keccak and ShardRAM allocations remained zero-initialized
  because they contain padding or conditionally written columns. A temporary
  `CENO_GPU_WITGEN_ZERO_OUTPUT={1,0}` switch allowed interleaved control and
  candidate runs from one binary.
- Revisions: Ceno `095d3adb6e89fdc4e5bc5f51e43da9b24ead30c1`
  (source parent `bb73003f7031f5498b6a2b3b177d54b1d9489fd7`), ceno-gpu
  `996ef2a1c1f5648d8ae42b085f630ec84a514d7b`, and benchmark
  `904990f18627f51e85a3a7ed1a364150b3a797d6`. The unrelated ceno-gpu
  sumcheck worktree changes were preserved and excluded from the experiment.
- Build and workload: release `jemalloc,gpu`; `GPU_WITGEN=1`; cached block
  `23587691`; `--chain-id 1`; cost limit `2684354560`; cache level 1; `h=23`;
  lane scheduling with four lanes. Each trial ran `prove-stark --shard-id 0`
  and wrote to a distinct output directory.
- Interleaved order: control 1, candidate 1, control 2, candidate 2, control 3,
  candidate 3. Logs are
  `m1_zero_output_{control,candidate}_{1,2,3}_20260814.log` in the benchmark
  worktree.

| Trial | Control witness | Candidate witness | Control HAL expansion | Candidate HAL expansion | Control app proof | Candidate app proof |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.80s | 1.81s | 39.29ms | 39.04ms | 6.2328s | 6.3742s |
| 2 | 1.85s | 1.83s | 39.43ms | 37.58ms | 6.3197s | 6.3334s |
| 3 | 1.85s | 1.85s | 39.30ms | 37.65ms | 6.4276s | 6.4568s |
| Median | 1.85s | 1.83s | 39.30ms | 37.65ms | 6.3197s | 6.3742s |

The trace did not expose the allocation memset as a separate timer, so summed
ordinary `hal_witgen_*` spans are the narrowest observable targeted-phase
proxy. Their median improved 4.20%, below the 5% targeted-phase gate. Median
total witness generation improved 1.08%, below the 2% total gate. Median
application proof time was 0.86% slower, within the 1% noise band. Median
opcode assignment moved from 815ms to 812ms; median FullTracer positioning
regressed from 618ms to 629ms, consistent with run-to-run noise outside the
isolated mechanism.

Correctness and resource checks:

- All 22 ordinary-instruction direct CUDA/CPU witness comparisons passed with
  uninitialized output. The broader environment-enabled test helper has a
  pre-existing device-backed-host-placeholder limitation, and the sequential
  debug-compare suite later hit a pre-existing harness segmentation fault;
  neither failure was introduced by this allocation change.
- Every trial reported `CUDA Backend Enabled`, 19,184,568 instructions,
  76,738,276 cycles, exactly two shards, and boundaries
  `[4, 54691232, 76738276]`.
- All six shard-0 application proofs completed and recursion verification
  succeeded. The candidate was rejected at the performance gate, so the
  acceptance-only complete two-shard proof run was not performed.
- Witness cleanup reported a clean 485 MiB baseline. Peak allocation was
  12,746 MiB of 15,850 MiB, leaving approximately 3.0 GiB headroom. No OOM,
  CUDA, kernel, proof, verification, transfer, or application-witness fallback
  anomaly appeared. Existing recursion row-major CPU fallback messages were
  unchanged and outside this experiment.

Decision: reject and roll back. There is no intrinsic tuning parameter for a
boolean initialization removal, so no tuning iteration was justified. No
ceno-gpu implementation commit was created; the temporary switch and
uninitialized allocation were removed. The parent for the next independent
experiment remains ceno-gpu `996ef2a1c1f5648d8ae42b085f630ec84a514d7b`
with the pre-existing unrelated sumcheck changes preserved.

### H2 — Coalesced column-oriented expansion

Status: rejected/rolled back on 2026-08-15.

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

#### Experiment record

- Inspection found that ordinary witness expansion already uses a column-major
  layout: `WIT_SET_COL` writes `output[column_offset + row]`, adjacent warp
  lanes write consecutive rows, every thread exclusively owns its row, and
  fixed-multiplicity offsets are algebraic. No variable-multiplicity ordinary
  expansion path or per-row output atomic was present. Replacing this with a
  second tiled implementation would duplicate the intended ownership model
  without first establishing a distinct bottleneck.
- Hypothesis: the existing 512-thread launch shape may limit occupancy for
  register-heavy expansion kernels. The isolated candidate added a temporary
  `CENO_GPU_WITGEN_BLOCK_SIZE` launch selector and changed only ordinary
  witness expansion blocks from 512 to 256 threads. The first intrinsic tuning
  iteration used 128 threads. The same binary was used for every control and
  candidate process.
- Revisions: Ceno `c5cdfaaca16d441cbb634e2ba4158606217eb65d`, ceno-gpu
  `996ef2a1c1f5648d8ae42b085f630ec84a514d7b`, and benchmark
  `904990f18627f51e85a3a7ed1a364150b3a797d6`. Pre-existing unrelated
  ceno-gpu sumcheck worktree changes were preserved and excluded.
- Build and workload: release `jemalloc,gpu`; `GPU_WITGEN=1`; cached block
  `23587691`; `--chain-id 1`; cost limit `2684354560`; cache level 1; `h=23`;
  lane scheduling with four lanes; memory tracking enabled. Every trial ran
  `prove-stark --shard-id 0` with a distinct output directory.
- Build command, from the benchmark worktree:
  `cargo build --release --features jemalloc,gpu --config
  .codex-results/fulltracer_local_patches.toml --bin
  ceno-reth-benchmark-bin`. Trial command, with `$BLOCK` set to 512, 256, or
  128 and distinct `$OUT`/`$LOG` values:
  `CENO_GPU_ENABLE_WITGEN=1 CENO_GPU_WITGEN=1
  CENO_GPU_WITGEN_BLOCK_SIZE=$BLOCK CENO_GPU_CACHE_LEVEL=1
  CENO_GPU_MEM_TRACKING=1 CENO_GPU_LARGE_TASK_BOOKING_MARGIN_MB=0
  CENO_GPU_JAGGED_RESHAPE_LOG_HEIGHT=23
  CENO_MAX_CELL_PER_SHARD=2684354560 CENO_CHIP_PROVING_MODE=lanes
  CENO_CHIP_PROVING_LANES=4 LANES=4 RUST_MIN_STACK=536870912
  ./target/release/ceno-reth-benchmark-bin --block-number 23587691
  --chain-id 1 --cache-dir block_data --mode prove-stark --shard-id 0
  --output-dir $OUT >$LOG 2>&1`.
- The primary interleaved order was control 1, 256 candidate 1, control 2,
  candidate 2, control 3, candidate 3. Logs are
  `m2_block{512_control,256_candidate}_{1,2,3}_20260815.log` in the benchmark
  worktree.

| Trial | 512 witness | 256 witness | 512 HAL expansion | 256 HAL expansion | 512 app proof | 256 app proof |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.82s | 1.80s | 48.639ms | 47.932ms | 5.26s | 5.03s |
| 2 | 1.84s | 1.81s | 49.221ms | 47.447ms | 5.21s | 5.19s |
| 3 | 1.83s | 1.79s | 49.629ms | 47.441ms | 5.18s | 5.10s |
| Median | 1.83s | 1.80s | 49.221ms | 47.447ms | 5.21s | 5.10s |

The 256-thread candidate improves median total witness generation by 1.64%,
below the 2% gate, and summed ordinary `hal_witgen_*` expansion by 3.60%,
below the 5% targeted-phase gate. Median opcode assignment improves from
822ms to 804ms (2.19%) and positioning from 633ms to 621ms. Application proof
time improves by 2.11%, so it does not violate the proving-time guard, but
passing that guard does not compensate for missing both positive gates.

The permitted 128-thread tuning iteration used fresh interleaved controls.
Logs are `m2_block512_control_{4,5,6}_20260815.log` and
`m2_block128_tune1_{1,2,3}_20260815.log`.

| Trial | 512 witness | 128 witness | 512 HAL expansion | 128 HAL expansion | 512 app proof | 128 app proof |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.94s | 1.84s | 48.580ms | 49.503ms | 5.20s | 5.28s |
| 2 | 1.80s | 1.86s | 48.798ms | 48.605ms | 5.04s | 5.13s |
| 3 | 1.80s | 1.96s | 48.656ms | 50.072ms | 5.13s | 5.32s |
| Median | 1.80s | 1.86s | 48.656ms | 49.503ms | 5.13s | 5.28s |

At 128 threads, median witness generation regresses 3.33%, HAL expansion
regresses 1.74%, opcode assignment regresses 2.61%, and application proof time
regresses 2.92%. The monotonic reversal after 256 threads gave no basis for a
second tuning iteration.

Correctness, resource, and profiler checks:

- With the 256-thread selector, all 22 ordinary-instruction direct CUDA/CPU
  comparisons passed. The separately routed Keccak helper failed before its
  comparison because it requires full GPU-witgen enablement; this is the same
  known helper limitation recorded for M1, not a mismatch. End-to-end trials
  exercised Keccak successfully.
- All twelve end-to-end trials reported `CUDA Backend Enabled`, 19,184,568
  instructions, exactly two execution shards, boundaries
  `[4, 54691232, 76738276]`, a successful shard-0 application proof, and
  successful recursion root verification. No new application-witness fallback,
  OOM, allocation, transfer, CUDA, kernel, proof, or verification anomaly
  appeared. Existing recursion row-major CPU fallbacks were unchanged.
- Minimum observed device headroom was 1,600.88 MiB, above the 1 GiB gate.
- Nsight Compute could not collect store-efficiency, bandwidth, occupancy, or
  atomic counters on this CUDA installation: injection failed before program
  execution with missing symbol `cuTensorMapEncodeIm2colWide`. The failure is
  recorded in `m2_baseline_addi_ncu_20260815.log`; no candidate code was active
  in that attempt. Timing and source-level ownership evidence therefore remain
  the available targeted measurements.

Decision: reject and roll back. No ceno-gpu implementation commit was created;
the temporary block-size selector was removed. M3 must start from ceno-gpu
`996ef2a1c1f5648d8ae42b085f630ec84a514d7b`, with only the pre-existing
unrelated sumcheck changes preserved.

## Co-design milestones

| Milestone | Deliverable | Gate |
| --- | --- | --- |
| D0 | Replace the kernel-first pending plan with this co-design | Reviewed documentation commit |
| P0 | Causal profile and replacement budget | Stop/go gate; revise the target if replacements do not fit within 165ms |
| M1 | Compact journal ABI and dual recording | Exact equality; warm preflight overhead at most 1% |
| M2 | Single-pass AOT journal emission | At most 48 bytes/instruction; preflight regression at most 10% |
| M3 | Compact GPU ingress and ordinary expansion | H2D at most 40ms; dispatch plus expansion at most 40ms |
| M4 | Address chain and local-slot pipelines | Address/continuation preparation at most 30ms |
| M5 | Device lookup accumulation | Exposed lookup finalization at most 10ms |
| M6 | Independently migrate special-chip families | secp256k1 at most 25ms; Keccak at most 20ms |
| M7 | Device-resident continuation and production cutover | Full warm witness at most 220ms before pipelining |
| M8 | Bounded within-shard pipeline | Exposed staging/synchronization at most 20ms |
| M9 | Explicit multi-GPU fleet and leases | One-GPU equivalence, then measured multi-device proof |
| M10 | Final interleaved validation | Warm shard-0 witness median at most 200ms; 165ms stretch |

### D0 — Plan replacement

Status: accepted in this documentation revision.

This revision records the baseline, budget, CPU/GPU boundary, journal and
address-chain design, multi-GPU lease policy, experiment contract, and complete
milestone sequence before production changes.

### P0 — Profiling and causal ceilings

Status: stop/go gate failed for 165ms on 2026-08-15; target revised to 200ms.

- Run three interleaved warmed AOT shard-0 controls and report preflight,
  replay, positioning, raw upload, per-chip assignment, continuation, lookup,
  final tables, application proof, VRAM, pinned memory, CPU utilization, PCIe
  throughput, and CUDA utilization.
- Scope `perf stat` and `perf record` separately to AOT preflight and FullTracer
  replay, including cycles, instructions, IPC, branches, cache misses, and
  generated-DSO symbols.
- Capture Nsight Systems with shard/chip phase labels. Repair the Nsight Compute
  CUDA-injection mismatch before relying on atomic, occupancy, bandwidth, or
  store-efficiency counters.
- In disposable worktrees, independently trim positioning, raw record upload,
  address sorting, lookup D2H, secp256k1 assignment, Keccak assignment, and
  continuation. Never merge trim code.
- Build a replacement budget showing that at least 1.485s is removable and all
  replacement work plausibly fits within 165ms. If the measurements do not
  support that budget, revise the target instead of implementing M1.

#### Measurement record

Revisions were Ceno `7210dc0431aa353e1ea18dbd459286a6541c95ad`,
ceno-gpu `996ef2a1c1f5648d8ae42b085f630ec84a514d7b`, and benchmark
`904990f18627f51e85a3a7ed1a364150b3a797d6`. The ceno-gpu worktree's
pre-existing sumcheck changes were preserved and excluded. The release build
used `jemalloc,gpu,aot`, local Cargo path patches, cached block `23587691`,
`--chain-id 1`, cost limit `2684354560`, cache level 1, `h=23`, four proving
lanes, and memory tracking. Benchmark-only `Cargo.lock` changes were restored.

The first three attempted controls were invalid for P0 because the cached
binary had last been built without `aot`; their logs are
`p0_aot_control_{1,2,3}_20260815.log` and are not included below. Rebuilding
with the explicit `aot` feature produced AOT artifact cache hits in all three
accepted controls. Logs are `p0_aot_warm_control_{1,2,3}_20260815.log` in the
benchmark checkout.

| Trial | Preflight | Witness | Replay/position | Opcode assignment | Continuation | Address sort | App proof |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 126.05ms | 1.66s | 460ms | 809ms | 346ms | 296ms | 5.1895s |
| 2 | 126.31ms | 1.67s | 465ms | 800ms | 359ms | 311ms | 5.2123s |
| 3 | 127.96ms | 1.64s | 467ms | 798ms | 328ms | 283ms | 5.3031s |
| Median | 126.31ms | 1.66s | 465ms | 800ms | 346ms | 296ms | 5.2123s |

Every accepted control reported 19,184,568 guest instructions, 76,738,276
cycles, exactly two shards, boundaries `[4, 54691232, 76738276]`, successful
shard-0 application proving, successful recursion verification, and exit code
0. Median CPU utilization was 414% and median maximum RSS was 12,335,280 KiB.
The FullTracer buffer contained 13,672,808 slots and 1,859,501,888 bytes. Peak
framebuffer use was 13,449.69 MiB of 15,850.56 MiB, leaving 2,400.87 MiB.
There is no compact-journal pinned allocator yet, so pinned-slab use is zero;
the current process instrumentation does not expose CUDA driver's incidental
host pinning separately.

Nested phase evidence gives independent removable ceilings without adding
their overlapping parents: the first shard-session upload was 1,773.36 MiB in
139ms; lookup D2H summed to 79.39, 71.90, and 71.12ms; secp256k1 add/double
assignment was approximately 205ms; and the Keccak family was approximately
103ms. The 296ms address sort processed 33,764,071 duplicated addresses into
418,956 unique addresses. These are observed phase ceilings, not claims that
all can be removed simultaneously.

Nsight Systems artifact `p0_aot_warm_shard0_20260815.nsys-rep` and its SQLite
export recorded 3,548.438 MB H2D, 446.919 MB D2H, 2,063.934 MB D2D, and
13,097.216 MB memset for the full profile. H2D consumed 284.66ms and D2H
94.80ms. The largest witness kernel was `witgen_keccak` at 39.08ms. Existing
NVTX ranges identify proving chip, lane, and stream, but do not carry shard ID
or journal chunk; adding that metadata remains required before pipeline or
lease validation.

Nsight Compute initially failed because CUDA-12.8 `cudarc` eagerly resolved
`cuTensorMapEncodeIm2colWide`, which the 2025.1.1 injection library did not
export. A diagnostic rebuild with `CUDARC_CUDA_VERSION=12050` repaired the
injection mismatch without a source change. The resulting report
`p0_aot_addi_ncu_20260815.ncu-rep` measured `witgen_addi` at 4.82ms, 30.91%
achieved occupancy, 96 registers per thread, 19.95% memory throughput, and
17.06% DRAM throughput. NCU-instrumented end-to-end timing is not used as a
control.

`perf stat` and `perf record` artifacts are retained for the execute-only AOT
run and two delayed proof windows. The whole execute run reported 78.09B
instructions, 27.51B cycles, IPC 2.84, 5.998B branches, 0.65% branch misses,
and 167.05M cache misses, but setup dominated it and the generated preflight
DSO was only 0.10% of samples. The first delayed proof window captured AOT
artifact preparation, not replay. The shifted window reached witness
assignment but the forced stop prevented the tracing tree from proving the
replay boundary. Both delayed windows are invalid as replay-scoped PMU
evidence and are not used for attribution. No lost samples were reported.

#### Replacement budget and decision

The 1.66s median decomposes into the three serial parents: 465ms replay,
800ms opcode assignment, 346ms continuation, and approximately 49ms residual
framework work. Removing those parents is sufficient in principle, but the
proposed replacement caps do not fit the original target:

| Replacement | Optimistic exposed budget |
| --- | ---: |
| Fully overlapped compact H2D and ordinary expansion | 40ms |
| Address and continuation preparation | 30ms |
| Lookup finalization | 10ms |
| secp256k1 expansion | 25ms |
| Keccak expansion | 20ms |
| Existing residual framework work | 49ms |
| Optimistic total before M8 synchronization allowance | 174ms |
| Total with the allowed 20ms pipeline/synchronization budget | 194ms |

Thus the architecture can plausibly remove 1.466s and reach approximately
194ms, but it does not demonstrate the required 1.485s removal or a credible
165ms result. The contradiction comes from the plan's own accepted phase caps,
not uncertainty about one suspect, so destructive trim builds would not make
the replacement work fit. No trim code was merged. The independent observed
ceilings above remain the experiment priorities once the revised target is
accepted.

Decision: stop before M1, as required by the P0 gate. Revise the committed
target to 200ms, which leaves only 6ms margin over the measured replacement
budget; retain 165ms as a stretch goal requiring a new measured overlap or
framework-removal mechanism. M1 remains blocked until this revised target and
the missing shard-aware profiling labels are accepted.

### M1 — Compact journal ABI and dual recording

Status: accepted as the device-neutral ABI foundation on 2026-08-15. The user
accepted P0's 200ms engineering target and explicitly deferred real multi-GPU
scheduling; M1 therefore reserves future device adaptation without adding a
fleet, leases, CUDA contexts, or device selection.

Implemented `CompactShardJournalV1` with magic/version, a layout fingerprint,
explicit integer arena tags, relocatable offset/count/stride descriptors, a
56-byte typed opcode record, and a 32-byte access-edge record containing the
predecessor cycle. The host owner contains vectors, but every device-facing
record is fixed-layout `repr(C)` data with no enum, pointer, allocation, or
device identity. A future device lease can bind the same relative descriptors
to any device allocation without changing the journal ABI.

`WitnessRecordSink` now has legacy and compact implementations. Setting
`CENO_COMPACT_JOURNAL_VALIDATE=1` dual-records at the shared `StepSource` seam,
which covers interpreter and native AOT replay, and rejects opcode-field,
ordering, access-field, predecessor, summary-count, descriptor, fingerprint,
and syscall-association mismatches. It reports total bytes, bytes per step, and
packing time per shard. The production path does not construct either sink
when validation is disabled, and no preflight code path changed; consequently
the preflight overhead is structurally zero for this milestone. The private
AOT ABI version moved from 65 to 66.

Validation:

- `cargo test -p ceno_emul compact_journal --lib`: 3 passed, covering fixed
  sizes/alignment/fingerprint, compact-versus-legacy field equality, access
  predecessor packing, and malformed descriptors.
- `cargo check -p ceno_zkvm --features aot-x86_64`: passed.
- `cargo check -p ceno_zkvm --features gpu,aot-x86_64`: blocked before the M1
  code by the checkout's existing `ceno-gpu-mock` API mismatch (`common`,
  `CudaHal`, and buffer APIs are absent). This is not treated as GPU runtime
  validation.
- A focused `ceno_zkvm` lib-test link was attempted but exhausted the full
  filesystem. Only Cargo-generated `ceno_zkvm`/`ceno_emul` artifacts were
  cleaned (1.5GiB); the smaller checks above then passed.

Implementation commit: `0ae2c20006b13ee3945ef28c35f209b58605e72a`
(`perf(witgen): add compact shard journal ABI`).

Decision: retain the ABI and dual recorder. Public-value serialization and
typed precompile payload expansion remain deliberately reserved in their arena
descriptors until their first consumers are implemented; M2 must fill and
compare those payloads before removing any legacy replay semantics. M2's parent
is the M1 implementation commit recorded below.

### M2 — Single-pass AOT journal emission

Status: rejected at the parent-layout gate on 2026-08-15; no AOT emitter code
was retained.

Before adding generated-DSO stores, the accepted M1 layouts were checked
against M2's volume requirement. `CompactOpcodeRecordV1` is 56 bytes and
`CompactAccessEdgeV1` is 32 bytes. Consequently the journal is at least 56
bytes per guest instruction with no architectural accesses and
`56 + 32 * accesses` bytes for ordinary instructions. It cannot meet the
committed average target of at most 48 bytes per guest instruction under any
workload. Emitting this layout directly from AOT would add large preflight
memory traffic for a mechanism that is statically unable to pass acceptance.

The gate also confirmed that M1 only reserved the syscall arena and public
value serialization; those payloads are not yet sufficient for exact
production replay removal. Adding assembly emission before defining them would
freeze another incomplete ABI revision.

Decision: do not implement or commit native emission for the rejected layout.
Reopen the private ABI before retrying M2 with typed opcode-family records,
separate compact register and memory access records, and predecessor slots
rather than repeated 64-bit cycles where the bounded execution permits it. The
replacement must prove its worst-case overflow/fallback semantics and measured
average volume before touching generated assembly. Actual multi-GPU contexts,
leases, and scheduling remain postponed; descriptors continue to use relative
offsets so the corrected ABI stays device-neutral.

The attempted cached-Reth measurement could not use the existing release
binary because it predates `CENO_COMPACT_JOURNAL_VALIDATE`; rebuilding was not
started with only 1.3GiB filesystem headroom. This does not weaken the rejection
because the zero-access lower bound alone exceeds the target. The next accepted
parent was `374fb922`; the required compact typed-family correction is recorded
below.

#### M1.1 — Typed journal ABI correction

Status: accepted as prerequisite infrastructure on 2026-08-15.

The rejected generic opcode/access pair was replaced by seven explicit,
relocatable arenas: opcode routes, register reads, register writes, memory
accesses, syscall associations, syscall accesses, and public-value words. The
device layouts contain only fixed-width integers. No host pointer, Rust enum,
slice, vector, CUDA identity, or device ownership crosses an arena descriptor.

Record sizes are now:

| Record | Bytes | Derivation removed from payload |
| --- | ---: | --- |
| Opcode route | 12 | cycle from shard start/index; `pc_after` from next route or shard summary |
| Register read | 8 | register and subcycle from decoded instruction/order |
| Register write | 12 | register and subcycle from decoded instruction/order |
| Memory access | 16 | cycle/subcycle from opcode index |
| Syscall association | 24 | payload stored once in syscall-access arena |
| Syscall access | 16 | syscall phase from association range |
| Public value word | 4 | fixed ordered word tape |

The future-access bit is packed with a bounded 31-bit predecessor cycle. The
packer rejects overflow instead of truncating; M2 must retain an explicit
legacy fallback for executions outside that bound. Ordinary opcode families
now fit the volume gate individually: the tested load path is exactly 48 bytes,
an R-type instruction is 40 bytes, and a two-read store is 44 bytes. Syscall and
public-value overhead is retained in the measured whole-journal average rather
than hidden outside it.

Dual validation reconstructs opcode order and `pc_after`, checks derived
cycles, predecessors, future flags, values, addresses, typed arena counts,
syscall associations/accesses, descriptors, fingerprint, shard summary, and
the public-value word tape. The private AOT ABI advanced from 66 to 67. This
correction still runs only under `CENO_COMPACT_JOURNAL_VALIDATE`, so production
preflight remains unchanged and has structurally zero added work.

Validation:

- `cargo test -p ceno_emul compact_journal --lib`: 4 passed.
- The ABI tests assert 12/8/12/16-byte ordinary records, exact legacy equality,
  malformed-descriptor rejection, and a 48-byte load-path volume ceiling.
- `cargo check -p ceno_zkvm --features aot-x86_64`: passed.
- A cached block-wide average was not rerun because only 1.2GiB filesystem
  headroom remained and the existing release binary predates this ABI.

Implementation commit: `6f8cc89c2e0cd14d574e831ea9dfaea7f114ecee`
(`perf(witgen): compact typed journal arenas`).

Decision: retain the corrected ABI. Retry M2 from `6f8cc89c`; generated AOT
stores must use these typed arenas directly and must measure the complete
journal, including syscall and public-value records, before acceptance. Actual
multi-GPU implementation remains postponed; the relative descriptors preserve
future per-device binding without constraining the current single-device path.

### M3 — Compact GPU ingress and ordinary expansion

Status: blocked on M2 acceptance.

Upload compact arenas, run device count/scan/scatter into chip-family ranges,
pass device offsets directly to ordinary kernels, and remove host
`step_indices` allocation/upload. Keep ordinary matrices and lookup outputs on
device; unsupported families retain visible legacy fallback.

### M4 — Address and local-slot pipelines

Status: blocked on M3 acceptance.

Run two separately revertible experiments. First derive successor and
future-access data by predecessor scatter with block-local unique aggregation.
Then give blocks or warps private local-slot ranges and deterministically scan
and compact them once. Each must preserve canonical row and lookup ordering.

### M5 — Device lookup accumulation

Status: blocked on M4 acceptance.

Test atomic reduction and sort/merge separately. Use warp/block-local tables,
merge once per key range, finalize the shard lookup table on device, and pass
device multiplicity buffers directly to witness tables and proving.

### M6 — Special-chip migration

Status: blocked on M5 acceptance.

Treat secp256k1 add/double and Keccak as separate accepted commits. Expand
compact EC operation records directly into GPU rows. For Keccak, retain packed
input on device and combine expansion with lookup accumulation. Migrate other
fallback chips only when their measured ceiling is material.

### M7 — Device-resident continuation and cutover

Status: blocked on M6 acceptance.

Feed access chains, EC records, and lookup buffers directly to continuation and
ShardRAM kernels; generate dynamic-init and final lookup tables on device; and
hand device-backed matrices to `create_proof`. Remove replay from the production
GPU path only when every active shard-0 family is covered. Keep an explicit
legacy/debug fallback.

### M8 — Bounded within-shard pipeline

Status: blocked on M7 acceptance.

Double-buffer journal chunks and overlap same-shard AOT emission, compact H2D,
expansion, and aggregation with one ingress and one witness stream joined by
events. Never stage the next shard on the leased device. Tune only chunk size
and staging depth, at most twice.

### M9 — Explicit multi-GPU fleet

Status: blocked on M8 acceptance.

Replace process-global CUDA HAL/cache ownership in the new path with
device-scoped contexts, static shard assignment, exclusive leases, global AOT
and H2D permits, queue depth one, and ordered proof collection. Validate one GPU
before two; test four only when available. Do not claim readiness without an
actual multi-device proof. The measured targets are no more than 5% per-shard
latency loss and at least 1.6x two-GPU multi-shard throughput.

### M10 — Final 10x validation

Status: blocked on M9 acceptance.

Run three interleaved accepted-baseline/candidate trials and one complete
two-shard proof. Require at most 200ms median warm shard-0 witness, report the
165ms stretch result, at most 10% preflight regression, materially lower
combined preflight plus witness time,
at most 1% application-proving regression, exactly two stable shards, complete
CPU/GPU equivalence and proof verification, at least 1 GiB VRAM headroom, no
fallback or runtime anomaly, and no same-device next-shard overlap.

Each rejected milestone leaves the next experiment based on the latest accepted
parent. A dependent milestone must be redesigned if its prerequisite is
rejected.

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

- D0: `docs(gpu): add AOT FullTracer GPU co-design plan`.
- P0 evidence: `docs(gpu): record AOT witgen causal profile`.
- Accepted implementations use the milestone-specific commit subject recorded
  in the plan; each owning repository receives a separate commit.
- Accepted milestone record: `docs(gpu): record <mechanism> milestone`.
- Rejected experiment: no code commit is merged; commit only the evidence with
  `docs(gpu): record rejected <mechanism> experiment`.
- Cross-repository changes receive separate owning-repository commits, with the
  final Ceno documentation commit referencing all exact hashes.

## Tests and assumptions

- Test ABI size, alignment, version, fingerprint, malformed descriptors, and
  cross-device pointers.
- Test interpreter/AOT journal equality and compact/legacy consumed-field
  equality.
- Test CPU/GPU witness, lookup, ShardRAM, continuation, public values, and proof
  equality.
- Cover empty, maximum, boundary-exact, and buffer-full shards; cross-shard
  future accesses; register aliases; first-touch memory; syscalls; traps; and
  dynamic fallback.
- Test required heights and padding rows for every migrated chip.
- Test lease exclusivity, queue depth, proof ordering, single-device fallback,
  and multi-device context isolation.
- Confirm logs contain `CUDA Backend Enabled` and do not contain fallback, OOM,
  kernel, proof, or verification errors.
- Use block `23587691`, cost limit `2684354560`, cache level 1, `h=23`,
  `CENO_CHIP_PROVING_MODE=lanes`, and `LANES=4`.
- Use cached inputs and `--chain-id 1`; never print or pass a raw RPC URL.
- Revert benchmark-only `Cargo.lock` changes after validation.
- The 10x target covers warmed shard-0 witness generation, not compilation or
  end-to-end proving.
- One GPU never overlaps two shards; separate devices may prove separate
  whole shards concurrently.
- The host is scarce, so one CPU emission/replay permit and one global H2D
  permit are the defaults.
- No public proof, AIR, transcript, public-value, shard, or witness semantics
  change. All layouts and scheduling interfaces remain internal.
