# Concurrent Chip Proving

This document describes the **concurrent chip proving** mechanism on the GPU,
centered around a memory-aware parallel scheduler that uses a greedy backfilling
algorithm to maximize GPU utilization while respecting VRAM limits.

## Motivation

Previously, chip proofs were generated **sequentially** — one circuit at a time.
This left significant GPU idle time, especially when small chip proofs could run
in parallel with large ones. The scheduler overlaps chip proofs concurrently with
preemptive memory reservation, improving overall proving throughput.

## Architecture Overview

The prover's `create_proof_of_shard` is restructured into three clean phases:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                             create_proof_of_shard                              │
│                                                                                │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐  │
│  │ Phase 1: BUILD       │  │ Phase 2: EXECUTE     │  │ Phase 3: COLLECT     │  │
│  │ build_chip_tasks     │─>│ run_chip_proofs      │─>│ collect_chip_results │  │
│  │                      │  │                      │  │                      │  │
│  │ - Iterate circuits   │  │ CPU: sequential      │  │ - Aggregate proofs   │  │
│  │ - Build ChipTask     │  │ GPU: scheduler       │  │   into BTreeMap      │  │
│  │ - Estimate GPU mem   │  │   concurrent exec    │  │ - Collect opening    │  │
│  │ - GPU: defer witness │  │   with backfilling   │  │   points & evals     │  │
│  │ - CPU: eager witness │  │ - Transcript forking │  │ - Merge PI updates   │  │
│  │                      │  │   handled internally │  │ - Merge transcript   │  │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
```

## Scheduler Core: Greedy Backfilling Algorithm

The scheduler sorts all chip proof tasks by estimated GPU memory (descending),
then greedily assigns the largest task that fits into currently available VRAM.
When nothing fits, it blocks until a running task completes and frees memory.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   ChipScheduler::execute_concurrently                    │
│                                                                          │
│  Input: Vec<ChipTask> (unsorted)                                         │
│                                                                          │
│  Step 1: Sort by estimated_memory_bytes DESC ("big rocks first")         │
│  ┌───────────────────────────────────────────────────────────────┐       │
│  │ Task A (800MB) > Task B (400MB) > Task C (200MB) > Task D ... │       │
│  └───────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  Step 2: Spawn N worker threads (N = min(stream_pool_size, #tasks))      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                          │
│  │ Worker 0   │  │ Worker 1   │  │ Worker 2   │  ...                     │
│  │ (stream)   │  │ (stream)   │  │ (stream)   │  ...                     │
│  └────────────┘  └────────────┘  └────────────┘                          │
│  Each worker: shared task_rx (Mutex<Receiver>), own done_tx (Sender)     │
│                                                                          │
│  Step 3: Scheduling loop (main thread)                                   │
│  ┌───────────────────────────────────────────────────────────────┐       │
│  │         Begin                                                 │       │
│  │           │                                                   │       │
│  │           ┌───────────────────────────────────────────────┐   │       │
│  │           ▼                                               │   │       │
│  │  ┌────────────────────┐                                   │   │       │
│  │  │ Drain completions  │◄── try_recv() (non-blocking)      │   │       │
│  │  │ release VRAM       │    unbook_capacity()              │   │       │
│  │  └────────────────────┘                                   │   │       │
│  │           │                                               │   │       │
│  │           ▼                                               │   │       │
│  │  ┌────────────────────┐ YES ┌──────────────────┐          │   │       │
│  │  │ Pending task fits  │────>│ book_capacity()  ├─────────>┤   │       │
│  │  │ in VRAM?           │     │ send to worker   │ continue │   │       │
│  │  └────────────────────┘     └──────────────────┘          │   │       │
│  │           │  NO                                           │   │       │
│  │           ▼                                               │   │       │
│  │  ┌────────────────────┐ YES ┌─────────────────────────┐   │   │       │
│  │  │ inflight == 0?     │────>│ DEADLOCK: Return Error. │   │   │       │
│  │  └────────────────────┘     └─────────────────────────┘   │   │       │
│  │           │  NO                                           │   │       │
│  │           ▼                                               │   │       │
│  │  ┌────────────────────┐                                   │   │       │
│  │  │ Block: wait for    │                                   │   │       │
│  │  │ next completion    │                                   │   │       │
│  │  └────────┬───────────┘                                   │   │       │
│  │           │  recv() (blocking) ──> free VRAM              │   │       │
│  │           └──────────────────────────────────────────────>┘   │       │
│  │           │                                                   │       │
│  │           │  pending.is_empty() && inflight == 0              │       │
│  │           ▼                                                   │       │
│  │          Exit                                                 │       │
│  └───────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  Step 4: Sort results by task_id to restore deterministic order          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Scheduling Example (Timeline)

Consider 4 tasks on a GPU with 1200MB available VRAM and 4 worker streams:

```
Tasks (sorted by memory, descending):
  A: 800MB    B: 400MB    C: 200MB    D: 50MB

────────────────────────────────────────────────────────────────── time ────────────────────>

        400MB 0MB          400MB 200 150MB   1200MB     <──  Mem Pool (free space)
            │  │                │ │ │         │ 
           t0 t1              t2 t3 t4        t5
            │  │                │ │ │         │ 
            ▼  ▼                ▼ ▼ ▼         ▼ 
            ┌─────────────────────────────────┐
            │ Task A (800MB)                  │ ─── try_book: 1200-800=400MB, fits! book @ t0
            └─────────────────────────────────┘     unbook @ t5
               ┌────────────────┐
            ...│ Task B (400MB) │               ─── try_book: 400-400=0MB, fits! book @ t1
               └────────────────┘                   unbook @ t2
                                  ┌──────────┐
            ......................│ C(200MB) │  ─── try_book: pool full (0MB free), wait
                                  └──────────┘  ... book @ t3: 400-200=200MB, fits!
                                    ┌───────┐
            ........................│ D(50) │   ─── try_book: pool full (0MB free), wait
                                    └───────┘   ... book @ t4: 200-50=150MB, fits!

Legend:
  t0: Launch A (800MB). Pool: 400MB free.
  t1: B (400MB) fits remaining 400MB. Launch B. Pool: 0MB free.
  t2: B completes → unbook 400MB. 
  t3: C (200MB) fits. Launch.
  t4: D (50MB) fits. Launch.
  t5: All done.
```

## GPU Memory Estimation

Before scheduling, each task's peak GPU memory is estimated without executing it.
The formula computes **resident** (always occupied) + **max(stage temporaries)**.

```
┌───────────────────────────────────────────────────────────────────────┐
│               estimate_chip_proof_memory(cs, input, name)             │
│                                                                       │
│  ┌─── Resident Memory (always occupied) ─────────────────────────┐    │
│  │                                                               │    │
│  │ trace_resident = witness_mle_bytes + structural_mle_bytes     │    │
│  │   (num_witin * 2^num_vars * sizeof(BabyBear))                 │    │
│  │   + (num_structural * 2^num_vars * sizeof(BB))                │    │
│  │                                                               │    │
│  │ main_witness = num_records * 2^num_vars * sizeof(BabyBearExt4)│    │
│  │   (records = reads + writes + lk_num + lk_den)                │    │
│  │                                                               │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─── Stage Temporaries (only one active at a time) ───────────────┐  │
│  │                                                                 │  │
│  │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │  │
│  │ │ Trace       │ │ Tower       │ │ ECC Quark   │ │ Main GKR    │ │  │
│  │ │ Extraction  │ │ Build+Prove │ │ Sumcheck    │ │ Zerocheck + │ │  │
│  │ │ (2x witness │ │ (prod +     │ │ (selectors  │ │ Rotation    │ │  │
│  │ │  temp_buf)  │ │  logup)     │ │  + splits)  │ │ sumcheck    │ │  │
│  │ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │  │
│  │       └──────────────┴──────────────┴──────────────┘            │  │
│  │                     max(temporaries)                            │  │
│  │                                                                 │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  TOTAL = trace_resident + main_witness + max(temporaries) + 5MB       │
└───────────────────────────────────────────────────────────────────────┘
```

### Dev-Mode Validation

Set `CENO_GPU_MEM_TRACKING=1 CENO_CONCURRENT_CHIP_PROVING=0` to enable
estimation validation. Each proving stage compares estimated vs actual GPU
memory, asserting:
- Under-estimate tolerance: 1MB (actual may exceed estimate by at most 1MB)
- Over-estimate margin: 5MB (estimate may exceed actual by at most 5MB)

## Per-Task Execution Flow (GPU Concurrent)

Each worker thread runs an independent chip proof with its own CUDA stream
and forked transcript:

```
┌──────────────────────────────────────────────────────────────────┐
│                     Worker Thread (per ChipTask)                 │
│                                                                  │
│  1. Acquire pool CUDA stream                                     │
│     cuda_hal.get_pool_stream()                                   │
│     bind_thread_stream(stream)  ◄── thread-local CUDA stream     │
│                                                                  │
│  2. Fork transcript (deterministic)                              │
│     local_transcript = clone(parent)                             │
│     local_transcript.append(task_id)                             │
│     local_transcript.append(circuit_idx)                         │
│                                                                  │
│  3. Deferred witness extraction (GPU JIT)                        │
│     extract_witness_mles_for_trace(pcs_data, idx, ..)            │
│     transport_structural_witness_to_gpu(rmm, ..)                 │
│                                                                  │
│  4. Chip proof pipeline (standalone _impl functions)             │
│     ┌──────────────────────────────────────┐                     │
│     │ [optional] prove_ec_sum_quark_impl   │                     │
│     │                   │                  │                     │
│     │                   ▼                  │                     │
│     │ build_main_witness (GKR witness gen) │                     │
│     │                   │                  │                     │
│     │                   ▼                  │                     │
│     │ prove_tower_relation_impl            │                     │
│     │ (product + logup tower build & prove)│                     │
│     │                   │                  │                     │
│     │                   ▼                  │                     │
│     │ prove_main_constraints_impl          │                     │
│     │ (GKR zerocheck + rotation sumcheck)  │                     │
│     └──────────────────────────────────────┘                     │
│                                                                  │
│  5. Sample from forked transcript, send CompletionMessage        │
│     forked_sample = transcript.sample_vec(1)[0]                  │
│     done_tx.send(CompletionMessage { result, mem, sample })      │
│                                                                  │
│  6. Panic safety: catch_unwind wraps entire execution            │
│     Converts panics to ZKVMError, prevents scheduler deadlock    │
└──────────────────────────────────────────────────────────────────┘
```

## Thread Safety Design

The concurrent scheduler must avoid `Send`/`Sync` requirements on
`ZKVMProver` and `GpuProver`. The solution:

```
┌──────────────────────────────────────────────────────────────────┐
│                      Thread Safety Architecture                  │
│                                                                  │
│  Problem: ZKVMProver holds non-Send/Sync state (Rc, closures)    │
│                                                                  │
│  Solution: Standalone _impl functions                            │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                                                           │   │
│  │ Original trait methods        Standalone functions        │   │
│  │ (require &self)              (no &self, Send+Sync args)   │   │
│  │                                                           │   │
│  │ device.prove_tower_relation ─> prove_tower_relation_impl  │   │
│  │ device.prove_main_constraints> prove_main_constraints_impl│   │
│  │ device.prove_ec_sum_quark ──> prove_ec_sum_quark_impl     │   │
│  │ self.create_chip_proof ─────> create_chip_proof_gpu_impl  │   │
│  │                                                           │   │
│  │ Trait methods delegate to standalone functions.           │   │
│  │ Concurrent path calls standalone functions directly.      │   │
│  │ Sequential path uses self.create_chip_proof (trait).      │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Shared data across threads:                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ transcript ──> SyncRef wrapper (read-only, cloned per task)│  │
│  │ pcs_data ───> SyncRef wrapper (read-only via get_trace)    │  │
│  │ Rc<Backend> ─> Arc<Backend>  (Rc→Arc migration)            │  │
│  │ CudaHalBB31 ─> Arc (was Mutex-guarded, now lock-free)      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Per-thread isolation:                                           │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ CUDA stream ──> thread_local! { THREAD_CUDA_STREAM }      │   │
│  │ transcript ───> cloned per task + task_id appended        │   │
│  │ GPU memory ──> preemptively booked from shared CudaMemPool│   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Deferred Witness Extraction (GPU)

On the GPU path, witness polynomials are **not** extracted from PCS data
during Phase 1. Instead, they are extracted just-in-time when a worker
begins executing a task. This reduces peak VRAM usage.

```
┌──────────────────────────────────────────────────────────────────────┐
│               CPU Path (Eager)          GPU Path (Deferred)          │
│                                                                      │
│  Phase 1:     extract_witness_mles()   witness = vec![] (empty)      │
│  build_tasks  transport_structural()   structural = vec![] (empty)   │
│               structural_rmm = None    structural_rmm = Some(rmm)    │
│                                                                      │
│  Phase 2:     create_chip_proof()      create_chip_proof_gpu_impl()  │
│  execute      (input already filled)   extract_witness_mles_for_     │
│                                          trace(pcs_data, idx, ..)    │
│                                        transport_structural_         │
│                                          witness_to_gpu(rmm, ..)     │
│                                        (now input is populated)      │
│                                        ... proceed with proving      │
└──────────────────────────────────────────────────────────────────────┘
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `CENO_CONCURRENT_CHIP_PROVING` | `1` (enabled) | Set to `0` for sequential execution |
| `CENO_SCHEDULER_WORKERS_NUM` | `64` | Number of concurrent CUDA streams |
| `CENO_GPU_MEM_TRACKING` | `0` (disabled) | Set to `1` to enable memory estimation validation |
| `RUST_MIN_STACK` | — | Set to `16777216` (16MB) for multi-threaded execution |

## Key Source Files

| File | Role |
|---|---|
| `ceno_zkvm/src/scheme/scheduler.rs` | Scheduler core: greedy backfilling algorithm |
| `ceno_zkvm/src/scheme/gpu/memory.rs` | GPU memory estimation per chip proof stage |
| `ceno_zkvm/src/scheme/gpu/mod.rs` | Standalone `_impl` proving functions |
| `ceno_zkvm/src/scheme/prover.rs` | 3-phase architecture: build / execute / collect |
| `ceno_zkvm/src/scheme/hal.rs` | `ChipInputPreparer` trait for deferred extraction |
| `gkr_iop/src/gpu/mod.rs` | Per-thread CUDA stream, `Rc→Arc`, lock-free HAL |
