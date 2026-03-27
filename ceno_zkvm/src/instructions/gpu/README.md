# GPU Witness Generation

Accelerate witness generation by offloading computation from CPU to GPU.
This module (`ceno_zkvm/src/instructions/gpu/`) contains all GPU-side dispatch,
caching, and utility code for the witness generation pipeline.

The CUDA backend lives in the sibling repo `ceno-gpu/` (`cuda_hal/src/common/witgen/`).

## Architecture

### Module Layout

```
gpu/
├── dispatch.rs         — GPU dispatch entry point (try_gpu_assign_instances, gpu_fill_witness)
├── config.rs           — Environment variable config (3 env vars), kind tags
├── cache.rs            — Thread-local device buffer caching, shared EC/addr buffers
├── chips/              — Per-chip column map extractors + chip-specific GPU dispatch
│   ├── add.rs ... sw.rs  (24 RV32IM column map extractors)
│   ├── keccak.rs         (column map + keccak GPU dispatch: gpu_assign_keccak_instances)
│   └── shard_ram.rs      (column map + batch EC computation: gpu_batch_continuation_ec)
├── utils/
│   ├── column_map.rs   — Shared column map extraction helpers (extract_rs1, extract_rd, ...)
│   ├── d2h.rs          — Device-to-host: witness transpose, LK counter decode, compact EC D2H
│   ├── debug_compare.rs— GPU vs CPU comparison (activated by CENO_GPU_DEBUG_COMPARE_WITGEN)
│   ├── lk_ops.rs       — LkOp enum, SendEvent struct
│   ├── sink.rs         — LkShardramSink trait, CpuLkShardramSink
│   ├── emit.rs         — Emit helper functions (emit_u16_limbs, emit_logic_u8_ops, ...)
│   ├── fallback.rs     — CPU fallback: cpu_assign_instances, cpu_collect_lk_and_shardram
│   └── test_helpers.rs — Test utilities: assert_witness_colmajor_eq, assert_full_gpu_pipeline
└── mod.rs              — Module declarations + lk_shardram integration tests (19 tests)
```

### Data Flow

```
                    Pass 1: PreflightTracer
                    ┌──────────────────────┐
                    │  ShardPlanBuilder     │ → shard boundaries
                    │  addr_future_accesses │ → next-access HashMap (GPU cache reads and sorts before H2D)
                    └──────────┬───────────┘
                               │
                    Pass 2: FullTracer (per shard)
                    ┌──────────▼───────────┐
                    │  Vec<StepRecord>      │ 136 bytes/step, #[repr(C)]
                    └──────────┬───────────┘
                               │ H2D (cached per shard in cache.rs)
                    ┌──────────▼───────────────────────────────────┐
                    │              GPU Per-Instruction              │
                    │  ┌─────────────┬──────────────┬────────────┐ │
                    │  │ F-1 Witness │ F-2 LK Count │ F-3 EC/Addr│ │
                    │  │ (col-major) │  (atomics)   │ (shared buf)│ │
                    │  └──────┬──────┴──────┬───────┴─────┬──────┘ │
                    └─────────┼─────────────┼─────────────┼────────┘
                              │             │             │
                      GPU transpose    D2H counters   flush at shard end
                              │             │             │
                    ┌─────────▼─────────────▼─────────────▼────────┐
                    │                 CPU Merge                     │
                    │  RowMajorMatrix  LkMultiplicity  ShardContext │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │           ShardRamCircuit (GPU)               │
                    │  Phase 1: per-row Poseidon2 (344 cols)       │
                    │  Phase 2: binary EC tree (layer-by-layer)    │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                                     Proof Generation
```

### Per-Shard Pipeline

Within `generate_witness()` (e2e.rs), each shard executes:

1. **upload_shard_steps_cached** — H2D `Vec<StepRecord>` (cached, shared across all chips)
2. **ensure_shard_metadata_cached** — H2D shard scalars + allocate shared EC/addr buffers
3. **Per-chip dispatch** — `gpu_fill_witness` matches `GpuWitgenKind` → 22 kernel variants
   - Each kernel writes: witness columns (col-major), LK counters (atomics), EC records + addr (shared buffers)
4. **flush_shared_ec_buffers** — D2H shared EC records + addr_accessed into `ShardContext`
5. **invalidate_shard_steps_cache** — Free GPU shard_steps memory
6. **assign_shared_circuit** — ShardRamCircuit GPU pipeline (Poseidon2 + EC tree)

### GPU/CPU Decision (dispatch.rs)

```
try_gpu_assign_instances():
  1. is_gpu_witgen_enabled()?          → CPU fallback if not set
  2. is_force_cpu_path() thread-local? → CPU fallback (debug comparison)
  3. I::GPU_LK_SHARDRAM == false?      → CPU fallback
  4. is_kind_disabled(kind)?           → CPU fallback
  5. Field != BabyBear?                → CPU fallback
  6. get_cuda_hal() unavailable?       → CPU fallback
  7. All pass                          → GPU path
```

### Keccak Dispatch

Keccak has a dedicated GPU dispatch path (`chips/keccak.rs::gpu_assign_keccak_instances`)
separate from `try_gpu_assign_instances` because:
1. **Rotation**: each instance spans 32 rows (not 1), requiring `new_by_rotation`
2. **Structural witness**: 3 selectors (sel_first/sel_last/sel_all) vs the standard 1
3. **Input packing**: needs `packed_instances` with `syscall_witnesses`

The LK/shardram collection logic is identical to the standard path.

### Lk and Shardram Collection

After GPU computes the witness matrix, LK multiplicities and shard RAM records
are collected through one of several paths (priority order):

| Path | Witness | LK Multiplicity | Shard Records | When |
|------|---------|-----------------|---------------|------|
| **A** Shared buffer | GPU | GPU counters → D2H | Shared GPU buffer (deferred) | Default for all verified kinds |
| **B** Compact EC | GPU | GPU counters → D2H | Compact EC D2H per-kernel | Older non-shared-buffer kinds |
| **C** CPU shardram | GPU | GPU counters → D2H | CPU `cpu_collect_shardram` | GPU shard unverified |
| **D** CPU full | GPU | CPU `cpu_collect_lk_and_shardram` | CPU full | GPU LK unverified |
| **E** CPU only | CPU | CPU `assign_instance` | CPU `assign_instance` | GPU unavailable |

Currently all non-Keccak kinds use **Path A**. Paths B-E are fallback/debug paths.

## E2E Pipeline Modes (e2e.rs)

```
create_proofs_streaming()
│
├─ Default GPU backend (CENO_GPU_ENABLE_WITGEN unset):
│   Overlap pipeline:
│     Thread A (CPU): witgen(shard 0) → witgen(shard 1) → witgen(shard 2) → ...
│     Thread B (GPU): ................prove(shard 0) → prove(shard 1) → ...
│     crossbeam::bounded(0) rendezvous channel for back-pressure
│
└─ CENO_GPU_ENABLE_WITGEN=1 (GPU witgen) or CPU-only build:
    Sequential pipeline:
      witgen(shard 0) → prove(shard 0) → witgen(shard 1) → prove(shard 1) → ...
      GPU shared between witgen and proving; no overlap possible.
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CENO_GPU_ENABLE_WITGEN` | unset (CPU witgen) | Set to enable GPU witness generation. Sequential witgen+prove pipeline. |
| `CENO_GPU_DISABLE_WITGEN_KINDS` | none | Comma-separated kind tags to disable specific chips' GPU path. Example: `add,keccak,lw`. Falls back to CPU for those chips. |
| `CENO_GPU_DEBUG_COMPARE_WITGEN` | unset | Enable GPU vs CPU comparison for all chips. Runs both paths and diffs results. |

### `CENO_GPU_DEBUG_COMPARE_WITGEN` Coverage

When set, the following comparisons run automatically:

**Per-chip (in dispatch.rs, for each opcode circuit):**
- `debug_compare_final_lk` — GPU LK multiplicity vs CPU `assign_instance` baseline (all 8 lookup tables)
- `debug_compare_witness` — GPU witness matrix vs CPU witness (element-by-element, col-major vs row-major)
- `debug_compare_shardram` — GPU shard records (read_records, write_records, addr_accessed) vs CPU
- `debug_compare_shard_ec` — GPU compact EC records vs CPU-computed EC points (nonce, x[7], y[7])

**Per-chip, Keccak-specific (in chips/keccak.rs):**
- `debug_compare_keccak` — Combined witness + LK + shard comparison for keccak's rotation-aware layout

**Per-shard, E2E level (in e2e.rs):**
- `log_shard_ctx_diff` — Full shard context comparison after all opcode circuits (addr_accessed, read/write records across all chips merged)
- `log_combined_lk_diff` — Merged LK multiplicities after `finalize_lk_multiplicities()` (catches cross-chip merge issues)

All comparisons output to stderr via `eprintln!` / `tracing::error!`, with a default limit of 16 mismatches per category.

## Tests

**79 tests total** (`cargo test --features gpu,u16limb_circuit -p ceno_zkvm --lib -- "gpu"`)

| Category | Count | Location | What it tests |
|----------|------:|----------|---------------|
| Column map extraction | 33 | `chips/*.rs` (31 via `test_colmap!` macro + 2 manual) | Circuit config → column map: all IDs in-range and unique |
| GPU witgen correctness | 23 | `chips/*.rs` | GPU kernel output vs CPU `assign_instance` (element-by-element witness comparison) |
| LK+shardram match | 19 | `gpu/mod.rs` | `collect_lk_and_shardram` / `collect_shardram` vs `assign_instance` baseline |
| LkOp encoding | 1 | `utils/mod.rs` | `LkOp::encode_all()` produces correct table/key pairs |
| EC point match | 1 | `scheme/septic_curve.rs` | GPU Poseidon2+SepticCurve EC point vs CPU `to_ec_point` |
| Poseidon2 sponge | 1 | `scheme/septic_curve.rs` | GPU Poseidon2 permutation vs CPU |
| Septic from_x | 1 | `scheme/septic_curve.rs` | GPU `septic_point_from_x` vs CPU |

### Running Tests

```bash
# All GPU tests (requires CUDA device)
CENO_GPU_ENABLE_WITGEN=1 cargo test --features gpu,u16limb_circuit -p ceno_zkvm --lib -- "gpu"

# Column map tests only (no CUDA device needed)
cargo test --features gpu,u16limb_circuit -p ceno_zkvm --lib -- "test_extract_"

# LK/shardram tests only (no CUDA device needed)
cargo test --features gpu,u16limb_circuit -p ceno_zkvm --lib -- "lk_shardram"

# With debug comparison enabled
CENO_GPU_ENABLE_WITGEN=1 CENO_GPU_DEBUG_COMPARE_WITGEN=1 cargo test --features gpu,u16limb_circuit -p ceno_host -- test_elf
```

## Per-Chip Boilerplate Macros

Three macros in `instructions.rs` reduce per-chip GPU integration to ~3 lines:

```rust
impl Instruction<E> for MyChip {
    // Emit LK ops + shard RAM records (CPU companion for GPU witgen)
    impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
        emit_u16_limbs(sink, step.rd().unwrap().value.after);
    });

    // Collect shard RAM records only (when GPU handles LK)
    impl_collect_shardram!(r_insn);

    // GPU dispatch: try GPU → fallback CPU
    impl_gpu_assign!(dispatch::GpuWitgenKind::Add);
}
```
