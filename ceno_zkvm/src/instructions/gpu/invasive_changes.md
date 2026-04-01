# GPU Witness Generation — Invasive Changes to Existing Codebase

This document lists all changes to **existing** ceno structures, traits, and flows
that this PR introduces. GPU-only new code (`instructions/gpu/`) is excluded —
this focuses on what existing code was modified and why.

---

## 1. `ceno_emul` — FFI Layout Changes (+332 / -88 lines)

### `#[repr(C)]` on emulator types

The following types were made `#[repr(C)]` to enable zero-copy H2D transfer to GPU:

| Type | File | Size | Purpose |
|------|------|------|---------|
| `StepRecord` | `tracer.rs` | 136B | Per-step emulator output, bulk H2D |
| `Instruction` | `rv32im.rs` | 12B | Opcode encoding embedded in StepRecord |
| `InsnKind` | `rv32im.rs` | 1B | `#[repr(u8)]` enum discriminant |
| `MemOp<T>` | `tracer.rs` | 16/24B | Read/Write ops embedded in StepRecord |
| `Change<T>` | `tracer.rs` | 2×T | Before/after pair |

**Impact**: These were previously `#[derive(Debug, Clone)]` with compiler-chosen layout.
Adding `#[repr(C)]` pins field order and padding. No behavioral change for CPU code,
but **field reordering or insertion now requires updating the CUDA mirror structs**.

### Layout test

`test_step_record_layout_for_gpu` verifies byte offsets of all `StepRecord` fields
at compile time. CUDA side has matching `static_assert(sizeof(...))`.

---

## 2. `Instruction<E>` Trait — New Methods and Constants

**File**: `ceno_zkvm/src/instructions.rs`

| Addition | Purpose |
|----------|---------|
| `const GPU_LK_SHARDRAM: bool = false` | Opt-in flag: does this chip have GPU LK+shardram support? |
| `fn collect_lk_and_shardram(...)` | CPU companion: collect all LK multiplicities + shard RAM records (without witness replay) |
| `fn collect_shardram(...)` | CPU companion: collect shard RAM records only (GPU handles LK) |

**Default implementations** return `Err(...)` — chips must explicitly opt in.

**Impact**: Existing chips that don't implement GPU support are unaffected (defaults).
The trait's existing `assign_instance` and `assign_instances` are unchanged.

Three macros reduce per-chip boilerplate:
- `impl_collect_lk_and_shardram!` — wraps the unsafe `CpuLkShardramSink` prologue
- `impl_collect_shardram!` — one-line delegate to insn_config
- `impl_gpu_assign!` — `#[cfg(feature = "gpu")] assign_instances` override

---

## 3. Gadgets — New `emit_lk_and_shardram` / `emit_shardram` Methods

**File**: `ceno_zkvm/src/instructions/riscv/insn_base.rs` (+253 lines)

Every base gadget (`ReadRS1`, `ReadRS2`, `WriteRD`, `ReadMEM`, `WriteMEM`, `MemAddr`)
gained two new methods:

| Method | What it does |
|--------|-------------|
| `emit_lk_and_shardram(sink, ctx, step)` | Emit LK ops + RAM send events through `LkShardramSink` |
| `emit_shardram(shard_ctx, step)` | Directly write shard RAM records to `ShardContext` (no LK) |

**Impact**: Additive only — existing `assign_instance` methods are unchanged.
The new methods extract the same logic that `assign_instance` performed inline,
but route through the `LkShardramSink` trait instead of directly calling
`lk_multiplicity.assert_ux(...)`.

### Intermediate configs (`r_insn.rs`, `i_insn.rs`, `b_insn.rs`, `s_insn.rs`, `j_insn.rs`, `im_insn.rs`)

Each gained corresponding `emit_lk_and_shardram` / `emit_shardram` methods that
compose their gadgets' methods + emit `LkOp::Fetch`.

---

## 4. Per-Chip Circuit Files — GPU Opt-in (+792 / -129 lines across ~20 files)

Each v2 circuit file (arith.rs, logic_circuit.rs, div_circuit_v2.rs, etc.) gained:

```rust
const GPU_LK_SHARDRAM: bool = true;  // or conditional match

impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
    // chip-specific LK ops
});
impl_collect_shardram!(r_insn);
impl_gpu_assign!(dispatch::GpuWitgenKind::Add);
```

**Impact**: Additive — existing `assign_instance` and `construct_circuit` unchanged.
The `#[cfg(feature = "gpu")] assign_instances` override is only compiled with the
`gpu` feature flag.

---

## 5. `ShardContext` — New Fields and Methods

**File**: `ceno_zkvm/src/e2e.rs` (+616 / -199 lines)

### New methods

| Method | Purpose |
|--------|---------|
| `new_empty_like()` | Clone shard metadata with empty record storage (for debug comparison) |
| `insert_read_record()` / `insert_write_record()` | Direct record insertion (GPU D2H path) |
| `push_addr_accessed()` | Direct addr insertion (GPU D2H path) |

### Renamed method

`send()` → split into `record_send_without_touch()` (no addr_accessed tracking) and
`send()` (which calls `record_send_without_touch` + `push_addr_accessed`).

### Pipeline hooks (in `generate_witness` shard loop)

```rust
#[cfg(feature = "gpu")]
flush_shared_ec_buffers(&mut shard_ctx);  // D2H shared GPU buffers

#[cfg(feature = "gpu")]
invalidate_shard_steps_cache();  // free GPU memory
```

### Pipeline mode (in `create_proofs_streaming`)

New overlap pipeline (default when GPU feature enabled but `CENO_GPU_ENABLE_WITGEN` unset):
CPU witgen on thread A, GPU prove on thread B, connected by `crossbeam::bounded(0)` channel.

---

## 6. `ZKVMWitnesses` — GPU ShardRam Pipeline

**File**: `ceno_zkvm/src/structs.rs` (thin wrapper only)

### `assign_shared_circuit` — GPU fast path

`try_assign_shared_circuit_gpu()` delegates to `gpu/chips/shard_ram::try_gpu_assign_shared_circuit()`.
The full GPU pipeline logic and `gpu_ec_records_to_shard_ram_inputs` conversion have been
moved to `instructions/gpu/` — `structs.rs` only contains the wrapper that inserts results
into `self.witnesses`.

Two helper methods made `pub(crate)` for GPU access: `mem_addresses()`, `make_cross_shard_record()`.

---

## 7. `ShardRamCircuit` — GPU Witness Generation

**File**: `ceno_zkvm/src/tables/shard_ram.rs` (+491 / -14 lines)

### New GPU functions

| Function | Purpose |
|----------|---------|
| `try_gpu_assign_instances()` | H2D path: CPU records → GPU kernel → D2H witness |
| `try_gpu_assign_instances_from_device()` | Device path: records already on GPU → kernel → D2H |

Both run a two-phase GPU pipeline:
1. **Per-row kernel**: basic fields + Poseidon2 trace (344 witness columns)
2. **EC tree kernel**: layer-by-layer binary tree EC summation

### Visibility change

`ShardRamConfig` fields changed from private to `pub(crate)` to allow
column map extraction in `gpu/chips/shard_ram.rs`.

---

## 8. `SepticCurve` — New Math Utilities

**File**: `ceno_zkvm/src/scheme/septic_curve.rs` (+307 lines)

New CPU-side math for EC point computation (mirrored in CUDA):

| Function | Purpose |
|----------|---------|
| `SepticExtension::frobenius()` | Frobenius endomorphism for norm computation |
| `SepticExtension::sqrt()` | Cipolla's algorithm for field square roots |
| `SepticPoint::from_x()` | Lift x-coordinate to curve point (used by nonce-finding loop) |
| `QuadraticExtension<F>` | Auxiliary type for Cipolla's algorithm |

---

## 9. Minor Touches

| File | Change |
|------|--------|
| `Cargo.toml` | `gpu` feature flag, `crossbeam` dependency |
| `gkr_iop/src/gadgets/is_lt.rs` | `AssertLtConfig.0.diff` field access (already `pub`) |
| `gkr_iop/src/utils/lk_multiplicity.rs` | Minor: `LkMultiplicity::increment` |
| `ceno_zkvm/src/gadgets/signed_ext.rs` | `pub(crate) fn msb()` accessor for GPU column map |
| `ceno_zkvm/src/gadgets/poseidon2.rs` | Column contiguity constants for GPU |
| `ceno_zkvm/src/tables/*.rs` | `pub(crate)` visibility on config fields for GPU column map access |
| `ceno_zkvm/src/scheme/{cpu,gpu,prover,verifier}` | Minor plumbing for GPU proving path |
| `ceno_host/tests/test_elf.rs` | E2E test adjustments |

---

## Summary

| Category | Nature | Risk |
|----------|--------|------|
| `#[repr(C)]` on emulator types | Layout pinning | Low — additive, but field changes now need CUDA sync |
| `Instruction<E>` trait extensions | Additive (defaults provided) | None — existing chips unaffected |
| Gadget `emit_*` methods | Additive | None — existing `assign_instance` unchanged |
| `ShardContext` new methods | Additive | Low — existing methods unchanged |
| `send()` → `record_send_without_touch()` + `send()` | Rename + split | Low — `send()` still works identically |
| `ShardRamConfig` visibility | `private` → `pub(crate)` | None |
| Pipeline overlap mode | New default behavior | Medium — CPU witgen + GPU prove on separate threads |
| `septic_curve.rs` math | Additive | None — new functions, existing unchanged |
