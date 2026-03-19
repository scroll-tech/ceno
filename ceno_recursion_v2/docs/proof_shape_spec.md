# Proof Shape Module Spec

This spec summarizes the components under `src/proof_shape`. The module is forked from upstream recursion code so we can
adapt it to Ceno’s ZKVM while keeping behavior aligned with OpenVM.

## ProofShapeModule (`src/proof_shape/mod.rs`)

### Purpose

- Verify child-proof trace metadata (heights, cached commits, public values) against the child verifying key.
- Route transcript/bus traffic related to those checks (power/range lookups, permutation commitments, GKR cross-module
  messages).
- Produce CPU (and optional CUDA) traces for the ProofShape and PublicValues AIRs, plus aggregate preflight info used
  later in recursion.

### Key Fields

- `per_air: Vec<AirMetadata>`: built from `RecursionVk.circuit_vks` in circuit-index order; currently stores
  `is_required = false`, `num_public_values = instance_openings().len()`, placeholder widths (`main_width = 0`,
  `cached_widths = vec![0; max_cached]`), and read/write/log lookup counts (`num_read_count`, `num_write_count`,
  `num_logup_count`) used by the GKR checks.
- Cached/commit parameters are currently fixed in `ProofShapeModule::new`: `min_cached_idx = 0`, `max_cached = 2`,
  `commit_mult = 100`.
- `idx_encoder`: enforces permutation ordering between `idx` (VK order) and `sorted_idx` (runtime order).
- Bus handles: power/range checker, proof-shape permutation, starting tidx, number of public values, GKR module,
  air-shape, expression-claim, fraction-folder, hyperdim lookup, lifted heights, commitments, transcript, n_lift, cached
  commit.

### Tracegen Flow

1. Build `ProofShapeChip::<4,8>` (CPU) / GPU equivalent, parameterized by cached-commit bounds and range/power checker
   handles.
2. Gather context (`StandardTracegenCtx`) of `(vk, proofs, preflights)` and produce row-major traces for both ProofShape
   and PublicValues airs.
3. Preflight builder (`Preflight::populate_proof_shape`) collects sorted trace metadata, starting tidx values, cached
   commits, and transcript positions for public values; these feed back into recursion aggregates.

### Module Interactions

- Sends/receives bus messages enumerated in the AIR sections below.
- `ProofShapeModule::new` wires buses via `BusIndexManager`; `commit_child_vk` commits the child VK once per recursion
  instance (currently unimplemented while ZKVM wiring is in progress).

## ProofShapeAir (`src/proof_shape/proof_shape/air.rs`)

### Column Groups

| Group                       | Columns                                                                | Notes                                                                                   |
|-----------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| Row selectors               | `proof_idx`, `is_valid`, `is_first`, `is_last`, `is_present`           | Manage per-proof iteration and summary row detection.                                   |
| Ordering & metadata         | `idx`, `sorted_idx`, `log_height`, `height`, `need_rot`, `num_present` | Track VK ordering vs runtime order, enforce height monotonicity, rotation requirements. |
| Transcript anchors          | `starting_tidx`, `starting_cidx`                                       | Anchor where per-air transcript reads start; exported via buses.                        |
| Height decomposition        | `height_limbs[NUM_LIMBS]`                                              | Enforce limb decomposition/range checks for `height`.                                   |
| Hyperdim summary            | `n_max`, `is_n_max_greater`, `num_air_id_lookups`, `num_columns`       | Track max `log_height` across present AIRs and auxiliary per-air lookup counts.         |
| Cached commit bookkeeping   | `cached_idx_flags`, `cached_idx_value`, `cached_commits`               | Track how many cached columns exist and their transcript tidx positions.                |
| Bookkeeping for permutation | Encoder-specific subcolumns (idx flags) verifying sorted order.        

### Constraints Overview

- **Looping**: `NestedForLoopSubAir<1>` runs per proof, iterating through `idx` values and ensuring `is_valid`+`is_last`
  drive transitions.
- **Permutation**: `ProofShapePermutationBus` enforces that runtime order (`sorted_idx`) is a permutation of VK order (
  `idx`). `idx_encoder` ensures only one row per column and enforces boolean flags.
- **Trace heights**: Range checker ensures `log_height` is monotonically non-increasing; when `is_present = 1`,
  `height = 2^{log_height}`. Hyperdim bus uses unsigned `n = log_height` (`n_abs = n`, `n_sign_bit = 0`).
- **Rotation/caching**: Rows with `need_rot = 1` record rotation requirements on `CommitmentsBus` and `CachedCommitBus`.
  `starting_cidx`/`starting_tidx` communicate the first column/ transcript offset for each AIR.
- **Expression lookups**: `ExpressionClaimNMaxBus`, `FractionFolderInputBus`, and `NLiftBus` mirror the computed
  `n_logup`, `n_max`, and `n_lift = log_height` metadata so batch constraint and fraction-folder modules can cross-check
  expectations. `AirShapeBus` exposes additional per-AIR properties (`NumRead`, `NumWrite`, `NumLk`) so GKR AIRs can
  enforce that their runtime layer counts match the verifying-key declarations. `NumInteractions` is currently emitted
  as
  `0` in this AIR.

### Bus Interactions

- Sends on: `ProofShapePermutationBus`, `HyperdimBus`, `LiftedHeightsBus`, `CommitmentsBus`, `ExpressionClaimNMaxBus`,
  `FractionFolderInputBus`, `NLiftBus`, `StartingTidxBus`, `NumPublicValuesBus`, `CachedCommitBus` (if continuations
  enabled).
- Receives from: `ProofShapePermutationBus` (VK order), `TowerModuleBus` (per-proof configuration), `AirShapeBus`
  (per-air property lookups, including the new `NumRead` / `NumWrite` / `NumLk` counters that downstream GKR AIRs
  enforce), `PowerCheckerBus` (for PoW enforcement), `RangeCheckerBus` (monotonic log heights),
  `TranscriptBus` (sample/observe tidx-aligned data), `CachedCommitBus` (continuations), `CommitmentsBus` (when reading
  transcript commitments).

### Summary Row Logic

On the row with `is_last = 1`, additional checks happen:

- Emit final `n_logup/n_max` via `ExpressionClaimNMaxBus` and `NLiftBus`.
- Update `ProofShapePreflight` fields in the transcript (tracked via tidx) so future recursion layers know where
  ProofShape stopped reading.

## PublicValuesAir (`src/proof_shape/pvs/air.rs`)

### Columns

| Column                                 | Description                                               |
|----------------------------------------|-----------------------------------------------------------|
| `is_valid`                             | Row selector; invalid rows carry padding data.            |
| `proof_idx`, `air_idx`, `pv_idx`       | Identify the proof/AIR/public-value index triple.         |
| `is_first_in_proof`, `is_first_in_air` | Lower-level loop markers used for sequencing constraints. |
| `tidx`                                 | Transcript cursor for the public value read.              |
| `value`                                | The actual public value field element.                    |

### Constraints

- `NestedForLoopSubAir<1>` enforces that enabled rows form contiguous `(proof_idx, air_idx)` segments and increments
  `pv_idx` and `tidx` appropriately when staying within the same AIR.
- On `is_first_in_proof`, enforce `pv_idx = 0` and `tidx = starting_tidx` supplied via preflights/ProofShape module.
- For padding rows, force `proof_idx = num_proofs` to match upstream convention.

### Interactions

- `PublicValuesBus.send`: publishes each `(air_idx, pv_idx, value)` pair so downstream modules can replay the values;
  optionally doubled when `continuations_enabled`.
- `NumPublicValuesBus.receive`: on first-in-air rows, ingests `(air_idx, tidx, num_pvs)` to cross-check counts derived
  from ProofShape.
- `TranscriptBus.receive`: ensures the transcript sees the same public values at the given `tidx` (read-only).

## Trace Generators

- `ProofShapeChip::<NUM_LIMBS, LIMB_BITS>` (CPU) and module-level tracegen wiring are currently placeholders in this
  branch, producing zero-filled traces with the requested height while AIR wiring stabilizes.
- `ProofShapeChipGpu`/CUDA ABI wrappers remain available behind feature gates.
- `PublicValuesTraceGenerator` walks each proof’s `public_values` arrays, emits `(proof_idx, air_idx, pv_idx)` rows,
  pads to powers of two, and records transcript progression.
- CUDA ABI wrappers (`cuda_abi.rs`) expose raw tracegen entry points for GPU builds.

## Preflight & Metadata

- `ProofShapePreflight` stores the sorted trace metadata, per-air transcript anchors (`starting_tidx`), cached commit
  tidx list, and summary scalars (`n_logup`, `n_max`).
- During transcript preflight (`ProofShapeModule::preflight`), the module replays transcript interactions (observing
  cached commitments, sampling challenges) and writes the preflight struct for later modules (e.g., GKR) to consume.
