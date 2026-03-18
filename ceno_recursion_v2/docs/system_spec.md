# System Module Spec

This document summarizes the aggregation layer under `src/system`. The code mirrors upstream `recursion_circuit::system`
but is forked so we can swap in ZKVM verifying keys (`RecursionVk`).

## Type Aliases (`src/system/types.rs`)

- `RecursionField = BabyBearExt4` and `RecursionPcs = Basefold<RecursionField, BasefoldRSParams>` unify ZKVM field
  choices across the crate.
- `RecursionVk = ZKVMVerifyingKey<RecursionField, RecursionPcs>` replaces the upstream `MultiStarkVerifyingKey` so
  future traits accept ZKVM proofs/VKs natively.
- `RecursionProof = ZKVMProof<RecursionField, RecursionPcs>` is the canonical proof type exposed to modules;
  `convert_proof_from_zkvm` / `convert_vk_from_zkvm` are bridge placeholders and currently `unimplemented!()`.

## Preflight Records (`src/system/preflight.rs`)

- Local fork of the upstream `Preflight`/`ProofShapePreflight`/`GkrPreflight` structs so we can evolve transcript layout
  and bookkeeping independently of OpenVM.
- Only the fields that current modules need are mirrored (trace metadata, tidx checkpoints, transcript log, Poseidon
  inputs). Additional upstream functionality stays commented out until required.

## Frame Shim (`src/system/frame.rs`)

- Local copy of upstream `system::frame` because the originals are `pub(crate)`.
- Provides `StarkVkeyFrame` and `MultiStarkVkeyFrame` structs used by modules (e.g., ProofShape) when exposing
  verifying-key metadata to AIRs.
- Each frame strips non-deterministic data (only clones params, cached commitments, interaction counts) to keep AIR
  traces stable.

## POW Checker Constant

- `POW_CHECKER_HEIGHT: usize = 32` mirrors the upstream constant so modules (ProofShape, batch-constraint) can
  type-check their `PowerChecker` gadgets without reaching into a private upstream module.

## GlobalCtxCpu Override (`src/system/mod.rs`)

- The upstream `GlobalCtxCpu` binds `TraceGenModule` to `[Proof<BabyBearPoseidon2Config>]`. We shadow it locally with a
  struct of the same name that implements `GlobalTraceGenCtx` but sets `type MultiProof = [RecursionProof]`.
- This keeps all CPU tracegen entry points on ZKVM proofs while leaving the trait definitions untouched; CUDA tracegen
  continues to use the upstream GPU context.

## VerifierTraceGen Trait

Located at `src/system/mod.rs:28`.

Responsibilities:

1. `new(child_vk, config) -> Self`: build the recursive subcircuit using the child verifying key and the user-provided
   `VerifierConfig`.
2. `commit_child_vk(engine, child_vk)`: write commitments for the child verifying key into the proof transcript.
3. `generate_proving_ctxs(...)`: orchestrate per-module trace generation (transcript, proof shape, main, GKR), run
   preflights, and collect `AirProvingContext`s.
4. `generate_proving_ctxs_base(...)`: helper that synthesizes a default `VerifierExternalData` (empty poseidon/range
   inputs, no required heights) and calls the trait method.

The trait is generic over both the prover backend (`PB`) and the Stark protocol configuration (`SC`), enabling CPU/GPU
backends.

## VerifierSubCircuit (`src/system/mod.rs:90`)

Fields capture the stateful modules that participate in recursive verification:

- `bus_inventory: BusInventory`: record of allocated buses ensuring consistent indices.
- `bus_idx_manager: BusIndexManager`: allocator used when wiring modules.
- `transcript: TranscriptModule`: handles Fiat–Shamir transcript operations across the entire recursion proof.
- `proof_shape: ProofShapeModule`: enforces child trace metadata (see `proof_shape_spec.md`).
- `main_module: MainModule`: validates main-module constraints and participates in tracegen orchestration.
- `gkr: GkrModule`: verifies the GKR proof emitted by the child STARK (see `docs/gkr_air_spec.md`).

### Trait Implementation Status

- `VerifierTraceGen` is implemented for CPU: `new`, `commit_child_vk`, `generate_proving_ctxs`, and
  `generate_proving_ctxs_base` are active.
- `AggregationSubCircuit` methods `airs`, `bus_inventory`, `next_bus_idx`, and `max_num_proofs` are active.
- Remaining placeholders are bridge converters in `src/system/types.rs` (`convert_proof_from_zkvm`,
  `convert_vk_from_zkvm`) and selected module internals that are intentionally stubbed while wiring stabilizes.

## AggregationSubCircuit Impl

- `airs()` returns a full list of `AirRef`s from transcript, proof-shape, main, GKR, plus power-checker and
  exp-bits-len AIRs.
- `bus_inventory()` returns a reference to the internal inventory so orchestration code can inspect bus handles.
- `next_bus_idx()` returns the current allocator cursor via `BusIndexManager`.
- `max_num_proofs()` returns the const generic bound used by aggregation provers.

## How Modules Fit Together

1. **TranscriptModule** absorbs all Fiat–Shamir sampling/observations (PoW, alpha, lambda, mu, sumcheck evaluations).
   Other modules refer to transcript locations via shared tidx counters.
2. **ProofShapeModule** reads the child proof metadata and emits bus messages for downstream modules (
   height summaries, cached commitments, public values, etc.).
3. **MainModule** enforces core verifier constraints linked to transcript/proof-shape outputs.
4. **GkrModule** consumes those messages plus the child GKR proof to verify the folding of claims (see separate spec).
5. **VerifierSubCircuit** orchestrates these modules: it shares `BusInventory`, ensures every module gets consistent
   handles, and sequences trace generation so transcript state advances consistently.

## Current Semantics Note

- The older system-level implication check relating child trace-height constraints to a
  `sum(num_interactions * lifted_height) < max_interaction_count` bound is currently commented out in
  `VerifierSubCircuit::new_with_options`.
- In the current ProofShape AIR, hyperdim is unsigned (`n = log_height`, `n_sign_bit = 0`) and
  `AirShapeProperty::NumInteractions` is emitted as `0`.

## Pending Work / Notes

- ZKVM proof objects now flow through every CPU tracegen module; `VerifierSubCircuit::commit_child_vk` still needs
  end-to-end bridge converters (`convert_proof_from_zkvm` / `convert_vk_from_zkvm`) are still pending.
- Bus wiring currently happens upstream; replicating it locally may require copying additional files if upstream keeps
  types `pub(crate)`.
- All module constructors should remain aligned with upstream layout to minimize future rebase conflicts; prefer small
  local wrappers over structural rewrites.
