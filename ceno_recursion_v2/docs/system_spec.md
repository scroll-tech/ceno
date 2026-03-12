# System Module Spec

This document summarizes the aggregation layer under `src/system`. The code mirrors upstream `recursion_circuit::system` but is forked so we can swap in ZKVM verifying keys (`RecursionVk`).

## Type Aliases (`src/system/types.rs`)
- `RecursionField = BabyBearExt4` and `RecursionPcs = Basefold<RecursionField, BasefoldRSParams>` unify ZKVM field choices across the crate.
- `RecursionVk = ZKVMVerifyingKey<RecursionField, RecursionPcs>` replaces the upstream `MultiStarkVerifyingKey` so future traits accept ZKVM proofs/VKs natively.
- `RecursionProof = ZKVMProof<RecursionField, RecursionPcs>` is the canonical proof type exposed to modules; `convert_proof_from_zkvm` is the shim that turns it into OpenVM's `Proof<BabyBearPoseidon2Config>` right before legacy logic runs.

## Preflight Records (`src/system/preflight.rs`)
- Local fork of the upstream `Preflight`/`ProofShapePreflight`/`GkrPreflight` structs so we can evolve transcript layout and bookkeeping independently of OpenVM.
- Only the fields that current modules need are mirrored (trace metadata, tidx checkpoints, transcript log, Poseidon inputs). Additional upstream functionality stays commented out until required.

## Frame Shim (`src/system/frame.rs`)
- Local copy of upstream `system::frame` because the originals are `pub(crate)`.
- Provides `StarkVkeyFrame` and `MultiStarkVkeyFrame` structs used by modules (e.g., ProofShape) when exposing verifying-key metadata to AIRs.
- Each frame strips non-deterministic data (only clones params, cached commitments, interaction counts) to keep AIR traces stable.

## POW Checker Constant
- `POW_CHECKER_HEIGHT: usize = 32` mirrors the upstream constant so modules (ProofShape, batch-constraint) can type-check their `PowerChecker` gadgets without reaching into a private upstream module.

## GlobalCtxCpu Override (`src/system/mod.rs`)
- The upstream `GlobalCtxCpu` binds `TraceGenModule` to `[Proof<BabyBearPoseidon2Config>]`. We shadow it locally with a struct of the same name that implements `GlobalTraceGenCtx` but sets `type MultiProof = [RecursionProof]`.
- This keeps all CPU tracegen entry points on ZKVM proofs while leaving the trait definitions untouched; CUDA tracegen continues to use the upstream GPU context.

## VerifierTraceGen Trait
Located at `src/system/mod.rs:28`.

Responsibilities:
1. `new(child_vk, config) -> Self`: build the recursive subcircuit using the child verifying key and the user-provided `VerifierConfig`.
2. `commit_child_vk(engine, child_vk)`: write commitments for the child verifying key into the proof transcript.
3. `cached_trace_record(child_vk)`: return the global cached-trace metadata used to skip regeneration when proofs repeat.
4. `generate_proving_ctxs(...)`: orchestrate per-module trace generation (transcript, proof shape, GKR, batch constraint) and collect `AirProvingContext`s, possibly using cached shared traces.
5. `generate_proving_ctxs_base(...)`: helper that synthesizes a default `VerifierExternalData` (empty poseidon/range inputs, no required heights) and calls the trait method.

The trait is generic over both the prover backend (`PB`) and the Stark protocol configuration (`SC`), enabling CPU/GPU backends.

## VerifierSubCircuit (`src/system/mod.rs:90`)
Fields capture the stateful modules that participate in recursive verification:
- `bus_inventory: BusInventory`: record of allocated buses ensuring consistent indices.
- `bus_idx_manager: BusIndexManager`: allocator used when wiring modules.
- `transcript: TranscriptModule`: handles Fiat–Shamir transcript operations across the entire recursion proof.
- `proof_shape: ProofShapeModule`: enforces child trace metadata (see `proof_shape_spec.md`).
- `gkr: GkrModule`: verifies the GKR proof emitted by the child STARK (see `docs/gkr_air_spec.md`).
- `batch_constraint: BatchConstraintModule`: enforces batched polynomial constraints tying transcript data to concrete AIRs.

### Trait Implementation Status
- All trait methods (`new`, `commit_child_vk`, `cached_trace_record`, `generate_proving_ctxs`, `AggregationSubCircuit::airs/next_bus_idx`) are currently `unimplemented!()` placeholders because the ZKVM refactor is still in progress. The struct exists so copied modules compile and we can iteratively fill in logic.

## AggregationSubCircuit Impl
- `airs()` will eventually return a vector of `AirRef`s covering the transcript module, proof-shape submodule, batch-constraint module, and GKR submodule. Keeping the method stubbed allows the rest of the crate to reference it while we port logic.
- `bus_inventory()` already returns a reference to the internal inventory so upstream orchestration code can inspect bus handles.
- `next_bus_idx()` will source fresh bus IDs via `BusIndexManager`; currently stubbed.
- `max_num_proofs()` is functional and returns the const generic bound used by aggregation provers.

## How Modules Fit Together
1. **TranscriptModule** absorbs all Fiat–Shamir sampling/observations (PoW, alpha, lambda, mu, sumcheck evaluations). Other modules refer to transcript locations via shared tidx counters.
2. **ProofShapeModule** reads the child proof metadata and emits bus messages for GKR and batch-constraint modules (height summaries, cached commitments, public values, etc.).
3. **GkrModule** consumes those messages plus the child GKR proof to verify the folding of claims (see separate spec).
4. **BatchConstraintModule** checks algebraic constraints across all AIRs (e.g., Poseidon compression tables, sumcheck gadgets) using the same buses.
5. **VerifierSubCircuit** orchestrates these modules: it shares `BusInventory`, ensures every module gets consistent handles, and sequences trace generation so transcript state advances consistently.

## Pending Work / Notes
- ZKVM proof objects now flow through every CPU tracegen module; `VerifierSubCircuit::commit_child_vk` still needs adapters that hash the ZKVM verifying key into the transcript before we can run end-to-end.
- Bus wiring currently happens upstream; replicating it locally may require copying additional files if upstream keeps types `pub(crate)`.
- All module constructors should remain aligned with upstream layout to minimize future rebase conflicts; prefer small local wrappers over structural rewrites.
