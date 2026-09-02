# Iteration 189 — provider/boundary ownership trace (pre-mutation)

## Task and gates

This iteration owns the TensorVM provider/boundary Custom/RAM counterpart repair.
The required gates are: source-backed ownership fix preserving record identities,
bounded `MOCK_PROVING=1` shard 0, then shard-0 proof plus independent Rust
verification, and only then the complete multi-shard E2E. No PIOP, PCS,
transcript, TensorBus, RAM semantics, guest ABI, or verifier relaxation is in
scope.

## Source-backed diagnosis before mutation

The iteration-188 mock log reports missing `production_qk_q_read`,
`production_qk_k_read`, `production_pv_v_read_once`, projection-boundary tensor
writes, and boundary state writes. The aggregate deltas are Memory
17,039,360 and Custom 9,175,041.

The QK/PV cores create row-level Custom TensorState reads in
`ceno_zkvm/src/instructions/riscv/ecall/tensor_production_attention_matrix.rs`
(`production_qk_q_read`, `production_qk_k_read`, and
`production_pv_v_read_once`). Their counterparts must be row-level Custom
writes with the same tensor id/version/index/value. The fused provider path in
`ceno_emul/src/vm_state.rs::tensor_production_stage_execute` returns only the
output vector and `ProductionFullLayerOperationRecord` metadata. That metadata
contains operation shape/role/tile identity, not per-row TensorState records,
and no caller converts it into Custom writes.

The stage anchor in
`ceno_zkvm/src/instructions/riscv/ecall/tensor_production_attention.rs` emits
only the compact TensorBus event/call record. The boundary cores emit endpoint
records and the RAM journal; the projection stage has no row-level provider
producer chip. Therefore the missing Q/K/V counterpart is not a stale RAM slot
or a future-shard flag: the fused provider removed the old row producer while
the matrix AIR retained row-level reads. Adding synthetic writes in the mock or
changing reads into self-balancing writes would be unsound.

The projection-boundary write/read samples are a second manifestation of the
same ownership gap: boundary rows are produced by the host RAM import/export
path, while the fused provider's intermediate tensors never receive a
canonical row-level producer record. Memory mismatches must still be traced
against `StepRecord::has_future_access` and shard ownership; they cannot be
silently ignored as cross-shard balancing.

## Criterion mapping before mutation

* Preserve record identities: requires a real producer carrying complete
  row-level values; operation metadata alone is insufficient.
* Preserve TensorBus/RAM semantics: do not fabricate provider records or alter
  RAM future-access rules without an exact source mapping.
* Mock/verifier integrity: must remain unchanged.
* E2E gate: cannot validly run until the missing producer is implemented.

## Proposed smallest sound change

First determine whether the existing fused provider can expose a complete
row-level operation ledger (tensor id, version, index, value, and ordering) at
the stage witness. If it cannot, the required fix is a materially new
provider-to-Custom-record architecture, outside this iteration's authority;
the correct result is CHANGES_REQUIRED rather than fabricated records. If it
can, add exactly one canonical provider-owned producer path consumed by the
existing Custom record accumulator, preserving all existing record tuples.

No source mutation has been made at this point.

## Terminal evaluation

The source trace confirms that a sound repair requires extending the provider
witness/record interface with complete row-level TensorState producer data (or
reintroducing a dedicated producer ecall/chip). That is a new record
architecture, not a provider-side assignment correction. The available
`ProductionFullLayerOperationRecord` cannot support it: its fields are only
`import_cycle`, layer, role, token range, output columns, and tile.

Accordingly no mutation, build, MOCK_PROVING run, shard proof, or multi-shard
E2E was performed. Running those gates with the current AIR would only repeat
the known invalid ownership mismatch. Existing evidence remains the iteration
188 mock log at
`/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-mock.log` (SHA
`91af02ce7feb35a63f9944d0db2d690a0993bd314d466297620bdff9876ddd9d`).

Verdict: **CHANGES_REQUIRED**. Exact next action: authorize a dedicated
provider-to-Custom row-ledger seam or restore a real TensorState producer chip;
then rerun the bounded mock before any verifier/E2E gate.
