# Iteration 188 — TensorVM record ownership diagnosis

## Scope

Bounded diagnosis of the mock TensorVM Custom/RAM mismatch. Preserve record
identities, TensorBus/RAM semantics, guest ABI, PIOP/PCS/transcript, equations,
and the head-1 matrix-reducer boundary. No full E2E was run in this task.

## Evidence and source trace

The mock log is `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-mock.log`.
It reports Memory multiplicity delta `17,039,360`, and among Custom mismatches:

* PV V read raw tuple starts `[2,1,532,2,0,0,524288,0]`.
* PV probability read starts `[2,1,532,3,0,2,1,268434910]`.
* Softmax probability write at the corresponding sample has the same identity
  prefix but a different value, with the first mismatch at row 1.
* Projection boundary writes are also unmatched, but are a separate producer
  ownership issue.

The PV AIR in
`ceno_zkvm/src/instructions/riscv/ecall/tensor_production_attention_matrix.rs`
defines `v_key = tile*128 + row_low7` for the V tensor, but defines the
probability key as `key = tile*128 + axis`. The CUDA implementation in
`../ceno-gpu/cpp/common/witgen/production_attention_matrix.cuh` used one shared
`key = tile*128 + row_low7` for both. Consequently physical row 1 queried
softmax cell 0 in CUDA while the circuit's Custom probability record queried
cell 1. This is an assignment bug, not padding or a verifier relaxation issue.

The QK/PV circuits have no `collect_shardram` implementation because their
Custom records are circuit witness records, not ordinary ShardRAM slots. The
GPU compact EC path only reconstructs Register/Memory slots in
`ceno_zkvm/src/instructions/gpu/utils/d2h.rs`; it cannot legitimately create
Custom counterparts. The provider's `operation_records` are currently
validated metadata in `ceno_emul/src/tensor/production_attention.rs` and are
not converted into Custom record writes. Therefore projection/QK/V producer
counterparts must not be fabricated as local records in this task.

## Mutation

Changed only the PV CUDA witness coordinate. The final corrected code uses
separate `probability_key = tile*128 + axis` and `v_key = tile*128 + row_low7`:

```diff
- uint32_t key = tile * 128u + row_low7;
+ uint32_t probability_key = tile * 128u + axis;
+ uint32_t v_key = tile * 128u + row_low7;
```

The probability lookup uses `probability_key`; the V load uses `v_key`. This
restores the AIR probability read/write identity without changing names,
namespaces, equations, or TensorBus/RAM behavior.

## Verification

Started:

```text
CARGO_TARGET_DIR=/home/wusm/data/cargo_tmp \
TMPDIR=/home/wusm/data/cargo_tmp/tmp \
cargo check -p cuda_hal --features cuda --release
```

The corrected CUDA HAL check passed in 1m05s (log SHA-256
`f11c3cba64d341dcf2e120321abc0281771f4a66854da9846afbd0c9e9555a2b`). The
accepted production binary rebuild passed in 1m46s (build log SHA-256
`786f29d08d2e6a2d0ca02fad4f35a66a19220a788faf8c2c9c7aad554e665fc3`; binary
SHA-256 `7d89cb62f09cba796364701455266e0a7cff27d1bcc553a86a56793b10d25eb4`).

One bounded mock command used `CENO_GPU_CACHE_LEVEL=full`,
`CENO_MAX_CELLS_PER_SHARD=6000000000`, `CENO_TARGET_SHARD_ID=0`,
`MOCK_PROVING=1`, `CENO_TENSOR_E2E_RW_TRACE=1`, and `RUST_LOG=info`. It exited
101 after diagnostics in 2:38.70 with `found 52428271 r/w mismatch errors`.
Log SHA-256: `91af02ce7feb35a63f9944d0db2d690a0993bd314d466297620bdff9876ddd9d`.
The log contains zero `production_pv_probability_read` or
`production_softmax_probability_write` mismatches. Remaining aggregate deltas
are Memory `17039360` and Custom `9175041`; sampled classes are Projection/
Attention boundary Memory writes, QK q/k Custom reads, PV V Custom reads, and
projection boundary Custom tensor/state writes. No verifier/full-layer run was
performed because the mock gate failed.

## Criterion verdicts

1. Producer/consumer mapping: **PARTIAL** — PV probability producer/consumer
   coordinate mismatch proven; projection/QK provider counterpart ownership is
   separately unresolved.
2. Minimal implementation: **PASS for PV coordinate** — one CUDA assignment
   expression changed; no semantic interface changed.
3. Bounded mock: **FAIL** — PV probability mismatch disappeared, but remaining
   Memory/Custom ownership mismatches remain.
4. Real shard proof/verifier: **NOT RUN** — gate 3 and provider ownership gate
   are not clean.

## Diff identity

The ceno-gpu owned file final SHA-256 is
`ca7e8ecff2654073ae3cea4e08f995d10d5275d97ed30a4f0a26ea835b157270`;
no ceno root source file was changed by this task.

## Next action

Root should authorize or replan a separate provider-side canonical Custom
counterpart design before any shard verifier or full-layer E2E. Do not fabricate
local counterparts.

## Post-fix verification (authoritative)

The corrected two-key CUDA diff is:

```diff
- uint32_t key = tile * 128u + row_low7;
+ uint32_t probability_key = tile * 128u + axis;
+ uint32_t v_key = tile * 128u + row_low7;
...
- probabilities[..., key]; projected_v[key * stride + ...]
+ probabilities[..., probability_key]; projected_v[v_key * stride + ...]
```

The CUDA HAL release check passed. The rebuilt production binary was run once
with `MOCK_PROVING=1` and exited 101 after diagnostics. Log:
`/home/wusm/data/cargo_tmp/logs/iteration-188-pv-key-mock.log`; SHA-256
`91af02ce7feb35a63f9944d0db2d690a0993bd314d466297620bdff9876ddd9d`.
There were no `production_pv_probability_read` or
`production_softmax_probability_write` mismatches. Remaining Custom
multiplicity mismatch is exactly `9,175,041`; the run’s total is `52,428,271`.

Terminal verdict: **CHANGES_REQUIRED**. The PV probability assignment is fixed,
but provider/boundary counterpart ownership remains unresolved; shard verifier
and full-layer E2E are correctly gated.
