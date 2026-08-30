# Tensor VM: Device-Resident TensorBus Execution

## Goal

Support Llama-style tensor execution without treating every intermediate tensor
as ordinary RISC-V memory. Consecutive tensor operators execute on GPU, retain
their intermediate values and reusable witnesses on device, and remain fully
constrained by Ceno proof relations.

The initial target is a device-resident attention -> FFN chain. The first
performance gate is K4096 MatMul GPU syscall execution with proof-witness
reuse. K11008 and larger-model work begin only after that gate passes.

## Core distinction

There are two independent memory domains.

```text
RISC-V RAM bus                         TensorBus
------------                           ---------
scalar control                         tensor handles and versions
syscall arguments                      tensor metadata
explicit materialization               TensorRead/TensorWrite records
public values                          device-resident tensor values
```

Ordinary RISC-V execution continues to use the existing RAM records. Tensor
intermediates use TensorBus; they do not become guest-memory bytes merely
because one tensor syscall feeds another.

## Tensor segment boundary

Use an explicit generated-guest/runtime boundary, not a heuristic based on
memory contents. A segment is primarily a scheduling and residency scope; it
does not initially need to be one giant AIR block.

```text
normal RISC-V code
    |
    | tensor_import(input_ptr, meta)
    |   RAM -> TensorBus / DeviceTensor
    v
tensor_attention_handle(x) -> a
tensor_ffn_handle(a)       -> b
tensor_attention_handle(b) -> c
    |
    | tensor_export(c, output_ptr, meta)
    |   TensorBus / DeviceTensor -> RAM
    v
normal RISC-V code
```

The segment establishes device-cache lifetime, TensorBus namespace, ordering,
and eviction scope. It allows later physical fusion of adjacent operations.

## ABI

Keep the existing pointer ABI for compatibility and add a handle ABI for
generated Tensor VM guests.

```text
Existing pointer ABI
tensor_matmul(in_ptr, weight_ptr, out_ptr, ...)

Tensor-handle ABI
tensor_import(input_ptr, meta) -> TensorId
tensor_matmul_handle(input, weight_id, meta) -> TensorId
tensor_attention_handle(input, layer, meta) -> TensorId
tensor_ffn_handle(input, layer, meta) -> TensorId
tensor_export(input, out_ptr, meta)
```

Pointer ABI calls read and write normal RISC-V RAM. They may use GPU internally
but must materialize output to `out_ptr`.

Handle ABI calls consume and produce TensorBus values. The guest only sees
opaque handles, dimensions, flags, and status codes. The host/runtime maps the
handle to host or device storage; device pointers never enter the guest ABI.

## TensorBus records

```rust
struct TensorId(u64);

struct TensorMeta {
    shape: SmallVec<[u32; 4]>,
    layout: TensorLayout,
    quant: TensorQuantization,
}

struct TensorWriteRecord {
    tensor_id: TensorId,
    version: u32,
    meta: TensorMeta,
    producer: TensorSyscallId,
    order: u64,
    digest: Option<TensorDigest>,
}

struct TensorReadRecord {
    tensor_id: TensorId,
    version: u32,
    meta: TensorMeta,
    consumer: TensorSyscallId,
    order: u64,
}
```

Required invariants:

- A read matches one prior write with the same ID, version, and metadata.
- Tensor versions are single-assignment unless an explicit mutable operation is
  introduced.
- Record order is derived from the existing syscall ordinal.
- A TensorBus value becomes RAM only through explicit materialization.
- Records are emitted whether a value is host-resident or device-resident.

The initial proof relation can be Ceno-style offline/tower consistency over
compact TensorBus records. Do not commit every ephemeral tensor separately.

## Residency-aware host runtime

```rust
enum TensorStorage {
    Host(HostTensor),
    Device(DeviceTensor),
}

struct TensorValue {
    id: TensorId,
    version: u32,
    meta: TensorMeta,
    storage: TensorStorage,
    witness: Option<TensorWitnessHandle>,
}

struct TensorGpuExecution {
    output: DeviceTensor,
    witness: TensorWitnessHandle,
    metrics: TensorExecutionMetrics,
}
```

A GPU provider accepts a host or device tensor. Host input uploads once;
device input is reused. GPU output remains device-resident by default. D2H is
allowed only for explicit materialization, public/scalar extraction, eviction,
or CPU fallback.

The GPU output is never trusted. It is reused only as assignment witness data;
the existing AIR and proof verification remain authoritative.

## Transfer policy

Naive execution is not acceptable:

```text
CPU tensor -> H2D -> GPU op -> D2H -> next syscall
```

Desired execution:

```text
Host X
  -> H2D once
  -> GPU Attention -> Device A + witness A
  -> GPU FFN       -> Device B + witness B
  -> optional D2H only at tensor_export
```

There must be zero intermediate D2H/H2D transfers between consecutive handle
syscalls within a segment.

Weights use a separate cache path:

```text
quantized hint bytes -> pinned host buffer -> async H2D tile -> GPU cache
                   -> inference and witness generation -> budgeted eviction
```

Do not permanently field-expand all model weights.

## Tensor lifetime policy

| Scope | Example | Treatment |
|---|---|---|
| Ephemeral | attention output -> FFN input | TensorBus records and shared device witness |
| Segment-shared | residual across fused blocks | TensorBus consistency claim |
| Persistent | KV cache or external boundary | digest/commitment plus TensorBus consistency |
| Materialized | final logits or output | TensorBus -> RISC-V RAM bridge |

The design principle is: commit according to tensor lifetime, not operator
boundary.

## Resident blocks: Tensor space and hint space

For multi-layer resident execution, Tensor space is the internal activation
plane and hint space is the model-weight plane. Guest RAM is only a boundary:

```text
IMPORT_BEGIN(input RAM) -> Tensor x0
  -> Attention(x0, hint_base, layer 0) -> a0
  -> Ffn(a0, hint_base, layer 0) -> x1
  -> ...
  -> Ffn(aN-1, hint_base, layer N-1) -> xN
EXPORT_END(xN) -> output RAM
```

`TensorRef = (segment_id, local_tensor_slot, version)` is not a guest pointer.
Each attention/FFN chip reads an input TensorRef, derives fixed hint-space
weight addresses from `(hint_base, layer, profile, role, tile_index)`, and
writes a fresh TensorRef. The hint-read relation remains proof-authoritative;
GPU staging/caching uses the same derived tile identities but is never trusted.

Only the imported input and exported final output are outer TensorBus boundary
values. Attention outputs, FFN outputs, residuals, norms, and temporaries are
segment-private Tensor-space values. The resident-block Core constrains their
read/write chain in one MLE/table, while attention and FFN chips constrain
their Tensor-space I/O, fixed hint reads, and arithmetic/lookup/quantization.

The physical provider ping-pongs two device buffers (`x` and `a`) across the
block. It uploads only x0 and downloads only xN; device buffers and witnesses
never enter the guest ABI. Preflight expands all internal chip costs and fixed
hint ranges from `(hint_base, layer_count, profile)` before atomically admitting
the block to a shard. This is the architecture for guest-selected 2/4/8/16
inner unroll capacity tests and the eventual 32-layer topology.

### zkLLM-compatible Llama-2-7B/2048 workload

The fair zkLLM comparison is a batch-one, full-sequence forward/prefill over
2048 input tokens. It is not one-token decoding against a 2048-token KV cache.
Every layer therefore computes Q, K, and V for all 2048 rows and proves the
full `[32 heads, 2048 queries, 2048 keys]` causal-attention domain. A cached
one-token decode remains a separate benchmark track.

The production workload uses Llama-2-7B dimensions `hidden=4096`, `heads=32`,
`head_dim=128`, `intermediate=11008`, and `layers=32`. It connects the existing
K4096/K11008 dot-product relations into complete batched matrices and includes
RMSNorm, Q/K/V/O projections, RoPE, causal masking, segmented zkLLM softmax,
residuals, gate/up/down projections, SwiGLU, and all Q16/Q20 rescaling and
remainder relations. The complete Ceno pass additionally includes embedding,
final RMSNorm, LM head, and final-position argmax. Report both transformer-core
time and complete-pass time because the released zkLLM layer driver does not
provide an equivalent embedding-through-argmax executable.

The comparison authority is the CCS Table 1 experiment: Q16 data/model scaling,
five size-2^16 attention tlookups, sequence 2048, and its stated proving-time
boundary. The archived refactored demo is an operator-reference implementation,
not the authority for reproducing Table 1 timing. Report Ceno's proof-bound
RoPE, causal mask, non-interactive transcript, and argmax as stricter additions.

For the compute-only milestone, external tensors use logical HintRefs derived
from `(model_profile, layer, role, tile_index)` rather than guest virtual
addresses. The guest does not pass `hint_base`. A lazy deterministic fixture
provider generates weight tiles on demand and supplies them as unauthenticated
private witnesses. Each logical HintRef is product-bound once and reused by all
consumers, so unauthenticated does not permit inconsistent per-read weights.
The resulting arbitrary weight polynomial is committed through the ordinary
per-shard Ceno witness commitment, and every inner chip is bound to that same
polynomial. Arithmetic and workload commitment are therefore valid relative to
the committed witness, but no model root or public seed authenticates it as
Llama weights. This deliberate model-identity unsoundness is acceptable for the
compute benchmark and must be disclosed. Lazy generation removes 25.10-GiB
guest-hint materialization only; it must not be counted as authenticated model
loading or real weight-bandwidth performance.

All inner relations remain ordinary deterministically registered Ceno Core
chips. Their instances, columns, proofs, openings, transcript order, verifier,
and recursion path stay inside each shard's existing `ZKVMWitnesses`,
`chip_proofs`, and witness commitment. `IMPORT_BEGIN ... EXPORT_END` remains an
atomic segment; multiple complete segments may batch into Core MLE sections and
shards cut only between segments. Full attention may tile/stream heads, K/Q
blocks, lazy weights, and proof scratch inside the segment to remain below 16
GiB, but it may not reduce the logical 32x2048x2048 workload or spill an
intermediate activation across the Tensor-space boundary.

### Stage-1 batched matrix proof milestone

The `llama-tiny` stage-1 implementation replaces the scalar output-dot proof
shape with one complete-matrix guest call per Core section. This distinction is
material: extrapolating the old scalar path to one exact production layer would
require 87,031,808 output-dot/finalize calls, 406,847,488 K1024 tile rows, and
at least 4.547 TiB for only the `input_raw` and `input_neg_carry` witness
fields. Those scalar counts are no longer the implementation plan; production
dimensions still require later matrix/attention providers and are not claimed
complete by this tiny gate.

One tiny section commits a complete 2x2 A, W, quotient, and remainder relation
in four logical rows, rather than one row per `(m,n,k)` multiplication. The Core
has 26 witness columns independent of the section count. A, W, Q, and R occupy
stable local columns 0, 3, 6, and 9; a verifier-known repeating structural
column binds logical rows to physical MLE row order. Repeated guest calls append
complete four-row sections to the same registered Core trace. The focused guest
makes two calls, hence one eight-row Core with two sections.

The matrix relation is a circuit-scoped auxiliary reduction analogous in
placement to rotation proof replay. It batches all complete sections, leaves
the existing tower and batched-main sumchecks unchanged, and derives exactly
three additional A, W, and output opening points. The ordinary WitIn round and
these three rounds all open every committed witness polynomial against the same
shard `witin_commit`; native verification locates the four semantic columns by
deterministic circuit order and rejects nonzero point tails. GPU Jagged opening
streams evaluations trace-by-trace, so the extra rounds do not collect all
witness MLE columns on the host.

The real-guest focused GPU E2E passed with two sections, exactly three
same-commitment rounds, independent native verification, and independent
product, quotient, and remainder proof-tamper rejection. The final run reported
a 553-MiB CUDA pool peak. Its GPU-produced proof and VK were then replayed by
recursion-v2 with Basefold PoW validation intact; the focused constraint and
LogUp check completed with:

```text
recursion-v2 app replay constraints verified: proofs=1 matrix_chips=1
```

This milestone proves the compact matrix-proof ownership, opening, native
verification, and recursion path. It does not yet implement a complete tiny
transformer layer, a production-width matrix provider, authenticated model
weights, or the production attention schedule.

The decode track, when implemented later, applies the same HintRef mechanism to
external K/V cache tensors and reports one-token-at-context-2048 separately.
The zkLLM-compatible prefill track has no input KV-cache hint: its K/V tensors
are produced by the 2048-row Q/K/V projections inside the proved workload.

## Implementation campaign

### Phase 0: baseline instrumentation

Measure CPU preflight arithmetic, CPU orchestration, H2D/D2H bytes, GPU
inference, GPU witness assignment, GPU proving, device-cache hits/misses, and
peak device memory separately.

### Phase 1: transitional GPU syscall provider

Implement GPU MatMul while preserving the pointer ABI. It returns a normal
materialized output plus a reusable `TensorWitnessHandle`. Differential-test it
against the CPU provider and prove the same AIR/public values.

### Phase 2: handle ABI and CPU reference TensorBus

Add `tensor_import`, handle operators, and `tensor_export`. Implement a
CPU-only TensorBus runtime first to validate records, versions, ordering, and
materialization semantics.

### Phase 3: TensorBus proof consistency

Add TensorRead/TensorWrite consistency to the proof flow. Start with compact
offline/tower records. Persistent state gets a digest/commitment later; avoid
PCS commitments for every ephemeral intermediate.

### Phase 4: device-resident attention -> FFN

Add GPU execution producing both `DeviceTensor` and `TensorWitnessHandle`.
Pass device handles directly between attention and FFN. Preserve exact Q16/Q20,
lookup, masking, RoPE, argmax, ordered syscall records, and AIR constraints.

### Phase 5: fused physical execution

Implement `ATTENTION_BLOCK` and `FFN_BLOCK` physical paths. Logical TensorBus
records remain compatible with unfused calls, while temporary score, softmax,
and activation tensors remain local device witnesses.

### Phase 6: multi-layer device segment

Run 1, 4, 8, then 32 layers device-resident. Logical batching remains governed
by Ceno shard cuts; physical device residency may stream layer weights and
witness tiles without changing proof semantics.

## Acceptance criteria

- CPU preflight does no dense tensor arithmetic for supported GPU syscalls.
- GPU syscall output and witness are reused by assignment; tensor arithmetic is
  not recomputed for proving.
- Consecutive handle syscalls perform zero intermediate D2H/H2D transfers.
- TensorBus consistency is verified independently of normal RISC-V RAM.
- `tensor_export` reproduces existing guest RAM semantics.
- CPU and GPU providers have identical outputs, public values, and verified
  proof semantics.
- K4096 GPU syscall inference and witness reuse pass before K11008 work.
- Reduced 32-layer topology reports inference time, proof time, transfer bytes,
  peak VRAM, token/s, and incremental ZKP cost.

## Non-goals of the first stage

- Do not move ordinary RISC-V RAM to GPU.
- Do not replace the current pointer ABI.
- Do not commit every intermediate tensor individually.
- Do not implement committed-model/KV-cache authentication before the
  single-segment device-resident path is correct.
- Do not benchmark K11008 or Llama-7B throughput while tensor providers are
  CPU-only.
