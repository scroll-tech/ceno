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
