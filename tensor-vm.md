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
  -> Attention(x0, HintRef(profile, layer 0, role, tile)) -> a0
  -> Ffn(a0, HintRef(profile, layer 0, role, tile)) -> x1
  -> ...
  -> Ffn(aN-1, HintRef(profile, layer N-1, role, tile)) -> xN
EXPORT_END(xN) -> output RAM
```

`TensorRef = (segment_id, local_tensor_slot, version)` is not a guest pointer.
Each v2 attention/FFN call reads one input TensorRef, allocates a fresh output
TensorRef, and identifies weights by
`HintRef = (profile, layer, role, tile_index)`. The production v2 descriptor has
no guest `hint_base`. The HintRef relation remains proof-authoritative; GPU
generation, staging, and caching use the same logical identity but are never
trusted.

Only the imported input and exported final output are outer TensorBus boundary
values. Attention outputs, FFN outputs, residuals, norms, and temporaries are
segment-private Tensor-space values. The resident-block Core constrains their
read/write chain in one MLE/table, while attention and FFN chips constrain
their Tensor-space I/O, fixed hint reads, and arithmetic/lookup/quantization.

The physical provider ping-pongs two device buffers (`x` and `a`) across the
block. It uploads only x0 and downloads only xN; device buffers and witnesses
never enter the guest ABI. Preflight expands all internal chip costs and logical
HintRef ranges from `(profile, layer_count)` before atomically admitting the
block to a shard. This is the architecture for guest-selected 2/4/8/16 inner
unroll capacity tests and the eventual 32-layer topology.

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

The production design replaces one scalar-output ECALL per output coordinate
with one compact row ECALL per output row. The row record is keyed by shard,
segment, operation ordinal, and row index; rows for one matrix operation must be
ordered, duplicate-free, and cover `0..M`. They share operation, shape,
TensorRef, and HintRef identities, write disjoint ranges of one output
TensorRef, and are coalesced into one tiled GPU GEMM. Row records are execution
descriptors, not copies of A or W and not TensorBus boundary events.

The exact production call-count projection is:

| Scope | Scalar-output ECALLs | Row ECALLs | Reduction |
|---|---:|---:|---:|
| One Llama-2-7B/2048 layer | 229,638,144 | 145,408 | 1,579x |
| 32 layers plus LM head | 7,413,956,608 | 4,655,104 | 1,593x |

This changes call and witness representation, not the required arithmetic. One
production layer still contains 448,824,082,432 matrix multiplications. Under
the former scalar Core specifically, projections alone expanded to 87,031,808
output-dot/finalize rows and 406,847,488 K1024 tile rows. Each tile row carried
at least 2,048 `input_raw` plus 1,024 `input_neg_carry` fields, so those two
fields alone extrapolated to 4.547 TiB. The batched design removes that
materialized scalar-product witness: larger M, K, and N increase MLE height and
matrix-sumcheck work instead of multiplying circuit columns by K or N.

The implemented `llama-tiny` gate proves the shared trace and reduction shape;
it is not yet the general production row-descriptor/provider implementation.
One tiny section stores complete 2x2 A, W, quotient Q, and remainder R matrices
in four logical rows, rather than materializing one row per `(m,n,k)` product.
Repeated guest/operator calls append complete four-row sections to the same
registered Core trace. The focused resident guest makes two calls, so its eight
logical rows need no padding; in general `4 * sections` rows are padded to the
next power of two.

The arithmetic payload uses 26 witness fields: signed A, W, and Q values with
magnitude/sign decompositions, plus R and its sixteen canonical bits. The
resident Tensor-space/HintRef integration adds fifteen identity, ordering, and
routing fields, for 41 committed MatMul WitIn MLEs. Five structural columns bind
physical row order, the three matrix terminal points, and the ordinary prefix;
they do not grow with K, N, or section count. A, W, Q, and R remain at stable
local WitIn columns 0, 3, 6, and 9.

The available scalar-versus-batched evidence has different scopes and is kept
explicit rather than normalized into a synthetic benchmark:

| Metric | Former scalar production extrapolation | Final tiny architecture-B gate |
|---|---:|---:|
| ECALL/row scale | 87,031,808 projection output dots and 406,847,488 K1024 tile rows per layer | 2 complete calls, 8 logical and 8 padded Core rows |
| MatMul-owned committed MLEs | not recorded | 41 WitIn MLEs |
| MatMul columns | exact total not recorded; two arrays alone used 3,072 fields per tile row | 41 WitIn plus 5 structural columns |
| Materialized witness | at least 4.547 TiB for the two named arrays | compact A/W/Q/R plus identity/routing fields; byte total not separately recorded |
| Setup/keygen time | unavailable for this extrapolation | unavailable for the final fixture |
| Witness/base-proving time | unavailable for this extrapolation | pass recorded; isolated time unavailable |
| Peak memory | at least the 4.547-TiB materialization before other fields | 409-MiB CUDA pool peak |

The production row-ECALL projections above are workload counts, while the right
column is the actually executed 2x2 proof gate. Production-width setup, proving,
and peak-memory comparisons remain future measurements.

Signed/range constraints, canonical `0 <= R < 2^16`, ECALL-to-Core
consistency, physical/logical row ordering, and the offline product relations
remain ordinary first-layer constraints in the existing batched-main flow. The
Core is read-only for offline-memory accounting, like other consumer-only
ecalls: for resident rows it reads the operator claim, input Tensor-space value,
and HintRef value. The handle ECALL writes the matching operator claim and fresh
output Tensor-space version; IMPORT writes the initial version, EXPORT reads the
final version, and the HintRef Core writes each unique logical tile value once.
Inactive conditional reads use the existing `Undefined` neutral record. Thus
the Core does not invent a compensating write, and one producer/one consumer
balances every active relation.

The circuit-scoped auxiliary matrix sumcheck proves

```text
Q(output_point) * 2^16 + R(output_point)
  = sum_(k, section) A(k, m, section) * W(n, k, section)
      * eq(output_section_point, section)
```

The left side is the auxiliary sumcheck's `claimed_sum`; its own verifier uses
it as the initial sum and checks the terminal A/W product evaluation. This
equality-weighted reduction batches all padded complete sections. It returns A
and W evaluations at their respective terminal points and Q/R evaluations at
the shared output point. The MatMul first GKR layer registers three groups,
`[A]`, `[W]`, and `[Q,R]`. For the unchanged batched-main challenge powers, the
prover, native verifier, and recursion replay append the same four correction
monomials:

```text
-alpha_A * A_claim * eq(A_point, x)
-alpha_W * W_claim * eq(W_point, x)
-alpha_Q * Q_claim * eq(output_point, x)
-alpha_R * R_claim * eq(output_point, x)
```

These terms bind the matrix terminal claims through the existing main
sumcheck's final evaluation. They do not add or replace a tower layer, change
the batched-main protocol or round count, or alter the legacy ordinary-chip
claim flow. `main_out_evals` remains empty. Batched-main reduces the four
semantic columns at its ordinary global point, and the original single WitIn
PCS opening against the existing `witin_commit` authenticates them. There are
zero Matrix-specific PCS rounds and no separate tensor commitment.

The final architecture-B real-guest GPU E2E passed Mock proving, real base
proving, and independent native Rust verification with one atomic shard, two
MatMul sections, eight HintRef rows, one ordinary WitIn opening, logical
H2D/D2H of 16/16 bytes, and zero intermediate transfers. It rejected HintRef
identity/value, Tensor slot/version, injected ordinary main-output, matrix
product, quotient, remainder, and recovered-main-claim tampering. The recorded
CUDA pool peak was 409 MiB. The fresh proof was 994,605 bytes and its VK was
139,010,634 bytes. Separate setup/keygen, witness-generation, base-proving,
native-verification, recursion, and peak-host-memory measurements were not
recorded for this final architecture-B fixture and remain unavailable rather
than inferred from superseded runs.

Only after the independent Rust verifier passed was that same proof/VK fixture
replayed by recursion-v2. Basefold PoW validation remained intact, the four
selector-equality corrections and legacy main claimed sum were constrained,
and the focused constraint/LogUp check completed with:

```text
recursion-v2 app replay constraints verified: proofs=1 matrix_chips=1
```

This milestone proves compact MatMul trace ownership, the auxiliary reduction,
fusion into batched-main, the original single opening, native verification, and
recursion replay. It does not yet implement a complete tiny transformer layer,
general production row descriptors/providers, authenticated model weights, or
the production attention schedule.

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
