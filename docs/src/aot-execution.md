# AOT Execution Architecture

Ceno's x86-64 AOT backend has two user-visible execution paths:

- **Pure** executes guest values for diagnostics and benchmarking. It preserves
  guest registers, memory, output, exit status, traps, syscalls, and retired
  instruction count, but does not produce proof-compatible access accounting.
- **Full** runs the production preflight path, then replays the finalized plan
  with `FullTracer` to produce step records and syscall witnesses.

Both paths compile statically reachable RISC-V basic blocks into a shared
object. Unsupported instructions, guarded memory cases, dynamic targets,
interior block entry, capacity proximity, and exceptional transitions return
to the scalar Rust path.

## Training and cache identity

`cargo ceno build` asks LLVM to emit `.llvm_bb_addr_map`. The ELF loader
validates its version, features, addresses, alignment, block sizes, metadata,
and callsite return PCs. These workload-independent roots are always admitted
as possible AOT entries, including blocks that the training input does not
execute.

Coverage training still interprets the program once to discover dynamic
targets and post-syscall continuations, count block and branch frequency, and
choose a stable block layout. Production training also sizes the next-access
tape and binds the artifact to the active shard-cost model. The cache key
includes the program and static-root digest, target, AOT ABI, emission style,
layout digest, shard limits, and planner fingerprint where applicable.

Generated-code changes must update the private cache identity or ABI metadata.
On a cache hit, Ceno validates metadata, the shared-object digest, block layout,
and planner identity before loading it. Missing, corrupt, or incompatible
artifacts are rebuilt rather than executed.

## Runtime ABI and block admission

The generated object receives a versioned runtime context containing the guest
register file, packed dense memory, program and dispatch state, tracing state,
planner tables, next-access tape cursors, and fallback counters. Offset tests
keep handwritten assembly synchronized with the Rust layout.

Production preflight admits a block only when its complete transition is safe:

- the instruction budget covers the whole block;
- planner descriptors remain in the current generation and below their bucket
  ceilings;
- the block stays within shard cell and cycle limits;
- the next-access tape has enough capacity;
- affine memory accesses do not wrap, are aligned, and remain inside one valid
  region; and
- execution enters at the block leader through a supported transition.

An admission failure does not weaken validation. It selects exact scalar
execution, which handles bucket crossings, shard splits, memory slow paths,
syscalls, traps, and dynamic control flow.

## Resident state and planner accounting

After admission, generated code may keep the register base, dense-memory base,
and memory ordinal base in callee-saved host registers. The block cannot call
Rust before its guarded exit, so this state remains valid. Cold exits and
fallbacks publish the guest PC and refresh shard-local resident state before
native execution resumes.

Planner table bases are loaded once per admitted accounting sequence. Every
descriptor still checks its generation, adds its exact instance delta, checks
the cached bucket ceiling, and rolls back before the slow path if admission
fails. Shard boundaries remain owned by the preflight planner.

## Memory events and shard-capacity handoff

Packed dense-memory cells store the guest value with its latest-access
instruction ordinal. Native loads and stores reconstruct exact subcycles,
update latest access state, and append cross-shard register and memory events
in canonical order. Heap, stack, and hint extrema are reconstructed from the
validated access stream after production execution.

Finalized preflight boundaries determine both the shard count and the maximum
number of steps in any shard. That maximum is carried as `FullTracerConfig`
with the emulation result. Replay validates boundary ordering, alignment,
coverage, shard count, and maximum size before allocating exactly one pending
record beyond the largest shard. This prevents one-step-buffer exhaustion
without allocating for the entire execution.

## Replay and syscalls

Full replay reuses the trained block layout but has a distinct cache entry. It
emits canonical `StepRecord`s and latest-access state directly, while Rust owns
unsupported transitions and syscall witness construction. Public-data crypto
kernels may execute in the host fast path, but their memory-operation order,
witnesses, invalid-input behavior, infinity and parity rules, and overlapping
buffer fallback must match the generic syscall implementation.

## Benchmarking requirements

Benchmark only warm cached artifacts, pin comparable runs to the same CPU, and
use separate cache identities for control and candidate binaries. Report
training, compilation, loading, native execution, and fallback time separately.
Alternate control and candidate samples and require identical guest output,
instruction and cycle totals, full boundary vectors, event order, witnesses,
and replay results. Pure numbers are diagnostic and must never be presented as
proof-compatible Full results.
