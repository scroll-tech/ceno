# Ceno AOT Execution/Tracing Contract

## Semantic modes

The AOT pipeline has three deliberately separate modes:

1. **Pure execution** is a benchmark-only diagnostic floor. It preserves guest
   registers, memory values, public output, exit code, fallback behavior, and
   retired guest-instruction count. It does not build latest-access state,
   next-access tape, shard plans, trace values, witnesses, or proofs and must
   never be presented as proof-compatible.
2. **Production Preflight** preserves the complete proof-facing planning state:
   global cycles, exact latest accesses, canonical next-access tape, memory
   ranges, per-chip costs, and shard boundaries. Its target is at most 5.0s on
   block 25580200, including native execution and required Rust fallbacks but
   excluding cached-artifact construction.
3. **FullTracer replay** consumes the Preflight plan and emits canonical step
   and syscall witnesses. It must remain replay-compatible with the interpreter
   and is not interchangeable with either execution-only mode.

The pure target is at most 3.0s for block 25580200. If pure execution reaches
that target, production bookkeeping has a 2.0s budget. If pure execution is
still slower than 3.0s, code generation and guest-instruction reduction remain
higher priority than redesigning proof tracking.

## Timing and artifact contract

Assembly generation, C compiler/linker work, shared-library loading, coverage
training, and cold cache population are setup metrics. They must be reported
separately and excluded from both the 3.0s pure and 5.0s warm Preflight gates.
A measured execution sample starts immediately before entry into the cached
native artifact and stops after the artifact and all required fallbacks return.
Pure reports split total execution into native time and fallback time, identify
fallback counts by reason and ecall, and include the AOT ABI/cache identity.

Performance comparisons use five warm, alternating samples, cached block input
and AOT artifacts, fixed CPU affinity, and recorded CPU model, online CPUs,
frequency governor, revisions, build profile, and feature flags. Report mean,
median, every raw sample, guest instructions/second, and peak RSS.

## Correctness contract

Pure execution must match the reference execution's:

- block hash/public digest and exit code;
- retired guest-instruction count;
- guest-visible architectural registers;
- guest memory values, including syscall and fallback writes;
- traps, dynamic jumps, and ecall semantics.

Production Preflight must additionally match exact global cycles, shard
boundaries, latest register and memory accesses, canonical next-access tape,
memory range bounds, FullTracer replay, final witnesses, and existing
proof-facing tests. Block 25687400 is the control workload and may regress by
no more than 2%.

Block 25580200's required hash is
`34439c597563024690ce3c91a082c34507569c7e18cc4d1b3b68550b791a2773`.
Block 25687400's required hash is
`d9beb945e65579fa6d95d14012936cf8c7dcf7c52ed54d96f53aa3b0538ff899`.

## Evidence gates

Profile cached Ceno and OpenVM AOT artifacts on the same CPU. Keep guest
instructions, VM cycles, AIR rows, native host instructions, and wall time as
separate metrics. Attribute low-level hotspots to concrete callers before
naming a production cause.

Test one optimization candidate at a time. A candidate is eligible for a
production implementation only when its five-run pure median improves by at
least 5%, or it removes at least 0.25s. Otherwise revert the candidate and
record the controlled trim result. A 4-byte value-only memory experiment is a
trim, not a production representation change, unless it explains at least 5%
of pure execution time. Every retained optimization receives its own commit
and repeats focused emulator, host, AOT integration, and proof-facing tests.
