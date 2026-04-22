# Technical Overview

This section covers the internal design and cryptographic protocols
used in Ceno. Before diving into the machinery, it is worth stating
plainly what the machinery is *for* — i.e. what a successful
verification actually binds the proof to.

## What the verifier guarantees

What a successful Ceno verification attests to depends on the
**verifier mode**, which is committed at verifier construction — it
lives on the verifier instance and is *not* a per-call argument or
derived from the proof, so a prover cannot influence which statement
is being verified. Three modes exist:

### FullRun

The production mode. The proof attests that:

- Execution starts at the program entry point declared in the
  verifying key. The first shard's initial program counter is bound
  to the verifying key's entry PC; every subsequent shard's initial
  PC is chained to the previous shard's final PC.
- No intermediate shard contains a halt ecall, and the last shard
  does. In other words, the trace ends exactly where the guest
  invokes halt.

Equivalently, the proof is of an execution of *this specific program
image* from *its declared entry point* to halt, not of some arbitrary
subtrace the prover chose to begin or end at a convenient point.

`FullRun` is the default mode of the verifier constructor, and the
recursive verifier in `ceno_recursion/` always runs an inner verifier
in this mode — there is no exposed mode parameter at the recursion
boundary.

### PrefixRun

A dev and benchmarking mode. Same start and intermediate-shard
guarantees as `FullRun` (execution starts at `vk.entry_pc`; no
intermediate shard halts), but the last-shard halt-existence check
is skipped. Used when the emulator is run for a fixed step budget
that stops before the program halts.

### DebugSegment

A single-shard developer mode for `--shard-id=N` workflows. Accepts
exactly one proof at an arbitrary position in the run, reads the
shard id from the proof's public values, and skips both the entry-PC
check and all cross-shard continuity checks. No claim is made about
entry, continuation, or termination; only that the single shard's
cryptographic proof is valid at its stated shard id.

### What is not a verifier-level guarantee

No mode makes a soundness-level claim about the exit code. The
halt-ecall chip binds `public_values.exit_code` to the value the
guest passed to the halt ecall, so on a `FullRun` proof the exit
code is a meaningful public value that a consumer can read — but
it is not required to be zero by the verifier. A caller that cares
about "exited successfully" must check `exit_code == 0` itself.

Similarly, `PrefixRun` and `DebugSegment` proofs are dev/benchmarking
affordances, not production verification surfaces. On a non-halting
shard the public-value fields other than PC are not adversary-
hardened the way the halt path is. Before either mode is exposed to
any external consumer (recursion, aggregation, a third-party
verifier), those fields must first be brought up to the halt-path
standard.

## Sections

The rest of this chapter details the machinery that supports the
guarantees above:

- [Architecture Overview](./architecture-overview.md) — the multi-chip
  structure, and how large traces are segmented
  across shards.
- [Prover Workflow](./prover-workflow.md) — how a proof is constructed
  end-to-end.
- [Optimizations](./optimizations.md) — performance-sensitive design
  choices.
- [Appendix](./appendix.md) — the PIOP constructions: grand-product
  GKR, local rotation, EC-sum Quark.
