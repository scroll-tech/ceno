# Technical Overview

This section covers the internal design and cryptographic protocols
used in Ceno. Before diving into the machinery, it is worth stating
plainly what the machinery is *for* — i.e. what a successful
verification actually binds the proof to.

## What the verifier guarantees

A successful Ceno verification attests to exactly two program-level
statements. Everything else in the verifier — transcript flow,
sumcheck, PCS openings, tower and GKR reductions, per-shard EC
accumulators, cross-shard memory consistency — is machinery whose
purpose is to make these two statements meaningful.

1. **Start: execution begins at the program entry point declared in
   the verifying key.** The first shard's initial program counter is
   bound to the verifying key's entry PC; every subsequent shard's
   initial PC is chained to the previous shard's final PC. The proof
   is of an execution of *this specific program image* starting from
   *its declared entry point*, not of some arbitrary subtrace the
   prover chose to begin at a convenient PC.
2. **Exit: the program exits successfully with code zero.** Every
   shard carries an exit-code public value, required by the verifier
   to be zero. On a halting shard, the halt-ecall chip binds this
   field to the value the guest passed in the first argument register
   via the public-value "instance" mechanism, so the check asserts
   *"the guest called the halt ecall with argument zero"* — i.e. the
   program exited successfully in the RISC-V convention.

Two terminal modes are legitimate, selected by a caller-supplied
"expect halt" flag: a full run reaching halt, or a prefix run stopped
at a step budget. The verifier checks, on each shard, that the
proof's halt-ecall presence matches the declared mode — only the
terminal shard may carry a halt, and only when the caller expects
one — which prevents a prover from either hiding a halt or
manufacturing one. The exit-code-zero invariant holds in both modes.

**Prefix proofs are a dev and benchmarking affordance, not a
production verification surface.** On a non-halting shard the
public-value fields other than PC are not adversary-hardened the way
the halt path is; verifier-level checks on them are format sanity
rather than soundness statements. Before prefix proofs are exposed to
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
