# Technical Overview

This section covers the internal design and cryptographic protocols
used in Ceno. Before diving into the machinery, it is worth stating
plainly what the machinery is *for* — i.e. what a successful
verification actually binds the proof to.

## What the verifier guarantees

A successful Ceno verification attests to three program-level facts:

- Execution starts at the program entry point declared in the
  verifying key. The first shard's initial program counter is bound
  to the verifying key's entry PC; every subsequent shard's initial
  PC is chained to the previous shard's final PC.
- No intermediate shard contains a halt ecall, and the last shard
  does. The trace ends exactly where the guest invokes halt.
- The halt ecall was invoked with argument zero. The halt-ecall chip
  binds `public_values.exit_code` to the value the guest passed in
  register `a0`, and the verifier requires that value to be zero.

Equivalently, the proof is of an execution of *this specific program
image* from *its declared entry point*, successfully halting with
exit code zero — not of some arbitrary subtrace the prover chose to
begin or end at a convenient point. The recursive verifier in
`ceno_recursion/` makes the same claim about every inner proof.

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
