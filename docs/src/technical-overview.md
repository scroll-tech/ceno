# Technical Overview

This section covers the internal design and cryptographic protocols
used in Ceno. Before diving into the machinery, it is worth stating
plainly what the machinery is *for* — i.e. what a successful
verification actually binds the proof to.

## What the verifier guarantees

A successful Ceno verification attests to two program-level facts:

- Execution starts at the program entry point declared in the
  verifying key. The first shard's initial program counter is bound
  to the verifying key's entry PC; every subsequent shard's initial
  PC is chained to the previous shard's final PC.
- No intermediate shard contains a halt ecall, and the last shard
  does. The trace ends exactly where the guest invokes halt.

Equivalently, the proof is of an execution of *this specific program
image* from *its declared entry point* to halt, not of some arbitrary
subtrace the prover chose to begin or end at a convenient point. The
recursive verifier in `ceno_recursion/` makes the same claim about
every inner proof.

### What is not a verifier-level guarantee

The verifier does *not* make a soundness-level claim about the exit
code. The halt-ecall chip binds `public_values.exit_code` to the
value the guest passed to the halt ecall, so the exit code is a
meaningful public value that a consumer can read — but it is not
required to be zero by the verifier. A caller that cares about
"exited successfully" must check `exit_code == 0` itself.

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
