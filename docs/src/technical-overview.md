# Technical Overview

This section covers the internal design and cryptographic protocols
used in Ceno. Before diving into the machinery, it is worth stating
plainly what the machinery is *for* — i.e. what a successful
verification actually binds the proof to.

## What the verifier guarantees

A successful Ceno verification attests to the following program-level
statements. Everything else in the verifier — transcript flow,
sumcheck, PCS openings, tower and GKR reductions, per-shard EC
accumulators, cross-shard memory consistency — is machinery whose
purpose is to make these meaningful.

1. **Start: execution begins at the program entry point declared in
   the verifying key.** The first shard's initial program counter is
   bound to the verifying key's entry PC; every subsequent shard's
   initial PC is chained to the previous shard's final PC. The proof
   is of an execution of *this specific program image* starting from
   *its declared entry point*, not of some arbitrary subtrace the
   prover chose to begin at a convenient PC.
2. **Halt: when the caller expects termination, the terminal shard
   invokes the halt ecall.** Intermediate shards must not halt, and
   the terminal shard's halt-ecall presence is checked against the
   caller's expectation (a full run reaching halt vs. a prefix run
   stopped at a step budget). This prevents a prover from either
   hiding a halt or manufacturing one.

### What is not a verifier-level guarantee

The verifier does *not* require a specific exit code. The halt-ecall
chip binds `public_values.exit_code` to the value the guest passed
in register `a0` at the halt site, so the field is a faithful readout
of what the guest passed — but the guest program defines its own
exit-code semantics, and a non-zero value may be a legitimate
application signal (for example, distinguishing error classes). A
caller that wants "exited successfully" must compare
`exit_code == 0` itself, outside the verifier.

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
