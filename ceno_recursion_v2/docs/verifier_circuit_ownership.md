# Verifier Circuit Ownership Principles

This document records the ownership rule for Ceno's recursion verifier circuit.
The short version is:

> Ceno should own the verifier circuit, while OpenVM remains a design reference
> and provider of protocol-neutral primitives.

## Motivation

Ceno follows the high-level OpenVM recursion data flow:

```text
proof-shape -> GKR -> batch constraint -> jagged -> basefold
```

However, the concrete protocol is not the same as OpenVM's recursion circuit:

- Ceno has a different set of AIRs.
- Ceno replaces OpenVM's stacking-style layer with a jagged layer.
- Ceno replaces WHIR-based opening verification with Basefold.
- The reduction from GKR output into batch constraint input is Ceno-specific.
- Ceno proof, verifying-key, public-value, transcript, and trace-shape semantics
  differ from OpenVM's native recursion assumptions.

Because these differences affect constraints and transcript semantics, they are
protocol-level differences, not integration details. The recursion verifier
should therefore be treated as Ceno protocol code.

## Ownership Rule

Use this rule when deciding whether code should stay upstream, be exposed from an
OpenVM fork, or become local Ceno code:

```text
visibility problem -> patch OpenVM/fork minimally
semantic problem   -> copy or rewrite into Ceno
```

Examples of visibility problems:

- A useful protocol-neutral type is private.
- A constructor or column layout is not exported.
- A primitive sub-AIR or helper bus is reusable as-is but hidden.

Examples of semantic problems:

- The AIR constraints encode OpenVM proof layout.
- The module assumes OpenVM public values.
- The transcript order differs from Ceno's verifier.
- The GKR-to-batch-constraint reduction differs.
- The module assumes OpenVM stacking or WHIR behavior.

Semantic differences should not be solved by repeatedly patching OpenVM internals.
Once constraints or transcript order diverge, the module should be Ceno-owned.

## What To Reuse From OpenVM

OpenVM should remain a dependency for protocol-neutral infrastructure:

- AIR framework traits and proving context patterns.
- Bus, permutation, and lookup idioms.
- Reusable sub-AIRs such as nested-loop helpers.
- Poseidon2 AIRs and subchips.
- Range, power, and other primitive checker AIRs.
- Backend, tracegen, and CUDA integration patterns when they remain generic.

These pieces are useful because they do not define Ceno's proof semantics.

## What Ceno Should Own

Ceno should own modules whose constraints define the Ceno recursion protocol:

- `proof_shape`: Ceno AIR list, trace metadata, public-value mapping, and child
  proof shape.
- `gkr` / `tower`: verification of Ceno's GKR proof shape.
- `batch_constraint`: Ceno's reduction target for GKR output.
- `jagged`: replacement for OpenVM stacking semantics.
- `basefold`: replacement for WHIR/opening verification.
- Ceno transcript scheduling whenever the order or domain separation differs.
- Ceno proof/VK adapters and public-value layout.

Copied OpenVM code in these areas should be treated as bootstrapping material,
not as upstream-owned code. Once copied, it is a Ceno-owned fork unless it remains
bit-for-bit protocol-neutral.

The jagged replacement for OpenVM stacking is specified in
`jagged_reduction_spec.md`.

## Module Interface First

The verifier circuit should be designed around Ceno-native module interfaces:

```text
ProofShapeOutput -> GkrInput
GkrOutput        -> BatchConstraintInput
BatchOutput      -> JaggedInput
JaggedOutput     -> BasefoldInput
BasefoldOutput   -> final recursion claim / public values
```

Each interface should specify:

- The values carried on buses.
- Transcript cursor ownership and expected sampling/observation order.
- Per-AIR metadata consumed by the next module.
- Trace shape and padding rules.
- Public values or commitments exposed outside the module.

Once these interfaces are explicit, OpenVM compatibility should not leak across
module boundaries. A module may follow OpenVM's structure internally, but its
external contract should be Ceno-native.

## Vendoring Guidance

If code is copied from OpenVM:

- Copy only the minimal transitive files needed.
- Preserve upstream path and commit metadata near the copied module.
- Mark whether the file is an unchanged mirror or a Ceno-owned fork.
- Keep local semantic changes small and documented.
- Prefer local wrappers for type adaptation only when constraints remain
  identical.

A suggested file header for copied protocol code:

```rust
// Vendored from openvm-org/openvm
// upstream path: <path>
// upstream commit: <sha>
// status: Ceno-owned fork
// reason: verifies Ceno recursion proof semantics
```

## Testing Implications

Ceno-owned verifier modules need local tests for adversarial shape and transcript
cases, not only compilation against OpenVM APIs. At minimum, tests should cover:

- Missing or reordered AIR metadata.
- Wrong public-value count or mapping.
- Wrong trace height or padding.
- Mismatched GKR layer count.
- Incorrect GKR-to-batch-constraint reduction.
- Incorrect transcript cursor or domain separation.
- Jagged/Basefold boundary mismatches.

The goal is to test the Ceno protocol contract directly.

## Practical Summary

Follow OpenVM's data flow and engineering patterns, but do not force Ceno's proof
system into OpenVM's concrete recursion circuit.

OpenVM is the reference architecture. Ceno owns the verifier protocol.
