# Ceno PR review checklist

Shared checklist for humans and AI assistants reviewing PRs in this
repo. Referenced from `CLAUDE.md` and `.github/copilot-instructions.md`.

Work through these categories for any PR that touches prover/verifier
or proof-system code. Items are ordered by severity — soundness
concerns first, style last.

## Asymmetry to keep in mind

A bug in **verifier** (or shared-protocol) code can let an invalid
proof pass — a soundness break. A bug in **prover**-only code usually
just fails to produce a valid proof — a liveness failure. Scrutinize
verifier-side edits more than prover-side edits, and treat any edit to
verifier code as the highest-scrutiny change in the repo.

"Verifier code" includes the **recursive verifier** in `ceno_recursion/`.
Recursion compresses many shard proofs into a single smaller proof by
running a verifier inside another proof, so a bug there can silently
pass invalid inner proofs through the compressed proof. Same scrutiny
as the top-level verifier.

**Recursion / native-verifier parity is a review category of its own.**
Any protocol-level change to the Rust verifier (transcript absorbs,
challenge derivation, PCS opening points, padding, domain-separation
tags, field ops) must be mirrored in the recursion circuit, and vice
versa. If a PR changes one side without the other → blocker. If the
mirroring is present but the diff makes it hard to see the two sides
correspond, ask for a before/after correspondence in the description.

## Transcript and Fiat–Shamir

Silent soundness bugs live here.

- New `transcript.append_*` or challenge derivation — prover and
  verifier must absorb **identical bytes in the same order**. Verify
  both sides of the diff.
- New absorb without a domain-separation label → **blocker**.
- Reordering an existing absorb is a protocol change; blocker unless
  explicitly intended and called out.

## Sumcheck and GKR layer plumbing

- `running_evals` claim flow is preserved across the edit.
- Boundary and padding arithmetic holds when chip size or layer count
  changes (powers of two, selector polynomials).
- Hypercube variable ordering (LE vs BE) is consistent on prover and
  verifier sides.

## PCS opening points

- Batched and individual openings match the points the verifier
  reconstructs.
- Any change to how opening points are derived is protocol-equivalent
  to a transcript change and deserves the same scrutiny.

## Determinism on transcript-sensitive paths

- New parallel iteration over `HashMap`, `HashSet`, or otherwise
  unordered input.
- Sort-before-hash when input is not already in a canonical order.

## Verifier robustness (liveness / DoS)

- `unwrap`, `expect`, index operator, or `assert!` on proof-derived
  bytes in verifier code paths → finding.
- Bounds checks present before indexing into proof-derived arrays.

## Feature-gate and build parity

- Goldilocks field exercised (`cargo make tests_goldilock`).
- CPU-only build still works after changes to `gkr_iop/src/hal.rs`,
  layer-prover traits, `gkr_iop/src/cpu`, or `gkr_iop/src/gpu`.
- New expensive debug assertion gated behind the `sanity-check`
  feature rather than `debug_assertions`.

## Scope

- Changes to workspace primitives from `scroll-tech/gkr-backend`
  (`sumcheck`, `transcript`, `mpcs`, `multilinear_extensions`,
  `ff_ext`, `poseidon`, `p3`, `whir`, `witness`, `sp1-curves`) belong
  in that repo, not this one.
- Backwards-compat shims are not accepted; the repo is pre-production
  and clean edits are preferred.
