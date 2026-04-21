# Copilot Instructions for ceno

These instructions apply only to pull request or diff review tasks in this repository. For non-review tasks, ignore this file.

## Scope and goals

- Treat this repository as a cryptography and zkVM codebase where soundness and correctness are higher priority than style.
- Apply this guidance only when asked to review a PR, commit range, or patch/diff.
- Prioritize actionable risks: behavioral regressions, protocol/soundness issues, architecture erosion, and performance regressions.

## Repository context

- Workspace: multi-crate Rust workspace (for example `ceno_zkvm`, `ceno_emul`, `ceno_recursion`, `ceno_cli`, `examples`).
- Toolchain: `nightly-2025-11-20` (see `rust-toolchain.toml`).
- CI expectations (see `.github/workflows/`):
  - `cargo fmt --all --check`
  - `cargo check --workspace --all-targets`
  - `cargo check --workspace --all-targets --release`
  - `cargo make clippy`
  - `cargo clippy --workspace --all-targets --release`
  - `cargo make tests`

## Review behavior (mandatory)

When reviewing a PR/diff, respond in this order:

1. Findings first, sorted by severity.
2. Open questions or assumptions.
3. Brief change summary.

Do not commit, push, or propose code changes. Provide review findings only.

Before reviewing code, check PR metadata:

- Verify the pull request description is non-empty.
- If it is empty, add a finding with location `PR metadata: description`, explain why reviewability is affected, and request a minimal problem/design/testing summary.

For each finding:

- Include severity: `blocker`, `major`, or `minor`.
- Include precise location (`path:line` and symbol when possible).
- Explain impact and triggering conditions.
- Propose a concrete fix or mitigation.
- Mention what test would catch it if coverage is missing.

If there are no findings, state that explicitly and mention residual risks or testing gaps.

## What to prioritize in this codebase

- Soundness-critical protocol correctness (sumcheck, PCS openings, prover/verifier consistency, transcript/challenge flow, domain separation).
- Arithmetic and layout correctness (field operations, multilinear indexing, padding/boundary math, off-by-one risks).
- Performance regressions in proving/verifying hot paths (unnecessary clones, extra allocations, accidental quadratic behavior, synchronization overhead).
- Architecture integrity across crates (API layering, unnecessary coupling, abstraction leaks).
- Panic and invariant handling on potentially untrusted proof/input data (`unwrap`, `expect`, indexing, assertions) — treat panics on proof-derived data in verifier code paths as liveness / DoS findings, not style.
- Determinism and concurrency risks (parallel iteration order assumptions, shared mutable state).

## Review checklist

Work through `./.github/pr-review-checklist.md` for any PR touching prover/verifier or proof-system code. That file is the canonical, category-by-category checklist (transcript / Fiat–Shamir, sumcheck layer plumbing, PCS openings, determinism, verifier robustness, feature-gate parity, scope) and is shared with `CLAUDE.md` and human reviewers.

## Testing guidance

When proposing or reviewing behavior changes, prefer targeted tests near the affected crate/module:

- Unit tests for boundaries (empty/singleton, power-of-two, shard boundaries, padding edges).
- Regression tests for discovered bugs.
- Deterministic checks for transcript/challenge-sensitive logic.
- Performance-sensitive changes should include benchmark evidence or reasoned impact notes.

## Anti-patterns to avoid

- Leading with style-only suggestions when correctness, soundness, architecture, or performance risks exist.
- Claims like "safe", "correct", or "fast" without citing concrete code paths.
- Requesting broad refactors outside PR scope unless needed to fix a blocker.
- Ignoring test impact for behavior-changing edits.

## Preferred response style

- Concise, direct, and technical.
- Use actionable bullet points.
- Keep summaries brief and focus on concrete findings.

