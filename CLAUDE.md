# Ceno zkVM — repo guide

Ceno is a **multivariate-polynomial (GKR-based) zkVM for RISC-V** written in
Rust. A bug in **verifier** code can let an invalid proof pass — a
soundness break. A bug in **prover** code usually just fails to produce
a valid proof (a liveness failure, not a soundness one). The verifier
is the load-bearing side; **soundness and correctness come before
performance, and performance comes before style**. Don't block on style
when correctness is at stake; don't trade soundness for a speedup
without explicit justification.

## Layout

Main crates in this repo:

- `ceno_zkvm/` — main zkVM prover and verifier. Chip circuits, shard
  orchestration, PCS integration, end-to-end (`bin e2e`).
- `gkr_iop/` — local GKR circuit framework: `Chip`, `Layer`, zerocheck /
  sumcheck / linear layer provers, CPU and GPU backends. 
- `ceno_emul/` — RISC-V emulator (produces traces for the prover).
- `ceno_recursion/` — recursive proof aggregation stack. Compresses
  shard proofs by running a verifier inside another proof; treat as
  verifier code for soundness purposes. **Must stay in lockstep with
  the native Rust verifier** — any protocol-level change on one side
  (transcript absorbs, challenge derivation, PCS opening points,
  padding, domain-separation tags, field ops) needs the mirrored
  change on the other, or the recursive proof silently verifies a
  different statement than the Rust verifier.
- `ceno_cli/` (`cargo ceno …`), `ceno_host/`, `derive/`.
- `ceno_rt/`, `ceno_serde/` — runtime APIs used **inside guest
  programs** (the guest Rust code that compiles to the
  `riscv32im-unknown-none-elf` target).
- `guest_libs/{crypto,keccak,sha2}/` — Ceno-specific crypto libraries
  that guest programs call; they route through accelerated precompile
  paths where available.
- `examples/` — ~30 example guest programs (fibonacci, keccak,
  secp256k1, sha256, bn254, …) that exercise the zkVM end-to-end. 
- `examples-builder/` — build harness for `examples/`.

A few workspace deps used by guest programs (`ceno_crypto_primitives`,
`ceno_syscall`) live in a separate repo `scroll-tech/ceno-patch`,
pinned by git branch in the top-level `Cargo.toml` (same pattern as
`gkr-backend`).

Low-level proof-system primitives (`sumcheck`, `transcript`, `mpcs`,
`multilinear_extensions`, `ff_ext`, `poseidon`, `p3`, `whir`, `witness`,
`sp1-curves`) come from a **separate repo**, `scroll-tech/gkr-backend`,
pinned by git tag in `Cargo.toml`. Edits to those live in that repo, not
here — don't try to fix upstream primitives by patching in this tree.

## Docs

User-facing mdbook at `docs/src/`. Start with
`docs/src/architecture-overview.md` (multi-chip architecture +
segmentation). PIOP appendices cover grand-product, local rotation, and
EC-sum Quark.

## Toolchain and commands

Pinned to `nightly-2025-11-20` (see `rust-toolchain.toml`), plus the
`riscv32im-unknown-none-elf` target. `cargo-make` is required.

CI gate (`.github/workflows/lints.yml`, `tests.yml`):

```sh
cargo fmt --all --check
cargo check --workspace --all-targets
cargo check --workspace --all-targets --release
cargo make clippy                           # clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --release
taplo fmt --check --diff
cargo make tests                            # full test run, RUST_MIN_STACK=33554432
cargo make tests_goldilock                  # same, --no-default-features --features goldilocks
```

Before declaring a change done: at minimum run `cargo make clippy` and
the tests for the crate you touched. For anything in prover/verifier
code paths, also run `cargo make tests` end-to-end.

## What to prioritize when editing

Verifier code — including the recursive verifier in `ceno_recursion/`
— is the highest-scrutiny surface in the repo. Spend more thinking
time per line there than anywhere else; prefer a slow, explicit edit
over a clever one.

1. **Soundness.** Transcript / challenge order, domain separation,
   sumcheck claim flow, PCS opening points, padding and boundary
   arithmetic, hypercube indexing. Break any of these on the verifier
   (or shared-protocol) side and the proof system is unsound. Re-check
   the math before any "cleanup" edit in prover/verifier code.
2. **Determinism.** Parallel iteration order, `HashMap` key order, and
   anything floating-point are not free. Transcript-sensitive paths
   must be deterministic across threads and platforms.
3. **Panics on attacker-controlled input.** `unwrap`, `expect`,
   indexing, and `assert!` applied to untrusted proof or witness data
   in **verifier** code paths are liveness/DoS risks (a crafted proof
   crashes the verifier instead of being cleanly rejected), not style
   issues.
4. **Performance in hot paths.** Prover/verifier inner loops — avoid
   stray `.clone()`, allocations, and accidentally quadratic patterns.
   Note benchmark impact when editing hot loops.
5. **Style last.**

## PR review

For any PR review task, follow `.github/copilot-instructions.md` for
response shape (findings-first, `blocker` / `major` / `minor` tags,
`path:line` locations) and `.github/pr-review-checklist.md` for the
concrete category-by-category checklist. The priority list above is
the filter for what counts as a finding.

## Conventions and gotchas

- **`goldilocks` feature** is a secondary field. Shard-RAM circuits
  don't currently support it (see commented-out goldilocks lines in
  `integration.yml`). Don't assume a change works on both fields
  without running both test suites.
- **`sanity-check` feature** (in `ceno_zkvm`) is used by integration CI
  for extra in-prover invariant checks. Prefer gating expensive
  debug-only assertions behind it over `debug_assertions`.
- **GPU prover** lives behind the `gpu` feature (and `ceno_gpu` /
  `cudarc` optional deps in `gkr_iop`). Don't break CPU-only builds
  when touching backend-abstracted code
  (`gkr_iop/src/hal.rs`, layer-prover traits, `gkr_iop/src/cpu`,
  `gkr_iop/src/gpu`).
- **No backwards-compat shims.** Repo is pre-production (README:
  "not suitable for use in production"); clean edits beat migration
  scaffolding.
- **Don't skip git hooks** (`--no-verify`) or bypass `-D warnings`.
- **`cargo make` is the source of truth** for test invocations; don't
  substitute bare `cargo test` when a `cargo make` target exists (it
  sets `RUST_MIN_STACK` and other env needed to avoid stack overflow
  in prover code).
