---
name: ceno-recursion-principles
description: Migration playbook for `ceno_recursion_v2` when integrating OpenVM recursion components with Ceno `RecursionProof`/`RecursionVk`. Focus on minimal forking, RecursionProof-first seams, preflight-owned replay, and strict placeholder/validation policy.
---

# Ceno Recursion Principles

## Overview

This skill captures the standing orders for evolving `ceno_recursion_v2`: reuse upstream OpenVM crates whenever possible, fork only where type boundaries force divergence, and keep ZKVM/OpenVM bridge logic at narrow seams.

## Quick Triggers

Use this skill when:
- Modifying `ceno_recursion_v2/src/system` or `src/continuation/**`
- Replacing `Proof<SC>` flows with `RecursionProof`
- Swapping child VK flows from `MultiStarkVerifyingKey<SC>` to `RecursionVk`
- Copying/patching OpenVM modules (recursion/continuation) into the Ceno crate
- Debugging trace/air mismatches during continuation proving

## Core Principles

1. **Minimal Divergence** - Fork only the seam that must diverge. Keep upstream for AIRs/modules that do not require Ceno type changes.
2. **RecursionProof First** - Public APIs in local forked modules should prefer `RecursionProof` and `RecursionVk` aliases over upstream `Proof<SC>` and `MultiStarkVerifyingKey`.
3. **Bridge Locality** - Put conversion stubs and TODOs in bridge points (`system/types.rs`, local trace adapters), not spread across unrelated AIR logic.
4. **Preflight Owns Replay** - Transcript/replay ordering is computed during preflight; later blob/trace generation should consume read-only replay data.
5. **Placeholder Discipline** - Temporary mocked values are allowed only if shape-correct and tagged with explicit TODO ownership.
6. **Invariant First** - Preserve count/order invariants (`airs()` vs `per_trace`) before semantic completeness.
7. **Visible, Reversible Deltas** - Prefer small, reviewable patches and avoid broad upstream copy unless absolutely required.

## Minimal Fork Decision Matrix

Fork locally only when at least one applies:
- Child proof/VK type at boundary must change to `RecursionProof`/`RecursionVk`.
- Upstream item is private (`pub(crate)`) and needed in local integration path.
- Upstream interface cannot inject Ceno-specific data without invasive changes.

Do not fork when:
- Change is only wiring/imports and can be done in local caller.
- Upstream module already supports required behavior through existing interfaces.

When forking, keep:
- Original file/module layout for future diffability.
- Fork scope minimal (single module seam first, then expand only if blocked).

## Workflow

### 1. Establish Type Seams First
- Confirm aliases in `src/system/types.rs` (`RecursionProof`, `RecursionVk`).
- Update constructor/trait signatures at seam files before touching AIR internals.

### 2. Keep AIR/Trace Ordering Consistent
- Ensure `src/circuit/inner/mod.rs` `airs()` order exactly matches context order produced in `src/circuit/inner/trace.rs`.
- If pre/post contexts are re-enabled, corresponding AIR entries must be present.

### 3. Placeholder Policy (Temporary)
- If data is missing from `RecursionProof`, use deterministic zero mocks.
- Add explicit comments: `TODO(recursion-proof-bridge): ...`.
- Mocked traces must be width-correct for their AIR and satisfy basic row-0 invariants.

### 4. Replay Ownership Rule
- Preflight computes and records transcript/replay ordering.
- Blob/trace generation should consume replay records only (no hidden replay recomputation).

### 5. Validation Loop
- Iterate with: `cargo check` -> target test -> capture first failing reason -> minimal fix.
- Prefer turning panics into structured errors where possible for diagnosability.
- Keep temporary diagnostics narrow and removable.

### 6. Cargo/Test Hygiene
- Run checks on `ceno_recursion_v2` after each nontrivial seam change.
- Keep target regression test command handy:
  - `RUST_MIN_STACK=33554432 RUST_BACKTRACE=1 cargo test -p ceno_recursion_v2 leaf_app_proof_round_trip_placeholder -- --nocapture`

## Acceptance Checklist for Migration PRs

Before continuing to next module, verify:
- `airs().len()` and proving-context trace count match.
- AIR ordering matches trace ordering (pre -> verifier -> post when enabled).
- Any mocked data has `TODO(recursion-proof-bridge)` and clear ownership.
- No new broad forks were introduced without matrix justification.
- Current top blocker is explicitly identified by latest test/check run.

## Reusable PR Checklist Template

Copy this block into each migration PR description and mark each item as done or N/A with rationale.

```markdown
## Migration Checklist (ceno-recursion-principles)

### Scope and Forking
- [ ] Fork scope is minimal and justified by the decision matrix.
- [ ] Upstream modules remain in use unless a concrete seam forces divergence.
- [ ] Forked files preserve upstream layout for easier future sync.

### Type Seams
- [ ] New/updated public seams use `RecursionProof` / `RecursionVk` where applicable.
- [ ] Bridge logic is localized (for example `src/system/types.rs` or local trace adapters).
- [ ] No unrelated AIR/business logic was modified only to pass types through.

### AIR and Trace Invariants
- [ ] `airs()` order matches proving context order exactly.
- [ ] `airs().len()` matches proving-trace count.
- [ ] Re-enabled pre/post contexts have corresponding AIR entries.

### Placeholder Policy
- [ ] Any mocked value is deterministic and shape-correct.
- [ ] Each mocked value has `TODO(recursion-proof-bridge): ...` with ownership.
- [ ] Placeholder traces satisfy basic row-0 invariants for their AIR.

### Replay Ownership
- [ ] Replay/transcript ordering is computed in preflight.
- [ ] Blob/trace generation consumes preflight replay records read-only.

### Validation Evidence
- [ ] `cargo check` run after the latest nontrivial seam change.
- [ ] Target regression test run (or explicit blocker reason recorded).
- [ ] Current top blocker (if any) is stated with file/path and first failing message.
```

## Reference Paths

- Skill source in repo: `skills/ceno-recursion-principles/SKILL.md`
- Skill source in global codex dir: `~/.codex/skills/ceno-recursion-principles/SKILL.md`
- Local seam hotspots:
  - `src/system/types.rs`
  - `src/circuit/inner/mod.rs`
  - `src/circuit/inner/trace.rs`
  - `src/continuation/prover/inner/mod.rs`
  - `src/gkr/mod.rs`, `src/system/preflight/mod.rs`
