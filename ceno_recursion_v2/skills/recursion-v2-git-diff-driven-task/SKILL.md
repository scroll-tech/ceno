---
name: recursion-v2-git-diff-driven-task
description: Diff-driven execution protocol for ceno_recursion_v2 tasks. Harvest TODO/task comments from current git diff, align strictly with the user's change request, implement against upstream OpenVM skeleton patterns, and fill real data from ceno_zkvm verifier source-of-truth.
---

# Recursion V2 Git Diff Driven Task

## Overview

Use this skill when task intent is written into newly added source comments and implementation should be driven directly by `git diff`.

This protocol enforces:
- TODO/comment-first task intake from staged and unstaged diffs,
- explicit alignment to the user's current change request,
- condensed, reviewable implementation plans,
- upstream-compatible constraint/bus skeleton wiring,
- source-of-truth data fill from the verifier path,
- and a fixed end-of-task validation gate.

## When To Use

Use this skill when any of the following applies:
- You added task comments/TODOs and want implementation to follow only those diff deltas.
- You are wiring or refactoring constraint/bus message skeletons in recursion/continuation flows.
- You need to replace placeholders with verifier-accurate data.
- You want a strict plan-before-implementation checkpoint.

## Diff Intake Protocol (Required)

1. Read `git diff` from both unstaged and staged changes.
2. Extract only newly added TODO/task comments that describe behavior changes.
3. Restate the explicit user change request and filter out out-of-scope TODOs/comments.
4. Convert in-scope items into a condensed checklist format:
   - `target`: file and symbol,
   - `behavior`: what must be implemented,
   - `acceptance`: concrete condition proving completion.
5. Remove duplicate or ambiguous items and keep only executable work items.
6. Present the condensed plan for review before editing logic.

## Implementation Protocol (Required)

1. Implement checklist items in priority order.
2. Keep implementation scoped to the user-approved request and in-scope diff TODOs.
3. Resolve every in-scope diff TODO by either:
   - replacing it with finished code, or
   - retaining a minimal explicit TODO with ownership and blocker rationale.
4. Preserve existing AIR ordering and bus key invariants unless checklist items explicitly request changes.

## Reference Hierarchy

Use references in this order:

1. Constraint/bus message skeleton patterns:
   - upstream OpenVM continuation modules,
   - upstream OpenVM recursion modules.
2. Source-of-truth for real data mapping and transcript/order semantics:
   - `ceno_zkvm/src/scheme/verifier.rs` (especially verifier-side fill/validation flow).
3. Local ceno_recursion_v2 style and invariants:
   - adapt to local aliases and buses without inventing new message shapes unless required.

## Plan Quality Bar

A valid plan must:
- map every actionable in-scope diff TODO/comment to exactly one checklist item,
- state file/symbol targets explicitly,
- include acceptance conditions that can be verified by code reading or test execution,
- and call out any blocker assumptions before implementation starts.

## Completion Gate (Run At End)

Run exactly these commands at task completion:

```bash
RUST_LOG=debug RUST_MIN_STACK=33554432 RUST_BACKTRACE=1 cargo test --release -p ceno_recursion_v2 leaf_app_proof_round_trip_placeholder -- --nocapture
cargo fmt --all
```

## Done Criteria

Task is done only when all are true:
- All condensed checklist items are implemented or explicitly marked blocked with rationale.
- All in-scope TODOs introduced by the current `git diff` are resolved or explicitly owned/blocked.
- No unresolved implementation comments remain from the task diff without ownership.
- Constraint/bus skeleton usage follows upstream-compatible patterns.
- Real data fill aligns with `ceno_zkvm/src/scheme/verifier.rs` semantics.
- Completion gate commands have been run and succeeded.

## Quick Reusable Checklist Template

```markdown
- [ ] Collect unstaged + staged git diff TODO/task comments
- [ ] Restate user request and mark in-scope items only
- [ ] Condense into target/behavior/acceptance checklist
- [ ] Share plan and get implementation go-ahead
- [ ] Implement using upstream continuation/recursion skeleton patterns
- [ ] Fill real data per ceno_zkvm verifier source-of-truth
- [ ] Resolve in-scope TODOs introduced in this diff
- [ ] Run required completion gate commands
```
