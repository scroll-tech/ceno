# Recursion v2 — Implementation Plan

Tracks under [#1266](https://github.com/scroll-tech/ceno/issues/1266).

## Goal

Given N base-layer Ceno proofs (one per shard), produce a single
recursive proof attesting that all proofs are valid, execution is
continuous across shards, cross-shard memory is consistent (EC sum = ∞),
and public values are correctly bound.

## Architecture

The v2 recursive verifier is a multi-AIR STARK circuit. Each protocol
step is its own set of AIRs with typed buses between them. The openvm
v2 prover generates the proof; Ceno owns the AIR constraints and trace
generation.

```
proof-shape → GKR tower → main sumcheck → batch constraint → jagged reduction → basefold
```

## Strategy: stack-first, soundness-second

Priority is getting the full integration stack running end-to-end:
**read proofs → preflight → tracegen → prove → verify**. AIRs can
use placeholder traces initially; the openvm v2 prover will generate
a valid STARK proof of whatever constraints exist. This validates
module wiring (bus balancing, trace heights, commitment counts) early
and gives a performance baseline. Soundness is filled in AIR-by-AIR
afterward.

## Phases

### Phase 0: Integration stack (current priority)

Build an integration test that exercises the full pipeline:

1. Read N base-layer Ceno proofs + VK from fixtures
2. Run preflight execution (transcript replay) for all modules
3. Generate witness traces for every registered AIR (placeholder where needed)
4. Run openvm v2 prover
5. Verify with openvm v2 verifier — **must pass**
6. Log performance: proving time, proof size, per-AIR trace heights, tracegen time

Deliverable: a test in `continuation/tests/` that does the above for
both 1-proof and 2-proof inputs. Extends the existing
`leaf_app_proof_round_trip_placeholder`.

Key tasks:
- Enable all modules in system orchestration (batch constraint currently disabled)
- Ensure every AIR is registered and contributes a trace
- Add timing instrumentation (preflight, tracegen, prove, verify)
- Log per-AIR trace heights + proof size

### Phase 1: Complete existing AIR wiring

Make AIR traces real (not placeholder) — module by module.

- Proof shape tracegen from preflight metadata
- Batch constraint: fix preflight/tracegen alignment
- VmPvsAir: wire `public_values_bus`, `cached_commit_bus`
- ZKVM type bridges (`convert_proof_from_zkvm`, `convert_vk_from_zkvm`)
- Inner circuit tracegen (VerifierPvsAir, DeferralPvsAir)

### Phase 2: Jagged Reduction + Basefold

The PCS verification pipeline — critical path for a sound recursive proof.

- Write Basefold module spec
- Implement Jagged reduction AIRs
- Implement Basefold AIR(s)

### Phase 3: Multi-proof aggregation

- Self-recursive prover (RecursionVk ↔ local VK bridge)
- Binary tree aggregation: leaf → internal → root
- Cross-shard connector chaining + EC sum assertion in VmPvsAir

## AIR inventory

### Done (10 AIRs — constraints + tracegen complete)

| Module | AIR | File |
|--------|-----|------|
| Transcript | `ForkedTranscriptAir` | `transcript/transcript_air.rs` |
| Tower/GKR | `TowerInputAir` | `tower/input/air.rs` |
| Tower/GKR | `TowerLayerAir` | `tower/layer/air.rs` |
| Tower/GKR | `TowerLayerSumcheckAir` | `tower/sumcheck/air.rs` |
| Tower/GKR | `TowerProdClaimAir` | `tower/layer/prod_claim/air.rs` |
| Tower/GKR | `TowerLogupClaimAir` | `tower/layer/logup_claim/air.rs` |
| Main | `MainAir` | `main/air.rs` |
| Main | `MainSumcheckAir` | `main/sumcheck/air.rs` |
| Inner | `UnsetPvsAir` | `circuit/inner/unset/air.rs` |

### Wiring / tracegen needed (7 AIRs — constraints written, plumbing incomplete)

| Module | AIR | What's missing |
|--------|-----|----------------|
| Proof Shape | `ProofShapeAir` | Tracegen emits zeros; needs preflight metadata |
| Proof Shape | `PublicValuesAir` | Same |
| Batch Constraint | `SymbolicExpressionAir` | Module disabled in system orchestration |
| Batch Constraint | `ConstraintsFoldingAir` | Same |
| Batch Constraint | `ExpressionClaimAir` | Same |
| Inner | `VmPvsAir` | `public_values_bus` + `cached_commit_bus` commented out |
| Inner | `VerifierPvsAir` | Tracegen TODO |
| Inner | `DeferralPvsAir` | Tracegen TODO |

### Not started — Jagged Reduction (7 AIRs)

| AIR | Purpose |
|-----|---------|
| `JaggedOpeningClaimsAir` | Receive column claims, compute tail-zero C_i, batch into claimed_sum |
| `JaggedMainSumcheckAir` | Degree-2 main sumcheck verification |
| `JaggedQEvalAir` | Reconstruct q_eval from col_evals, check q*f == expected |
| `JaggedAssistSumcheckAir` | Degree-2 assist sumcheck verification |
| `JaggedRobpAir` | ROBP predicate evaluation + final check |
| `JaggedBasefoldHandoffAir` | Chunk col_evals, emit Basefold opening claims |
| `JaggedShapeAir` | Cumulative heights, reshape, column mapping |

### Not started — Basefold (spec needed first)

| AIR | Purpose |
|-----|---------|
| TBD | Verify Basefold PCS opening proofs (Merkle + FRI-like folding) |

### Summary

| Category | Count | Status |
|----------|-------|--------|
| Done | 10 | Constraints + tracegen complete |
| Wiring needed | 7 | Constraints done, plumbing incomplete |
| Jagged | 7 | Not started (spec exists) |
| Basefold | 1+ | Not started (no spec) |
| **Total** | **25+** | |

## Open questions

1. Which gkr-backend revision is canonical for jagged verifier equations?
2. Should C_i (tail-zero factor) use division or product form in AIRs?
3. Is JAGGED_RESHAPE_GROUP_WIDTH = 8 protocol-fixed?
4. How do rotation claims map to jagged column order?
5. How many AIRs should basefold split into?
