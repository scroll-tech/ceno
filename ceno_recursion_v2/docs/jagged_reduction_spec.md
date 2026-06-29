# Jagged Reduction Module Spec

This document specifies the Ceno recursion module that replaces the role of
OpenVM's `stacking` module from `openvm-org/openvm` branch
`develop-v2.1.0-rv64`.

The module reduces many per-AIR trace polynomial evaluation claims into opening
claims against Ceno's jagged polynomial commitment. In the native prover today,
that commitment is `mpcs::Jagged<mpcs::Basefold<...>>`: Jagged verifies the
packing/reduction argument and then delegates the resulting openings to
Basefold.

This is Ceno-owned protocol code. OpenVM stacking is useful as an architecture
reference for module boundaries, transcript cursor ownership, buses, and AIR
decomposition, but the concrete equations here are Ceno Jagged/Basefold
equations, not OpenVM Stacking/WHIR equations.

## Position In The Pipeline

The intended recursion verifier flow is:

```text
proof-shape -> GKR -> batch constraint -> jagged reduction -> basefold
```

The jagged reduction module sits after batch constraint and before Basefold:

```text
BatchConstraintOutput -> JaggedInput
JaggedOutput          -> BasefoldInput
```

Its job is to verify the same reduction performed by the native Jagged PCS
verifier:

```text
per-column opening claims
  -> one batched claim over the packed polynomial q'
  -> jagged sumcheck
  -> assist sumcheck for the jagged index map
  -> Basefold opening claims for q'
```

## Relationship To OpenVM Stacking

OpenVM's stacking module performs:

```text
column opening claims
  -> random linear combination with lambda
  -> univariate reduction over skipped dimensions
  -> multilinear sumcheck over stacked dimensions
  -> stacked opening batching with mu
  -> WHIR claim
```

Ceno's jagged module is analogous only at the module-boundary level: both reduce
many column opening claims into fewer commitment-opening claims. The concrete
protocol is different:

- Ceno packs all trace columns for a commitment into one logical jagged
  polynomial `q'`.
- Ceno uses a column batching challenge `z_col`, not OpenVM's stacking
  `lambda`/`mu` schedule.
- Ceno's reduction has a main jagged sumcheck and an assist sumcheck for the
  jagged inverse map.
- Ceno hands off to Basefold, not WHIR.
- Ceno's proof shape determines the mapping from AIR columns to jagged
  polynomial indices.

Therefore OpenVM stacking AIRs should not be copied directly as protocol code.
The useful pieces are the engineering pattern: split the verifier into small
AIRs, make transcript reads/writes explicit, and move cross-module values over
typed buses.

## Native Jagged PCS Contract

This section describes the verifier behavior the recursion AIRs must reproduce.
The implementation inspected is the `mpcs::jagged` module from
`scroll-tech/gkr-backend`.

### Commitment Shape

For each committed matrix sequence, Jagged builds one logical polynomial `q'`:

```text
q' = p_0 || p_1 || ... || p_{N-1}
```

where each `p_i` is one trace-column polynomial. The commitment carries:

- `inner`: the inner Basefold commitment to reshaped `q'`.
- `cumulative_heights`: `t[0] = 0`, `t[i + 1] = t[i] + h_i`.
- `reshape_log_height`: `log_h`, the row dimension used when reshaping `q'`
  into Basefold columns.

The original polynomial height is:

```text
h_i = t[i + 1] - t[i]
s_i = ceil_log2(h_i)
```

The logical `q'` uses the real occupied heights. Padding is only an evaluation
convention and for the inner Basefold reshape.

### Opening Shape

For each Jagged commitment, the verifier receives one or more groups:

```text
(opening_point, evals_for_consecutive_polynomials)
```

In the current native verifier, these groups are flattened in commitment order.
Each evaluation is assigned to the next polynomial index. The first `usize` tag
in the generic PCS verifier opening tuple is not used by Jagged after dispatch;
the point and eval vector are the semantic payload.

All opening points for one commitment must be prefix-compatible. Jagged builds a
single common point `z_row` of length:

```text
max_s = max_i ceil_log2(h_i)
```

If a polynomial has fewer variables than `max_s`, its padded evaluation includes
the zero-tail factor:

```text
C_i = product_{j=s_i}^{max_s-1} (1 - z_row[j])
```

The native flattening step divides by `C_i` to recover the native evaluation
`p_i(z_row[..s_i])`, and the verifier later multiplies by the same `C_i` when
forming the batched claim. In AIRs this should be constrained as a product
relation, not as an unconstrained inverse:

```text
original_eval_i = C_i * native_eval_i
```

The native code rejects `C_i = 0` during flattening. The recursion circuit must
either enforce the same nonzero condition or avoid witness divisions by keeping
the original-evaluation form through the batched claim.

### Jagged Proof Shape

For each commitment opening round, the Jagged proof contains:

- `sumcheck_proof`: degree-2 sumcheck proof for `sum_b q'(b) * f(b)`.
- `col_evals`: evaluations of reshaped `q'` columns at `rho_row`.
- `f_at_rho`: claimed value of the jagged weight function at `rho`.
- `assist_proof`: degree-2 assist sumcheck proving `f_at_rho`.

The full Jagged proof also contains:

- `inner_proof`: the inner Basefold opening proof for all generated inner
  opening rounds.

### Verifier Flow

For each Jagged commitment round:

1. Flatten grouped opening claims into `(z_row, native_evals)` and check point
   prefix compatibility.

2. Append `native_evals` to the transcript and sample:

   ```text
   z_col <- transcript
   num_col_vars = max(ceil_log2(num_polys), 1)
   ```

3. Compute `eq_col = eq(z_col, *)` and the batched opening claim:

   ```text
   claimed_sum =
     sum_i eq_col[i] * C_i * native_eval_i
   ```

4. Verify the main jagged sumcheck with:

   ```text
   max_degree = 2
   num_giga_vars = ceil_log2(padded_total)
   padded_total = ceil(total_evals / 2^log_h) * 2^log_h
   ```

   The sumcheck proves:

   ```text
   claimed_sum = sum_b q'(b) * f(b)
   ```

   where `f(b)` is the jagged weight induced by the inverse map from flat
   `q'` index `b` to `(poly_index, row)`.

5. Let the sumcheck output point be `rho`. Split it according to the inner
   reshape:

   ```text
   rho_row = rho[..log_h]
   rho_col = rho[log_h..]
   ```

6. Reconstruct `q'(rho)` from proof-provided `col_evals`:

   ```text
   q_eval = sum_j eq(rho_col, j) * col_evals[j]
   ```

7. Append `col_evals` and `f_at_rho` to the transcript, then check:

   ```text
   q_eval * f_at_rho == main_sumcheck_expected_evaluation
   ```

8. Verify the assist sumcheck with:

   ```text
   n_robp = num_giga_vars + (padded_total.is_power_of_two() ? 1 : 0)
   n_assist = 2 * n_robp
   max_degree = 2
   ```

   The extra ROBP bit is needed when `padded_total` is a power of two, because
   the boundary value `total_evals` must be representable in the `< d`
   comparison.

9. De-interleave the assist point:

   ```text
   assist_point = (rho_star_c[0], rho_star_d[0], rho_star_c[1], rho_star_d[1], ...)
   ```

10. Evaluate the width-4 ROBP predicate:

    ```text
    g(a, b, c, d) = [a + c = b and b < d]
    ```

    as:

    ```text
    h_at_rho_star =
      g_hat(z_row_padded, rho_padded, rho_star_c, rho_star_d)
    ```

11. Compute:

    ```text
    q_at_rho_star =
      sum_y eq_col[y] * eq(assist_point, bits(t[y]), bits(t[y + 1]))
    ```

12. Check the assist final relation:

    ```text
    h_at_rho_star * q_at_rho_star == assist_expected_evaluation
    ```

13. Emit inner Basefold opening claims:

    ```text
    inner_commitment = jagged_commitment.inner
    opening_point    = rho_row
    opening_evals    = col_evals, chunked by JAGGED_RESHAPE_GROUP_WIDTH
    point_len        = log_h
    ```

After all Jagged rounds are processed, the module invokes the Basefold verifier
on the collected inner rounds and `inner_proof`.

## Inputs

Inputs are per child proof.

### From Batch Constraint

The batch constraint module must provide the opening claims that should be
checked against witness and fixed commitments:

- `tidx_jagged`: transcript position at which Jagged verification begins.
- commitment kind: witness, fixed-first-shard, or fixed-non-first-shard.
- per-AIR/per-chip opening point.
- per-column evaluations in the same order as the committed jagged polynomial
  indices.
- proof-shape index information needed to prove that order.

The native verifier receives these claims after GKR/main-sumcheck as
`input_opening_point`, `wits_in_evals`, and `fixed_in_evals`. The recursion
module should not trust vector order implicitly; the proof-shape module must
constrain the mapping from AIR/chip columns to jagged polynomial indices.

### From Proof Shape And VK

Proof shape and verifying-key data must provide enough metadata to bind every
opening claim to the committed jagged layout:

- commitment list and commitment kind.
- inner Basefold commitment digest for each Jagged commitment.
- `reshape_log_height`.
- `cumulative_heights`.
- `num_polys = cumulative_heights.len() - 1`.
- `sort_idx -> air_idx`.
- trace partition metadata.
- per-partition width and column offsets.
- per-polynomial height and variable count.
- rotation metadata, if a claim is for a rotated trace column.

This metadata must be constrained by buses, not trusted as trace-only witness.

### From Jagged Proof

The module consumes:

- one `JaggedBatchOpenProof` per opened Jagged commitment.
- `sumcheck_proof`.
- `col_evals`.
- `f_at_rho`.
- `assist_proof`.
- final `inner_proof` for Basefold.

### From Transcript

The module observes and samples exactly the values used by native Jagged
verification:

- observe flattened/native opening evaluations.
- sample `z_col`.
- observe each main sumcheck round polynomial and sample its challenge.
- observe `col_evals`.
- observe `f_at_rho`.
- observe each assist sumcheck round polynomial and sample its challenge.

Basefold consumes the transcript state immediately after these Jagged steps.

## Outputs

### To Basefold

The Jagged module sends:

- `tidx_basefold`: transcript position after all Jagged rounds.
- inner Basefold commitment for each Jagged commitment.
- `rho_row` as the Basefold opening point.
- `log_h` as the Basefold point length.
- `col_evals` chunked by `JAGGED_RESHAPE_GROUP_WIDTH` for inner openings.
- `inner_proof` pointer/metadata consumed by the Basefold verifier.

These outputs should use Ceno-native buses, e.g. `BasefoldModuleBus`,
`BasefoldOpeningPointBus`, and `BasefoldOpeningEvalsBus`. Do not reuse WHIR bus
names unless the downstream module is actually WHIR-compatible.

### To Other Modules

The module may publish equality-table or ROBP helper values if other modules
share them. These should be exposed through local Ceno buses with explicit
ownership.

## Proposed AIR Split

The exact split can change during implementation, but the verifier should stay
small enough that each AIR owns one equation family.

1. `JaggedOpeningClaimsAir`
   - Receives opening claims from batch constraint.
   - Receives proof-shape mapping to jagged polynomial indices.
   - Checks commitment order and point prefix compatibility.
   - Computes tail-zero factors `C_i`.
   - Computes the batched `claimed_sum` after `z_col` is sampled.

2. `JaggedMainSumcheckAir`
   - Verifies the degree-2 main sumcheck transcript.
   - Outputs `rho` and `main_sumcheck_expected_evaluation`.
   - Owns `num_giga_vars`, `padded_total`, and sumcheck round count checks.

3. `JaggedQEvalAir`
   - Splits `rho` into `rho_row` and `rho_col`.
   - Receives proof-provided `col_evals`.
   - Computes `q_eval = sum_j eq(rho_col, j) * col_evals[j]`.
   - Checks `q_eval * f_at_rho == main_sumcheck_expected_evaluation`.
   - Sends `rho_row` and `col_evals` toward Basefold handoff.

4. `JaggedAssistSumcheckAir`
   - Verifies the degree-2 assist sumcheck transcript.
   - Outputs the de-interleaved assist challenge vectors.
   - Owns `n_robp` and `n_assist` checks.

5. `JaggedRobpAir`
   - Evaluates `g_hat(z_row_padded, rho_padded, rho_star_c, rho_star_d)`.
   - Computes `q_at_rho_star` from `eq_col` and cumulative height bits.
   - Checks the assist final relation.
   - This AIR is Ceno-specific; OpenVM `EqBaseAir`/`EqBitsAir` are not a direct
     match for the jagged ROBP predicate.

6. `JaggedBasefoldHandoffAir`
   - Chunks `col_evals` by `JAGGED_RESHAPE_GROUP_WIDTH`.
   - Sends inner Basefold commitment, point, point length, and eval chunks.
   - Outputs `tidx_basefold`.

7. `JaggedShapeAir` or proof-shape integration
   - Checks `cumulative_heights` monotonicity and length.
   - Checks `reshape_log_height`, `total_evals`, `padded_total`, and chunk count.
   - Binds AIR/chip columns to the committed polynomial order.

## Claim Flow

The core claim flow is:

```text
per-AIR column claims
    -- proof-shape ordering / tail correction -->
native per-polynomial evals
    -- eq(z_col, i) batching -->
claimed_sum
    -- main jagged sumcheck -->
rho, expected_main
    -- q'(rho) reconstruction from col_evals -->
q_eval * f_at_rho == expected_main
    -- assist sumcheck + ROBP final check -->
f_at_rho is valid
    -- Basefold handoff -->
open reshaped q' columns at rho_row
```

The two critical soundness bridges are:

```text
q_eval * f_at_rho == main_sumcheck_expected_evaluation
h_at_rho_star * q_at_rho_star == assist_expected_evaluation
```

## Transcript Region

The Jagged transcript region should be contiguous for each opened commitment:

```text
1. observe native opening evaluations
2. sample z_col
3. for each main jagged sumcheck round:
     observe round polynomial evaluations
     sample round challenge
4. observe col_evals
5. observe f_at_rho
6. for each assist sumcheck round:
     observe round polynomial evaluations
     sample round challenge
```

After all Jagged rounds, the Basefold verifier consumes the inner proof using
the current transcript state.

Any deviation from this schedule must be documented because changing transcript
order changes the proof system.

## Buses

Expected external buses:

- From batch constraint:
  - `JaggedModuleBus`: start `tidx` and commitment-round metadata.
  - `JaggedOpeningClaimsBus`: ordered per-column opening claims.
  - optional batch randomness bus if batch constraint and Jagged share values.

- From proof shape:
  - `AirShapeBus`
  - `LiftedHeightsBus`
  - `JaggedCommitmentShapeBus`
  - `JaggedColumnIndexBus`

- To Basefold:
  - `BasefoldModuleBus`
  - `BasefoldCommitmentBus`
  - `BasefoldOpeningPointBus`
  - `BasefoldOpeningEvalsBus`
  - optional per-round metadata buses.

Expected internal buses:

- `JaggedTidxBus`
- `JaggedClaimedSumBus`
- `JaggedMainSumcheckBus`
- `JaggedRhoBus`
- `JaggedQEvalBus`
- `JaggedAssistSumcheckBus`
- `JaggedRobpBus`
- `JaggedBasefoldHandoffBus`

## Implementation Policy

Use OpenVM's stacking module as a reference, but apply the ownership rule from
`verifier_circuit_ownership.md`:

```text
visibility problem -> patch OpenVM/fork minimally
semantic problem   -> copy or rewrite into Ceno
```

For this module:

- The row-loop patterns and helper sub-AIR style can follow OpenVM.
- The Ceno jagged layout, sumcheck equations, ROBP predicate, transcript
  schedule, and Basefold handoff are semantic and must be Ceno-owned.
- Any copied OpenVM file must include upstream path, commit, status, and reason.

The native `mpcs::Jagged` implementation is the executable reference for
correctness. The recursion AIRs should match its verifier equations unless the
protocol is intentionally changed and the native prover/verifier are changed
with it.

## Open Questions

Before implementing the AIRs, finalize:

- The exact `gkr-backend` revision whose Jagged verifier is canonical for
  recursion.
- Whether the current native flattening division by `C_i` should be represented
  in AIRs or replaced by an equivalent no-division formulation.
- Whether `JAGGED_RESHAPE_GROUP_WIDTH = 8` is protocol-fixed or only an
  implementation batching detail.
- How proof shape constrains the order of witness/fixed eval vectors against
  jagged polynomial indices.
- Whether the unused opening-point length tag should be removed from the Jagged
  interface or explicitly constrained by the recursion circuit.
- How rotation claims are represented in the jagged column order.
- The final Basefold handoff bus payloads and transcript cursor contract.

These choices determine the exact trace layout and which helper AIRs can be
shared across Jagged and Basefold.
