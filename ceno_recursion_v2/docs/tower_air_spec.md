# GKR AIR Spec

This document captures the current behavior of each GKR-related AIR that lives in `src/tower`. It mirrors the code so we
can reason about constraints or plan refactors without diving back into Rust. Update the relevant section whenever an
AIR’s columns, constraints, or interactions change.

## TowerInputAir (`src/tower/input/air.rs`)

### Columns

| Field                 | Shape           | Description                                                          |
|-----------------------|-----------------|----------------------------------------------------------------------|
| `is_enabled`          | scalar          | Row selector (0 = padding).                                          |
| `proof_idx`           | scalar          | Outer proof loop index enforced by nested sub-AIRs.                  |
| `idx`                 | scalar          | Inner loop index enumerating AIR instances within a proof.           |
| `n_layer`             | scalar          | Number of active GKR layers for the proof.                           |
| `is_n_layer_zero`     | scalar          | Flag for `n_layer == 0` (drives “no interaction” branches).          |
| `is_n_layer_zero_aux` | `IsZeroAuxCols` | Witness used by `IsZeroSubAir` to enforce the zero test.             |
| `tidx`                | scalar          | Transcript cursor at start of the proof.                             |
| `r0_claim`            | `[D_EF]`        | Root numerator commitment supplied to `TowerLayerAir`.               |
| `w0_claim`            | `[D_EF]`        | Root witness commitment supplied to `TowerLayerAir`.                 |
| `q0_claim`            | `[D_EF]`        | Root denominator commitment supplied to `TowerLayerAir`.             |
| `alpha_logup`         | `[D_EF]`        | Transcript challenge sampled before passing inputs to GKR layers.    |
| `input_layer_claim`   | `[D_EF]`        | Folded claim returned from `TowerLayerAir`.                          |
| `layer_output_lambda` | `[D_EF]`        | Batching challenge sampled in the final GKR layer (zeros if unused). |
| `layer_output_mu`     | `[D_EF]`        | Reduction point sampled in the final GKR layer (zeros if unused).    |

### Row Constraints

- **Enablement / indexing**: A `NestedForLoopSubAir<2>` enforces boolean `is_enabled`, padding-after-padding, and
  consecutive `(proof_idx, idx)` pairs for enabled rows.
- **Zero test**: `IsZeroSubAir` checks `n_logup` against `is_n_logup_zero`, unlocking the “no interaction” path.
- **Input layer defaults**: When `n_logup == 0`, the input-layer claim must be `[0, α]` (numerator zero, denominator
  equals `alpha_logup`).
- **Transcript math**: Local expressions derive the transcript offsets for alpha sampling, per-layer reductions, and the
  xi-sampling window directly from `n_layer`. No auxiliary `n_max` adjustment is needed.

### Interactions

- **Internal buses**
    - `TowerLayerInputBus.send`: emits `(idx, tidx skip roots, r0/w0/q0_claim)` when interactions exist.
    - `TowerLayerOutputBus.receive`: pulls reduced `(idx, layer_idx_end, input_layer_claim, lambda, mu)` back.
- **External buses**
    - `TowerModuleBus.receive`: initial module message `(idx, tidx, n_logup)` per enabled row.
    - `BatchConstraintModuleBus.send`: forwards the final input-layer claim with the final transcript index.
    - `TranscriptBus`: sample `alpha_logup` and observe `q0_claim` only when `has_interactions`.

### Notes

- Local booleans `has_interactions` gate all downstream activity, so future refactors must keep those semantics aligned
  with the code branches.

## TowerLayerAir (`src/tower/layer/air.rs`)

### Columns

| Field                              | Shape         | Description                                                                |
|------------------------------------|---------------|----------------------------------------------------------------------------|
| `is_enabled`                       | scalar        | Row selector.                                                              |
| `proof_idx`                        | scalar        | Proof counter shared with input AIR.                                       |
| `idx`                              | scalar        | AIR index within the proof (matches the input AIR).                        |
| `is_first_air_idx`                 | scalar        | First row flag for each `(proof_idx, idx)` block.                          |
| `is_first`                         | scalar        | Indicates the first layer row of a proof.                                  |
| `is_dummy`                         | scalar        | Marks padding rows that still satisfy constraints.                         |
| `layer_idx`                        | scalar        | Layer number, enforced to start at 0 and increment per transition.         |
| `tidx`                             | scalar        | Transcript cursor at the start of the layer.                               |
| `lambda`                           | `[D_EF]`      | Fresh batching challenge sampled for non-root layers.                      |
| `lambda_prime`                     | `[D_EF]`      | Challenge inherited from the previous layer (root layer pins it to `1`).   |
| `mu`                               | `[D_EF]`      | Reduction point sampled from transcript.                                   |
| `sumcheck_claim_in`                | `[D_EF]`      | Combined claim passed to the layer sumcheck AIR.                           |
| `read_claim`                       | `[D_EF]`      | Folded product contribution with respect to `lambda`.                      |
| `read_claim_prime`                 | `[D_EF]`      | Companion folded claim with respect to `lambda_prime` (root = r₀).         |
| `write_claim`                      | `[D_EF]`      | Same as above for the write accumulator.                                   |
| `write_claim_prime`                | `[D_EF]`      | Companion write claim.                                                     |
| `logup_claim`                      | `[D_EF]`      | LogUp folded claim w.r.t. `lambda`.                                        |
| `logup_claim_prime`                | `[D_EF]`      | LogUp folded claim w.r.t. `lambda_prime` (root = q₀).                      |
| `num_read_count`                   | scalar        | Declared accumulator length for the read prod AIR (must equal `n_logup`).  |
| `num_write_count`                  | scalar        | Declared accumulator length for the write prod AIR (must equal `n_logup`). |
| `num_logup_count`                  | scalar        | Declared accumulator length for the logup AIR (must equal `n_logup`).      |
| `eq_at_r_prime`                    | `[D_EF]`      | Product of eq evaluations returned from sumcheck.                          |
| `r0_claim`, `w0_claim`, `q0_claim` | `[D_EF]` each | Root evaluations supplied by `TowerInputAir`.                              |

### Row Constraints

- **Looping**: `NestedForLoopSubAir<2>` continues to enforce boolean enablement, padding-after-padding, and
  lexicographic ordering for `(proof_idx, idx)`. `is_first_air_idx` scopes the per-proof input bus handshake to the very
  first active row, while `is_first` marks the first layer row.
- **Layer counter**: `layer_idx = 0` on the `is_first` row and increments by one on every transition flagged by the loop
  helper.
- **`lambda_prime` propagation**: On the root row, `lambda_prime` must equal `[1, 0, …, 0]`; on each transition the next
  row’s `lambda_prime` is constrained to equal the previous row’s sampled `lambda`. This lets downstream AIRs reuse the
  same logic for both initialization and continuing layers.
- **Root comparisons**: When `is_first = 1`, the `_prime` claims received from downstream AIRs must match the supplied
  `r0_claim`, `w0_claim`, `q0_claim`. This replaces the old local interpolation logic.
- **Inter-layer propagation**: `next.sumcheck_claim_in = read_claim + write_claim + logup_claim` on transitions. The
  `_prime` versions feed `sumcheck_claim_out = read_claim_prime + write_claim_prime + logup_claim_prime`, which is what
  the sumcheck AIR receives.
- **Count consistency**: `num_read_count`, `num_write_count`, and `num_logup_count` are all constrained to equal
  `n_logup`, and each is individually range-checked against ProofShape metadata via `AirShapeBus`.
- **Transcript timing**: Same `tidx` arithmetic as before, but now the post-sumcheck transcript window must also cover
  the sample/observe operations that the product/logup AIRs perform themselves.

### Interactions

- **Layer buses**
    - `layer_input.receive`: only on the first non-dummy row; provides `(idx, tidx, r0/w0/q0_claim)`.
    - `layer_output.send`: on the last non-dummy row; reports `(idx, tidx_end, layer_idx_end, folded claim, lambda, mu)`
      back to `TowerInputAir` so the caller can record the transcript state for downstream verifiers.
- **Sumcheck buses**
    - `sumcheck_input.send`: for non-root layers, dispatches `(layer_idx, is_last_layer, tidx + D_EF, claim)` to the
      sumcheck AIR.
    - `sumcheck_output.receive`: ingests `(claim_out, eq_at_r_prime)` and re-encodes them into local columns.
    - `sumcheck_challenge.send`: posts the `mu` challenge as round 0 for the next layer’s sumcheck.
- **Transcript bus**
    - Samples `lambda` (non-root) and `mu`, observes all `p/q` evaluations.
- **Xi randomness bus**
    - On the proof’s final layer, sends `mu` as the shared xi challenge consumed by later modules.
- **Prod/logup buses**
    - Sends `(idx, layer_idx, tidx, lambda, lambda_prime, mu)` to the read/write prod AIRs every row (dummy rows are
      masked out). Receives back both `lambda_claim` and `lambda_prime_claim` along with `num_read_count` /
      `num_write_count`.
    - Sends the same challenge payload to the logup AIR and receives its dual claims plus `num_logup_count`.
    - No separate “init” buses exist anymore; setting `lambda_prime = 1` on the root row instructs the sub-AIRs to act
      as
      the initialization accumulators whose outputs are compared directly against `r0/w0/q0`.

### Notes

- Dummy rows allow reusing the same AIR width even when no layer work is pending; constraints are guarded by
  `is_not_dummy` to avoid accidentally constraining padding rows.
- The transcript math (5·`D_EF` per layer after sumcheck) must stay synchronized with `TowerInputAir`’s tidx
  bookkeeping.

## TowerProdSumCheckClaimAir (`src/tower/layer/prod_claim/air.rs`)

### Columns & Loops

- `NestedForLoopSubAir<2>` enumerates `(proof_idx, idx)` and treats `layer_idx` as an inner counter controlled by
  `is_first_layer`; within each `(proof_idx, idx, layer_idx)` triple an `index_id` column counts accumulator rows.
- Columns include:
    - Loop/indexing flags (`is_enabled`, `is_first_layer`, `is_first`, `is_dummy`, `index_id`, `num_read_count`,
      `num_write_count`).
    - Metadata observed from `TowerLayerAir`: `layer_idx`, `tidx`, challenges `lambda`, `lambda_prime`, `mu`.
    - Transcript observations: `p_xi_0`, `p_xi_1`, interpolated `p_xi`.
    - Dual running powers/sums: `(pow_lambda, acc_sum)` for the standard sumcheck, `(pow_lambda_prime, acc_sum_prime)`
      for
      the root-compatible accumulator.

### Constraints

- Clamp `index_id` to zero on the first row of every layer triple, increment it while `stay_in_layer = 1`, and enforce
  `index_id + 1 = num_read_count` / `num_write_count` on the rows that send results.
- Recompute `p_xi` via the usual linear interpolation in `mu`.
- Update both accumulators:
    - `acc_sum_next = acc_sum + p_xi * pow_lambda`, with `pow_lambda_next = pow_lambda * lambda`.
    - `acc_sum_prime_next = acc_sum_prime + (p_xi_0 * p_xi_1) * pow_lambda_prime`,
      `pow_lambda_prime_next = pow_lambda_prime * lambda_prime`.
- The root-layer behavior falls out automatically: when `lambda_prime = 1`, the `_prime` accumulator simply sums
  pairwise products, so the final row exports `r0`/`w0`-style claims.

### Interactions

- First row per layer triple receives
  `TowerProdLayerChallengeMessage { idx, layer_idx, tidx, lambda, lambda_prime, mu }`.
- Final row sends `TowerProdSumClaimMessage { lambda_claim = acc_sum, lambda_prime_claim = acc_sum_prime }` alongside
  the
  appropriate `num_*_count`. Read/write variants simply use different buses.

## TowerLogUpSumCheckClaimAir (`src/tower/layer/logup_claim/air.rs`)

### Columns & Loops

- Shares the same `(proof_idx, idx)` outer loop and `index_id` accumulator counter as the product AIR.
- Columns:
    - Loop metadata plus `num_logup_count`.
    - Transcript data `p_xi_0`, `p_xi_1`, `q_xi_0`, `q_xi_1`, interpolated `p_xi`, `q_xi`.
    - Challenges `lambda`, `lambda_prime`, `mu`.
    - Running powers `pow_lambda`, `pow_lambda_prime`.
    - Accumulators: `acc_sum` for the standard `(p_xi + lambda * q_xi)` contribution, `acc_p_cross`, `acc_q_cross` for
      the
      log-up initialization terms that previously lived in their own AIR.

### Constraints

- Recompute `p_xi`, `q_xi` every row, then derive the cross terms
  `p_cross = p_xi_0 * q_xi_1 + p_xi_1 * q_xi_0`, `q_cross = q_xi_0 * q_xi_1`.
- Accumulators:
    - `acc_sum_next = acc_sum + pow_lambda * (p_xi + lambda * q_xi)`.
    - `acc_p_cross_next = acc_p_cross + pow_lambda_prime * p_cross`.
    - `acc_q_cross_next = acc_q_cross + pow_lambda_prime * lambda_prime * q_cross`.
      Root-layer behavior again follows from `lambda_prime = 1`.
- `pow_lambda` and `pow_lambda_prime` follow the same multiplicative recurrence as in the product AIR.
- `index_id` bookkeeping and “final row sends” conditions mirror the product AIR.

### Interactions

- Receives the layer challenge message with both `lambda` and `lambda_prime` on the first row.
- Final row sends `TowerLogupClaimMessage { lambda_claim = acc_sum, lambda_prime_claim = acc_q_cross }` plus
  `num_logup_count`. (The `acc_p_cross` value remains internal because only the denominator-style accumulator is needed
  upstream at the moment.)

## TowerLogUpSumCheckClaimAir (`src/tower/layer/logup_claim/air.rs`)

### Columns & Loops

- Shares the `(proof_idx, idx, layer_idx)` nested-loop structure and reuses `index_id` to count accumulator rows.
- Columns mirror the product AIR plus the denominator evaluations: `is_enabled`, the loop counters/flags,
  `(p_xi_0, p_xi_1, q_xi_0, q_xi_1)`, interpolated `(p_xi, q_xi)`, `lambda`, `mu`, `pow_lambda`, `acc_sum`,
  `index_id`, and `num_logup_count`.

### Constraints

- Recomputes both `p_xi` and `q_xi` in every row.
- Uses the existing log-up contribution `acc_sum_next = acc_sum + (lambda * q_xi) * pow_lambda`.
- `index_id` obeys the same initialization/increment/final-row checks against `num_logup_count` as the product AIR.
- Only the final accumulator row per `(proof_idx, idx, layer_idx)` may drive `TowerLogupClaimBus`.

### Interactions

- Layer metadata is consumed on the row flagged by `is_first_layer`.
- Folded logup claim is emitted exactly once per triple when the accumulator row counter reaches `num_logup_count`.

## TowerLayerSumcheckAir (`src/tower/sumcheck/air.rs`)

### Columns

| Field                         | Shape    | Description                                                 |
|-------------------------------|----------|-------------------------------------------------------------|
| `is_enabled`                  | scalar   | Row selector.                                               
| `proof_idx`                   | scalar   | Proof counter.                                              
| `idx`                         | scalar   | Module index within the proof (mirrors `TowerLayerAir`).    
| `layer_idx`                   | scalar   | Layer whose sumcheck is being executed.                     
| `is_first_idx`                | scalar   | First sumcheck row for the current `(proof_idx, idx)` pair. |
| `is_first_layer`              | scalar   | First round row for the current layer.                      
| `is_first_round`              | scalar   | First round inside the layer.                               
| `is_dummy`                    | scalar   | Padding flag.                                               
| `is_last_layer`               | scalar   | Whether this layer is the final GKR layer.                  
| `round`                       | scalar   | Sub-round index within the layer (0 .. layer_idx-1).        
| `tidx`                        | scalar   | Transcript cursor before reading evaluations.               
| `ev1`, `ev2`, `ev3`           | `[D_EF]` | Polynomial evaluations at points 1,2,3 (point 0 inferred).  
| `claim_in`, `claim_out`       | `[D_EF]` | Incoming/outgoing claims for each round.                    
| `prev_challenge`, `challenge` | `[D_EF]` | Previous xi component and the new random challenge.         
| `eq_in`, `eq_out`             | `[D_EF]` | Running eq accumulator before/after this round.             

### Row Constraints

- **Looping**: `NestedForLoopSubAir<3>` now iterates over `(proof_idx, idx, layer_idx)` with the sumcheck round serving
  as the innermost loop. The `is_first_idx` flag gates reset logic when we advance to a new module instance, while
  `is_first_layer` protects the per-layer bookkeeping just before the round loop begins.
- **Round counter**: `round` starts at 0 and increments each transition; final round enforces `round = layer_idx - 1`.
- **Eq accumulator**: `eq_in = 1` on the first round; `eq_out = update_eq(eq_in, prev_challenge, challenge)` and
  propagates forward.
- **Claim flow**: `claim_out` computed via `interpolate_cubic_at_0123` using `(claim_in - ev1)` as `ev0`;
  `next.claim_in = claim_out` across transitions.
- **Transcript timing**: Each transition bumps `next.tidx = tidx + 4·D_EF` (three observations + challenge sample).

### Interactions

- `sumcheck_input.receive`: first non-dummy round pulls `(layer_idx, is_last_layer, tidx, claim)` from `TowerLayerAir`.
- `sumcheck_output.send`: last non-dummy round returns `(claim_out, eq_at_r_prime)` to the layer AIR.
- `sumcheck_challenge.receive/send`: enforces challenge chaining between layers/rounds (`prev_challenge` from prior
  layer, `challenge` published for the next layer or eq export).
- All three buses now include the `idx` field so messages disambiguate distinct module instances inside the same proof.
- `transcript_bus.observe_ext`: records `ev1/ev2/ev3`, followed by `sample_ext` of `challenge`.

### Notes

- Dummy rows short-circuit all bus traffic; guard send/receive calls with `is_not_dummy`.
- The layout assumes cubic polynomials (degree 3) and would need updates if the sumcheck arity changes.
