# Tower AIR Spec

This document captures the current behavior of each tower-related AIR that lives in `src/tower`. We use a
spec-driven development approach for this tower work: update this spec first when an AIR’s columns, constraints, or
interactions need to change, then an AI agent or human developer can port the spec changes into the codebase and keep
the implementation in lockstep with the documented contract.

## Protocol Math Reference

The tower protocol math is specified in
[tower_module_design.md](tower_module_design.md#protocol-math). This AIR spec should describe how each AIR realizes that
contract through columns, buses, row loops, and local constraints. Keep per-AIR accumulator formulas here when they are
needed to debug constraints, but do not duplicate the global layer-reduction source of truth.

Use [tower_air_review_checklist.md](tower_air_review_checklist.md) to track spec-to-code review progress.

## TowerInputAir (`src/tower/input/air.rs`)

### Columns

| Field                      | Shape           | Description                                                          |
|----------------------------|-----------------|----------------------------------------------------------------------|
| `is_enabled`               | scalar          | Row selector (0 = padding).                                          |
| `proof_idx`                | scalar          | Outer proof loop index enforced by nested sub-AIRs.                  |
| `idx`                      | scalar          | Structural row counter inside one proof; constrained to `chip_idx`.  |
| `chip_idx`                 | scalar          | Proof-local chip proof index, supplied by `ProofShapeAir`.           |
| `num_layers`               | scalar          | Number of active GKR layers for the proof.                           |
| `is_num_layers_zero`       | scalar          | Flag for `num_layers == 0` (drives “no interaction” branches).       |
| `is_num_layers_zero_aux`   | `IsZeroAuxCols` | Witness used by `IsZeroSubAir` to enforce the zero test.             |
| `tidx`                     | scalar          | Transcript cursor at start of the proof.                             |
| `r0_claim`                 | `[D_EF]`        | Product of read root out-eval pairs returned to `ProofShapeAir`.     |
| `w0_claim`                 | `[D_EF]`        | Product of write root out-eval pairs returned to `ProofShapeAir`.    |
| `p0_claim`                 | `[D_EF]`        | Root LogUp numerator claim returned to `ProofShapeAir`.              |
| `q0_claim`                 | `[D_EF]`        | Root LogUp denominator claim returned to `ProofShapeAir`.            |
| `alpha_logup`              | `[D_EF]`        | Current Rust column name for the root batching challenge `lambda_1`.  |
| `r_1`                      | `[D_EF]`        | Root one-variable interpolation point for the initial claim.          |
| `initial_tower_claim`      | `[D_EF]`        | Batched initial claim `C_1(r_1)` sent to `TowerLayerAir`.             |
| `input_layer_claim`        | `[D_EF]`        | Folded claim returned from `TowerLayerAir`.                          |
| `layer_output_lambda_next` | `[D_EF]`        | Batching challenge sampled in the final GKR layer (zeros if unused). |
| `layer_output_mu`          | `[D_EF]`        | Reduction point sampled in the final GKR layer (zeros if unused).    |

### Row Constraints

- **Enablement / identity**: Constraints enforce boolean `is_enabled`, padding-after-padding, and one enabled
  `TowerInputAir` row per `(proof_idx, chip_idx)` tower proof. `chip_idx` is the proof-local index of the chip proof, not
  the VK-assigned `chip_id`. The structural `idx` column is constrained to equal `chip_idx` on enabled rows.
- **Zero test**: `IsZeroSubAir` checks `num_layers` against `is_num_layers_zero`, unlocking the “no interaction” path.
- **Input layer defaults**: When `num_layers == 0`, the root claims must be `r0_claim = 1`, `w0_claim = 1`,
  `p0_claim = 0`, and `q0_claim = 1`; the input-layer claim must be `[0, alpha_logup]` (numerator zero, denominator
  equals `alpha_logup`).
- **Transcript math**: Local expressions derive the transcript offsets for batching-challenge sampling, per-layer reductions, and the
  xi-sampling window directly from `num_layers`. No auxiliary `n_max` adjustment is needed.
- **Root claim export**: `TowerInputAir` returns `(r0_claim, w0_claim, p0_claim, q0_claim)` to `ProofShapeAir`.
  The read/write roots are:

  ```text
  r0_claim = product_k r_out_evals[k][0] * r_out_evals[k][1]
  w0_claim = product_k w_out_evals[k][0] * w_out_evals[k][1]
  ```

  Proof-shape uses those chip-level values to enforce:

  ```text
  prod_chip r0_claim = prod_chip w0_claim
  sum_chip p0_claim / q0_claim = 0 / x
  ```
- **Initial claim assembly**: `TowerInputAir` samples the root batching challenge and root interpolation point
  `(lambda_1, r_1)`, passes them to the read, write, and LogUp root fold AIRs, and receives the three contributions:

  ```text
  initial_tower_claim = read_initial_claim + write_initial_claim + logup_initial_claim
  ```

  Those contributions are computed from the same root out-eval rows that produce
  `(r0_claim, w0_claim, p0_claim, q0_claim)`.

### Interactions

- **Internal buses**
    - `Tower{Read,Write}RootInputBus.send`: starts root product folding with
      `(chip_idx, claim_tidx, lambda_1, r_1, lambda_1_start, num_prod_count)`.
    - `TowerLogupRootInputBus.send`: starts root LogUp folding with
      `(chip_idx, claim_tidx, lambda_1, r_1, lambda_1_start, num_logup_count)`.
    - `Tower{Read,Write}RootBus.receive`: pulls `r0_claim` or `w0_claim` from the product root folds.
    - `TowerLogupRootBus.receive`: pulls `(p0_claim, q0_claim, logup_initial_claim)` from the LogUp root fold.
    - `Tower{Read,Write}InitBus.receive`: pulls the read/write contributions to `C_1(r_1)`.
    - `TowerLayerInputBus.send`: emits
      `(chip_idx, layer_tidx, num_layers, num_read_specs, num_write_specs, num_logup_specs, initial_tower_claim)`
      when interactions exist.
    - `TowerLayerOutputBus.receive`: pulls reduced
      `(chip_idx, layer_idx_end, input_layer_claim, lambda_next, mu)` back.
- **External buses**
    - `TowerModuleBus.receive`: proof-shape message
      `(proof_idx, chip_idx, num_layers, num_read_specs, num_write_specs, num_logup_specs)` per enabled row.
    - `TowerRootClaimBus.send`: returns `(chip_idx, r0_claim, w0_claim, p0_claim, q0_claim)` to `ProofShapeAir`.
    - `MainBus.send`: forwards the final input-layer claim with the final transcript index.
    - `TranscriptBus`: sample the root batching/interpolation challenges and observe root claim data only when
      `has_interactions`. The root input buses may carry sampled values into child AIRs as ordinary dataflow; only the
      transcript bus fixes sample/observe chronology.

## TowerLayerAir (`src/tower/layer/air.rs`)

### Columns

| Field                              | Shape         | Description                                                                |
|------------------------------------|---------------|----------------------------------------------------------------------------|
| `is_enabled`                       | scalar        | Row selector.                                                              |
| `proof_idx`                        | scalar        | Proof counter shared with input AIR.                                       |
| `chip_idx`                         | scalar        | Proof-local chip proof index used to scope tower claim/sumcheck messages.  |
| `is_first_proof_idx`               | scalar        | First row flag for each `proof_idx` group.                                 |
| `is_first_chip_idx`                | scalar        | First row flag for each `(proof_idx, chip_idx)` tower proof.               |
| `is_noop`                          | scalar        | Zero-test output: `is_noop = 1` iff `num_layers = 0`.                      |
| `is_num_layers_zero_aux`           | `IsZeroAux`   | Witness used to enforce the `num_layers == 0` zero test.                   |
| `layer_idx`                        | scalar        | Layer number, enforced to start at 0 and increment per transition.         |
| `tidx`                             | scalar        | Transcript cursor at the start of the layer.                               |
| `lambda_next`                      | `[D_EF]`      | Fresh/outgoing batching challenge for the next-layer claim.                |
| `lambda_cur`                       | `[D_EF]`      | Current sumcheck batching challenge (root layer pins it to `1`).           |
| `mu`                               | `[D_EF]`      | Reduction point sampled from transcript.                                   |
| `sumcheck_claim_in`                | `[D_EF]`      | Combined claim passed to the layer sumcheck AIR.                           |
| `read_claim_next`                 | `[D_EF]`      | Folded product contribution with respect to `lambda_next`.                 |
| `read_claim_cur`                  | `[D_EF]`      | Folded product contribution with respect to `lambda_cur`.                  |
| `write_claim_next`                | `[D_EF]`      | Same as above for the write accumulator.                                   |
| `write_claim_cur`                 | `[D_EF]`      | Companion write claim with respect to `lambda_cur`.                        |
| `logup_claim_next`                | `[D_EF]`      | LogUp folded claim with respect to `lambda_next`.                          |
| `logup_claim_cur`                 | `[D_EF]`      | LogUp folded claim with respect to `lambda_cur`.                           |
| `num_read_count`                   | scalar        | Declared accumulator length for the read product AIR.                      |
| `num_write_count`                  | scalar        | Declared accumulator length for the write product AIR.                     |
| `num_logup_count`                  | scalar        | Declared accumulator length for the LogUp AIR.                             |
| `read_lambda_next_end`             | `[D_EF]`      | `lambda_next` power after the read product group.                          |
| `read_lambda_cur_end`              | `[D_EF]`      | `lambda_cur` power after the read product group.                           |
| `write_lambda_next_end`            | `[D_EF]`      | `lambda_next` power after the write product group.                         |
| `write_lambda_cur_end`             | `[D_EF]`      | `lambda_cur` power after the write product group.                          |
| `eq_at_r_prime`                    | `[D_EF]`      | Product of eq evaluations returned from sumcheck.                          |
| `initial_tower_claim`             | `[D_EF]`      | Batched initial claim `C_1(r_1)` supplied by `TowerInputAir`.              |

### Row Constraints

- **Looping**: Loop constraints enforce boolean enablement, padding-after-padding, and grouping by
  `(proof_idx, chip_idx)`. `NestedForLoopSubAir<2>` tracks the two outer counters `proof_idx` and `chip_idx`, while
  `layer_idx` is the innermost counter. `is_first_proof_idx` resets the outer proof counter; `is_first_chip_idx` scopes
  the tower input bus handshake to the first active row for that chip tower proof and also marks `layer_idx = 0`.
- **Layer counter**: `layer_idx = 0` on the `is_first_chip_idx` row and increments by one on every transition flagged by
  the loop helper.
- **`lambda_cur` propagation**: On the first active tower row, `lambda_cur` must equal `[1, 0, …, 0]`; on each transition
  the next row’s `lambda_cur` is constrained to equal the previous row’s sampled `lambda_next`. This lets downstream AIRs
  reuse the same logic for both initialization and continuing layers.
- **Initial claim**: When `is_first_chip_idx = 1`, the layer sumcheck starts from the supplied `initial_tower_claim = C_1(r_1)`.
  The `*_claim_cur` values received from downstream AIRs are used to assemble `T_i(rho)`, not to recompute
  `r0_claim`/`w0_claim`.
- **Inter-layer propagation**: `next.sumcheck_claim_in = read_claim_next + write_claim_next + logup_claim_next` on transitions. The
  current-claim versions feed `sumcheck_claim_out = read_claim_cur + write_claim_cur + logup_claim_cur`, which is what
  the sumcheck AIR receives.
- **Count consistency**: `num_layers`, `num_read_count`, `num_write_count`, and `num_logup_count` are anchored by the
  first-row shape metadata from `TowerInputAir` and must stay constant across the chip's tower rows.
- **No-op rows**: `IsZeroSubAir` enforces `is_noop` iff `num_layers == 0`; no-op rows allow reusing the same AIR width
  when no layer work is pending, and bus traffic is guarded by `is_not_noop`.
- **Transcript timing**: Same `tidx` arithmetic as before, but now the post-sumcheck transcript window must also cover
  the sample/observe operations that the product/logup AIRs perform themselves.

### Interactions

- **Layer buses**
    - `layer_input.receive`: only on the first non-no-op row; provides
      `(chip_idx, layer_tidx, num_layers, num_read_specs, num_write_specs, num_logup_specs, initial_tower_claim)`.
    - `layer_output.send`: on the last non-no-op row; reports
      `(chip_idx, tidx_end, layer_idx_end, input_layer_claim, lambda_next, mu)`
      back to `TowerInputAir` so the caller can record the transcript state for downstream verifiers.
- **Sumcheck buses**
    - `sumcheck_input.send`: for non-root layers, dispatches
      `(chip_idx, layer_idx, is_last_layer, tidx + D_EF, claim)` to the sumcheck AIR.
    - `sumcheck_output.receive`: ingests `(chip_idx, layer_idx, claim_out, eq_at_r_prime)` and re-encodes them into local
      columns.
    - `sumcheck_challenge.send`: posts `(chip_idx, layer_idx, round = 0, mu)` as round 0 for the next layer’s sumcheck.
- **Transcript bus**
    - Samples `lambda_next` for non-root layers and `mu` for every active layer.
    - Product and LogUp child-claim observations are owned by the product/LogUp claim AIRs, not by `TowerLayerAir`.
- **Prod/logup buses**
    - Sends claim-folding inputs only on non-root layers; root output/init folding is owned by `TowerInputAir`'s root buses.
    - Sends read product input with `prod_offset = 0`, start powers equal to one, and `num_prod_count = num_read_count`.
    - Receives read product claims plus `read_lambda_next_end` and `read_lambda_cur_end`, then sends write product input with
      `prod_offset = num_read_count`, start powers equal to the read end powers, and `num_prod_count = num_write_count`.
    - Receives write product claims plus `write_lambda_next_end` and `write_lambda_cur_end`, then sends the LogUp input
      with start powers equal to the write end powers and `num_logup_count`.
    - Receives back both `lambda_next_claim` and `lambda_cur_claim` from each claim AIR.
    - Root init buses are outside `TowerLayerAir`; this AIR receives the already assembled
      `initial_tower_claim = C_1(r_1)` from `TowerInputAir`.

## TowerProdClaimAir (`src/tower/layer/prod_claim/air.rs`)

### Columns

There are two product claim AIR instances with the same contract:

- `TowerProdReadClaimAir` folds read product specs;
- `TowerProdWriteClaimAir` folds write product specs.

The read variant uses:

```text
prod_offset = 0
num_prod_count = num_read_specs
```

The write variant uses:

```text
prod_offset = num_read_specs
num_prod_count = num_write_specs
```

The trace needs columns equivalent to:

- loop metadata: `is_enabled`, `(proof_idx, chip_idx)` scope, and optional `layer_idx`;
- a mode selector for `DeriveLayerClaims` versus `DeriveOutputClaim`;
- `claim_tidx` for transcript observation of the product claim tuple;
- `num_prod_count` and the active row counter inside the selected group;
- product tuple values `P_k(0)` and `P_k(1)`;
- layer-mode challenges and powers: `lambda_next`, `lambda_cur`, `mu`, `lambda_next_start`, `lambda_cur_start`,
  running next/current powers, and end powers;
- layer-mode accumulators for `next_claim` and `eval_claim`;
- output-mode challenges and powers: `lambda_1`, `r_1`, `lambda_1_start`, and running `init_pow`;
- output-mode accumulators for `output_claim` and `initial_claim`.

So if a chip has `num_read_specs = 4` and `num_write_specs = 6`, the read product claim AIR needs 4 active rows and the
write product claim AIR needs 6 active rows. Together they fold the 10 product specs. LogUp specs are folded separately by
`TowerLogupClaimAir`.

### Row Constraints

The AIR supports two modes:

```text
DeriveLayerClaims:
  derive (eval_claim, next_claim) for one active tower layer

DeriveOutputClaim:
  derive the chip-level root output product claim plus the C_1 contribution
```

In both modes, each active row consumes one product spec tuple:

```text
P_k(0), P_k(1)
```

For row `k` inside the read or write product group, define:

```text
A0_k = P_k(0)
A1_k = P_k(1)

A_mu_k    = (1 - mu) * A0_k + mu * A1_k
A_r1_k    = (1 - r_1) * A0_k + r_1 * A1_k
A_cross_k = A0_k * A1_k
```

In `DeriveLayerClaims` mode, `A0_k = Prod_{prod_offset + k}^{i+1}(rho, 0)` and
`A1_k = Prod_{prod_offset + k}^{i+1}(rho, 1)`. In `DeriveOutputClaim` mode, they are the root out-eval pair for the
selected read or write product spec.

#### DeriveLayerClaims Mode

The next-layer product claim is:

```text
prod_next_claim =
    sum_k lambda_next^(prod_offset + k) * A_mu_k
```

Equivalently, with `next_pow_0 = lambda_next_start = lambda_next^prod_offset`:

```text
next_acc_{k+1} = next_acc_k + next_pow_k * A_mu_k
next_pow_{k+1} = next_pow_k * lambda_next
```

The product expected-evaluation contribution is the product contribution to `T_i(rho)`:

```text
prod_eval_claim =
    sum_k lambda_cur^(prod_offset + k) * A_cross_k
```

Equivalently, with `current_pow_0 = lambda_cur_start = lambda_cur^prod_offset`:

```text
eval_acc_{k+1} = eval_acc_k + current_pow_k * A_cross_k
current_pow_{k+1} = current_pow_k * lambda_cur
```

The final active row sends:

```text
TowerProdSumClaimMessage {
  chip_idx,
  layer_idx,
  lambda_next_claim       = prod_next_claim,
  lambda_cur_claim        = prod_eval_claim,
  lambda_next_end         = lambda_next_start * lambda_next^num_prod_count,
  lambda_cur_end          = lambda_cur_start  * lambda_cur^num_prod_count
}
```

`lambda_next_start` and `lambda_cur_start` must equal the batching powers at `prod_offset`:

```text
lambda_next_start = lambda_next^prod_offset
lambda_cur_start  = lambda_cur^prod_offset
```

For the read product AIR, `prod_offset = 0` and both start powers are one. For the write product AIR,
`prod_offset = num_read_specs`, and both start powers must equal the end powers exported by the read product AIR.

#### DeriveOutputClaim Mode

The output product claim is:

```text
prod_output_claim = product_k A_cross_k
```

Equivalently:

```text
output_acc_0     = 1
output_acc_{k+1} = output_acc_k * A_cross_k
```

The same rows also derive the product contribution to the initial tower claim:

```text
prod_initial_claim =
    sum_k lambda_1^(prod_offset + k) * A_r1_k
```

Equivalently, with `init_pow_0 = lambda_1_start = lambda_1^prod_offset`:

```text
init_acc_0     = 0
init_acc_{k+1} = init_acc_k + init_pow_k * A_r1_k
init_pow_{k+1} = init_pow_k * lambda_1
```

For the read instance, `output_claim = r0_claim` and `lambda_1_start = 1`. For the write instance,
`output_claim = w0_claim` and `lambda_1_start = lambda_1^num_read_specs`. This mode has no `mu` interpolation and no
contribution to `T_i(rho)` or `C_{i+1}`; its `lambda_1` weights contribute only to `C_1(r_1)`.

The final active row sends `output_claim = output_acc_end` and `initial_claim = init_acc_end`.

The common loop constraints are:

- One active row corresponds to one product spec.
- The mode bit must be constant across the group.
- `DeriveLayerClaims` mode is grouped by non-root `(proof_idx, chip_idx, layer_idx)` inside each read/write AIR instance.
- `DeriveOutputClaim` mode is grouped by `(proof_idx, chip_idx)` inside each read/write AIR instance.
- `DeriveLayerClaims` mode initializes additive accumulators to zero and power accumulators from the input message.
- `DeriveOutputClaim` mode initializes the multiplicative output accumulator to one, initializes the additive
  initial-claim accumulator to zero, and initializes `init_pow` from the root input message.
- In `DeriveOutputClaim` mode, each observed root out-eval pair must update both `output_acc` and `init_acc`; this binds
  the root claim and initial claim to the same data.
- The mode selector must gate bus sends/receives so a row group produces exactly the messages for its selected mode.

### Interactions

In `DeriveLayerClaims` mode, the AIR receives the non-root layer input message on the first row:

```text
TowerProdLayerInputMessage {
  chip_idx,
  layer_idx,
  tidx,
  lambda_next, // next-layer batching challenge
  lambda_cur,  // current-layer batching challenge
  mu,
  prod_offset,
  lambda_next_start,
  lambda_cur_start,
  num_prod_count
}
```

and sends on the final active row:

```text
TowerProdSumClaimMessage {
  chip_idx,
  layer_idx,
  lambda_next_claim       = prod_next_claim,
  lambda_cur_claim        = prod_eval_claim,
  lambda_next_end         = lambda_next_start * lambda_next^num_prod_count,
  lambda_cur_end          = lambda_cur_start  * lambda_cur^num_prod_count
}
```

In `DeriveOutputClaim` mode, the AIR receives the root input bus message on the first row:

```text
Tower{Read,Write}RootInputBus {
  chip_idx,
  claim_tidx,
  lambda_1,
  r_1,
  lambda_1_start,
  num_prod_count
}
```

and sends both product root-mode messages from the same final active row:

```text
Tower{Read,Write}RootBus {
  chip_idx,
  output_claim
}

Tower{Read,Write}InitBus {
  chip_idx,
  initial_claim
}
```

The AIR owns transcript observations for the active product child claims. It does not own the layer-level sumcheck check;
`TowerLayerAir` combines the returned product, write-product, and LogUp claims.

## TowerLogUpSumCheckClaimAir (`src/tower/layer/logup_claim/air.rs`)

### Columns

This AIR folds only the LogUp specs. Product specs are folded by the read/write product claim AIRs. If a chip has
`num_prod_specs = 10` and `num_logup_specs = 20`, this AIR needs 20 active accumulator rows for that layer; the 10
product specs are handled by the read/write product claim AIRs.

The LogUp batching offset is:

```text
logup_offset = num_read_specs + num_write_specs = num_prod_specs
```

The trace needs columns equivalent to:

- loop metadata: `is_enabled`, `(proof_idx, chip_idx)` scope, and optional `layer_idx`;
- a mode selector for `DeriveLayerClaims` versus `DeriveOutputClaim`;
- `claim_tidx` for transcript observation of the LogUp tuple;
- `num_logup_count` and the active row counter inside the selected group;
- LogUp tuple values `P_k(0)`, `P_k(1)`, `Q_k(0)`, and `Q_k(1)`;
- layer-mode challenges and powers: `lambda_next`, `lambda_cur`, `mu`, `lambda_next_start`, `lambda_cur_start`, and
  running next/current powers;
- layer-mode accumulators for `next_claim` and `eval_claim`;
- output-mode challenges and powers: `lambda_1`, `r_1`, `lambda_1_start`, and running `init_pow`;
- output-mode fraction accumulators for `(p0_claim, q0_claim)` and an accumulator for `logup_initial_claim`.

### Row Constraints

The AIR supports two modes:

```text
DeriveLayerClaims:
  derive (eval_claim, next_claim) for one active tower layer

DeriveOutputClaim:
  derive the chip-level root LogUp fractional pair (p0_claim, q0_claim) plus the C_1 contribution
```

In both modes, each active row consumes one LogUp spec tuple:

```text
P_k(0), P_k(1),
Q_k(0), Q_k(1)
```

For row `k`, define:

```text
P0_k = P_k(0)
P1_k = P_k(1)
Q0_k = Q_k(0)
Q1_k = Q_k(1)

P_mu_k = (1 - mu) * P0_k + mu * P1_k
Q_mu_k = (1 - mu) * Q0_k + mu * Q1_k

P_r1_k = (1 - r_1) * P0_k + r_1 * P1_k
Q_r1_k = (1 - r_1) * Q0_k + r_1 * Q1_k

P_cross_k = P0_k * Q1_k + P1_k * Q0_k
Q_cross_k = Q0_k * Q1_k
```

In `DeriveLayerClaims` mode, these are the child claims at `(rho, 0)` and `(rho, 1)`. In `DeriveOutputClaim` mode,
they are the root LogUp out-eval tuple.

#### DeriveLayerClaims Mode

The next-layer LogUp claim is:

```text
logup_next_claim =
    sum_k lambda_next^(logup_offset + 2k)     * P_mu_k
  + sum_k lambda_next^(logup_offset + 2k + 1) * Q_mu_k
```

Equivalently, with `next_pow_0 = lambda_next_start = lambda_next^logup_offset`:

```text
next_acc_{k+1} = next_acc_k + next_pow_k * (P_mu_k + lambda_next * Q_mu_k)
next_pow_{k+1} = next_pow_k * lambda_next^2
```

The LogUp expected-evaluation contribution is the LogUp contribution to `T_i(rho)`:

```text
logup_eval_claim =
    sum_k lambda_cur^(logup_offset + 2k)     * P_cross_k
  + sum_k lambda_cur^(logup_offset + 2k + 1) * Q_cross_k
```

Equivalently, with `current_pow_0 = lambda_cur_start = lambda_cur^logup_offset`:

```text
eval_acc_{k+1} = eval_acc_k + current_pow_k * (P_cross_k + lambda_cur * Q_cross_k)
current_pow_{k+1} = current_pow_k * lambda_cur^2
```

`lambda_next_start` and `lambda_cur_start` must equal the product write end powers:

```text
lambda_next_start = lambda_next^logup_offset
lambda_cur_start  = lambda_cur^logup_offset
```

Each LogUp row consumes two consecutive batching powers:

```text
P_k next weight    = lambda_next^(logup_offset + 2k)
Q_k next weight    = lambda_next^(logup_offset + 2k + 1)
P_k current weight = lambda_cur^(logup_offset + 2k)
Q_k current weight = lambda_cur^(logup_offset + 2k + 1)
```

The final active row sends:

```text
TowerLogupClaimMessage {
  chip_idx,
  layer_idx,
  lambda_next_claim       = logup_next_claim,
  lambda_cur_claim        = logup_eval_claim
}
```

#### DeriveOutputClaim Mode

The output LogUp fractional pair folds by fraction addition:

```text
p_acc_0 = 0
q_acc_0 = 1

p_acc_{k+1} = p_acc_k * Q_cross_k + P_cross_k * q_acc_k
q_acc_{k+1} = q_acc_k * Q_cross_k
```

The same rows also derive the LogUp contribution to the initial tower claim:

```text
logup_initial_claim =
    sum_k lambda_1^(logup_offset + 2k)     * P_r1_k
  + sum_k lambda_1^(logup_offset + 2k + 1) * Q_r1_k
```

Equivalently, with `init_pow_0 = lambda_1_start = lambda_1^logup_offset`:

```text
init_acc_0     = 0
init_acc_{k+1} = init_acc_k + init_pow_k * (P_r1_k + lambda_1 * Q_r1_k)
init_pow_{k+1} = init_pow_k * lambda_1^2
```

The final active row sends:

```text
p0_claim = p_acc_end
q0_claim = q_acc_end
logup_initial_claim = init_acc_end
```

The common loop constraints are:

- One active row corresponds to one LogUp spec.
- The mode bit must be constant across the group.
- `DeriveLayerClaims` mode is grouped by non-root `(proof_idx, chip_idx, layer_idx)`.
- `DeriveOutputClaim` mode is grouped by `(proof_idx, chip_idx)`.
- In `DeriveLayerClaims` mode, recompute `P_mu_k` and `Q_mu_k` every row using interpolation at `mu`.
- Recompute `P_cross_k` and `Q_cross_k` every row.
- In `DeriveLayerClaims` mode, update the next-claim accumulator using `lambda_next`.
- In `DeriveLayerClaims` mode, update the eval-claim accumulator using `lambda_cur`.
- In `DeriveLayerClaims` mode, advance LogUp powers by the corresponding batching challenge squared.
- In `DeriveOutputClaim` mode, update the fraction-addition output accumulators and the initial-claim accumulator.
- The mode selector must gate bus sends/receives so a row group produces exactly the messages for its selected mode.

### Interactions

In `DeriveLayerClaims` mode, the AIR receives the non-root layer input message on the first row:

```text
TowerLogupLayerInputMessage {
  chip_idx,
  layer_idx,
  tidx,
  lambda_next, // next-layer batching challenge
  lambda_cur,  // current-layer batching challenge
  mu,
  lambda_next_start,
  lambda_cur_start,
  num_logup_count
}
```

and sends on the final active row:

```text
TowerLogupClaimMessage {
  chip_idx,
  layer_idx,
  lambda_next_claim       = logup_next_claim,
  lambda_cur_claim        = logup_eval_claim
}
```

In `DeriveOutputClaim` mode, the AIR receives the root input message on the first row:

```text
TowerLogupRootInputBus {
  chip_idx,
  claim_tidx,
  lambda_1,
  r_1,
  lambda_1_start,
  num_logup_count
}
```

and sends the root fractional pair and initial-claim contribution in one message from the same final active row:

```text
TowerLogupRootBus {
  chip_idx,
  p0_claim,
  q0_claim,
  logup_initial_claim
}
```

The AIR owns transcript observations for active LogUp child claims. It does not own the layer-level sumcheck check;
`TowerLayerAir` combines the returned read-product, write-product, and LogUp claims.

## TowerLayerSumcheckAir (`src/tower/sumcheck/air.rs`)

### Columns

| Field                         | Shape    | Description                                                 |
|-------------------------------|----------|-------------------------------------------------------------|
| `is_enabled`                  | scalar   | Row selector.                                               |
| `proof_idx`                   | scalar   | Proof counter.                                              |
| `idx`                         | scalar   | Structural tower row counter; constrained to `chip_idx`.    |
| `chip_idx`                    | scalar   | Proof-local chip proof index used on sumcheck buses.        |
| `layer_idx`                   | scalar   | Layer whose sumcheck is being executed.                     |
| `is_first_idx`                | scalar   | First sumcheck row for the current `(proof_idx, chip_idx)`. |
| `is_first_layer`              | scalar   | First round row for the current layer.                      |
| `is_first_round`              | scalar   | First round inside the layer.                               |
| `is_dummy`                    | scalar   | Padding flag.                                               |
| `is_last_layer`               | scalar   | Whether this layer is the final GKR layer.                  |
| `round`                       | scalar   | Sub-round index within the layer (0 .. layer_idx-1).        |
| `tidx`                        | scalar   | Transcript cursor before reading evaluations.               
| `ev1`, `ev2`, `ev3`           | `[D_EF]` | Polynomial evaluations at points 1,2,3 (point 0 inferred).  
| `claim_in`, `claim_out`       | `[D_EF]` | Incoming/outgoing claims for each round.                    
| `prev_challenge`, `challenge` | `[D_EF]` | Previous xi component and the new random challenge.         
| `eq_in`, `eq_out`             | `[D_EF]` | Running eq accumulator before/after this round.             

### Row Constraints

- **Looping**: Loop constraints iterate over `(proof_idx, chip_idx, layer_idx)` with the sumcheck round serving as the
  innermost loop. The `is_first_idx` flag gates reset logic when we advance to a new chip tower proof, while
  `is_first_layer` protects the per-layer bookkeeping just before the round loop begins. No additional local tower
  identifier is used.
- **Round counter**: `round` starts at 0 and increments each transition; final round enforces `round = layer_idx - 1`.
- **Eq accumulator**: `eq_in = 1` on the first round; `eq_out = update_eq(eq_in, prev_challenge, challenge)` and
  propagates forward.
- **Claim flow**: `claim_out` computed via `interpolate_cubic_at_0123` using `(claim_in - ev1)` as `ev0`;
  `next.claim_in = claim_out` across transitions.
- **Transcript timing**: Each transition bumps `next.tidx = tidx + 4·D_EF` (three observations + challenge sample).
- **Dummy rows**: Dummy rows short-circuit all bus traffic; guard send/receive calls with `is_not_dummy`.
- **Arity assumption**: The layout assumes cubic polynomials (degree 3) and would need updates if the sumcheck arity
  changes.

### Interactions

- `sumcheck_input.receive`: first non-dummy round pulls `(chip_idx, layer_idx, is_last_layer, tidx, claim)` from
  `TowerLayerAir`.
- `sumcheck_output.send`: last non-dummy round returns `(chip_idx, layer_idx, claim_out, eq_at_r_prime)` to the layer AIR.
- `sumcheck_challenge.receive/send`: enforces challenge chaining between layers/rounds (`prev_challenge` from prior
  layer, `challenge` published for the next layer or eq export).
- All three tower sumcheck buses include `chip_idx` so messages disambiguate chip tower proofs inside the same proof.
- `transcript_bus.observe_ext`: records `ev1/ev2/ev3`, followed by `sample_ext` of `challenge`.
