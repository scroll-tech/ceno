# GKR AIR Spec

This document captures the current behavior of each GKR-related AIR that lives in `src/gkr`. It mirrors the code so we can reason about constraints or plan refactors without diving back into Rust. Update the relevant section whenever an AIR’s columns, constraints, or interactions change.

## GkrInputAir (`src/gkr/input/air.rs`)

### Columns
| Field | Shape | Description |
| --- | --- | --- |
| `is_enabled` | scalar | Row selector (0 = padding).
| `proof_idx` | scalar | Proof counter enforced by `ProofIdxSubAir`.
| `n_logup` | scalar | Number of logup layers present.
| `n_max` | scalar | Max layer count (bounds xi sampling).
| `is_n_logup_zero` | scalar | Flag for `n_logup == 0` (drives “no interaction” branches).
| `is_n_logup_zero_aux` | `IsZeroAuxCols` | Witness used by `IsZeroSubAir` to enforce `n_logup` zero test.
| `is_n_max_greater_than_n_logup` | scalar | Whether more xi challenges are needed than GKR layers.
| `tidx` | scalar | Transcript cursor at start of the proof.
| `q0_claim` | `[D_EF]` | Root denominator commitment observed when interactions exist.
| `alpha_logup` | `[D_EF]` | Transcript challenge sampled before passing inputs to GKR layers.
| `input_layer_claim` | `[[D_EF]; 2]` | (numerator, denominator) pair returned from `GkrLayerAir`.
| `logup_pow_witness` | scalar | Optional PoW witness.
| `logup_pow_sample` | scalar | Optional PoW challenge sample.

### Row Constraints
- **Enablement / indexing**: `ProofIdxSubAir` enforces boolean `is_enabled`, padding-after-padding, and consecutive `proof_idx` for enabled rows.
- **Zero test**: `IsZeroSubAir` checks `n_logup` against `is_n_logup_zero`, unlocking the “no interaction” path.
- **Input layer defaults**: When `n_logup == 0`, the input-layer claim must be `[0, α]` (numerator zero, denominator equals `alpha_logup`).
- **Derived counts**: Local expressions compute `num_layers`, `needs_challenges`, transcript offsets for PoW, alpha sampling, per-layer reductions, and extra xi sampling—all reused in bus messages so the AIR doesn’t store redundant columns.

### Interactions
- **Internal buses**
  - `GkrLayerInputBus.send`: emits `(tidx skip q0, q0_claim)` when interactions exist.
  - `GkrLayerOutputBus.receive`: pulls reduced `(layer_idx_end, input_layer_claim)` back.
  - `GkrXiSamplerBus.send/receive`: if extra xi challenges are needed, dispatches request `(idx = num_layers, tidx_after_layers)` and waits for completion `(idx = n_max + l_skip - 1, tidx_end)`.
- **External buses**
  - `GkrModuleBus.receive`: initial module message (`tidx`, `n_logup`, `n_max`, comparison flag) per enabled row.
  - `BatchConstraintModuleBus.send`: forwards the final input-layer claim with the final transcript index.
  - `TranscriptBus`: optional PoW observe/sample, sample `alpha_logup`, and observe `q0_claim` only when `has_interactions`.
  - `ExpBitsLenBus.lookup`: validates PoW challenge bits if PoW is configured.

### Notes
- Transcript offsets rely on `pow_tidx_count(logup_pow_bits)` to keep challenges contiguous.
- Local booleans `has_interactions` and `needs_challenges` gate all downstream activity, so future refactors must keep those semantics aligned with the code branches.

## GkrLayerAir (`src/gkr/layer/air.rs`)

### Columns
| Field | Shape | Description |
| --- | --- | --- |
| `is_enabled` | scalar | Row selector.
| `proof_idx` | scalar | Proof counter shared with input AIR.
| `is_first` | scalar | Indicates the first layer row of a proof.
| `is_dummy` | scalar | Marks padding rows that still satisfy constraints.
| `layer_idx` | scalar | Layer number, enforced to start at 0 and increment per transition.
| `tidx` | scalar | Transcript cursor at the start of the layer.
| `lambda` | `[D_EF]` | Batching challenge for non-root layers.
| `p_xi_0`, `q_xi_0`, `p_xi_1`, `q_xi_1` | `[D_EF]` | Layer claims at evaluation points 0 and 1.
| `numer_claim`, `denom_claim` | `[D_EF]` | Linear interpolation results `(p,q)` at point `mu`.
| `sumcheck_claim_in` | `[D_EF]` | Claim passed to sumcheck.
| `eq_at_r_prime` | `[D_EF]` | Product of eq evaluations returned from sumcheck.
| `mu` | `[D_EF]` | Reduction point sampled from transcript.

### Row Constraints
- **Looping**: `NestedForLoopSubAir<1>` enforces enablement, per-proof sequencing, and detects transitions (`is_transition`) / last rows (`is_last`).
- **Layer counter**: On the first row, `layer_idx = 0`; on transitions, `next.layer_idx = layer_idx + 1`.
- **Root layer**: Requires `p_cross_term = 0` and `q_cross_term = sumcheck_claim_in`, using helper `compute_recursive_relations`.
- **Interpolation**: Recomputes `numer_claim`/`denom_claim` via `reduce_to_single_evaluation` and enforces equality with the stored columns.
- **Inter-layer propagation**: When transitioning, `next.sumcheck_claim_in = numer + next.lambda * denom` and transcript index jumps by the exact amount consumed (`lambda`, four observations, `mu`).

### Interactions
- **Layer buses**
  - `layer_input.receive`: only on the first non-dummy row; provides `(tidx, q0_claim)`.
  - `layer_output.send`: on the last non-dummy row; reports `(tidx_end, layer_idx_end, [numer, denom])` back to `GkrInputAir`.
- **Sumcheck buses**
  - `sumcheck_input.send`: for non-root layers, dispatches `(layer_idx, is_last_layer, tidx + D_EF, claim)` to the sumcheck AIR.
  - `sumcheck_output.receive`: ingests `(claim_out, eq_at_r_prime)` and re-encodes them into local columns.
  - `sumcheck_challenge.send`: posts the `mu` challenge as round 0 for the next layer’s sumcheck.
- **Transcript bus**
  - Samples `lambda` (non-root) and `mu`, observes all `p/q` evaluations.
- **Xi randomness bus**
  - On the proof’s final layer, sends `mu` as the shared xi challenge consumed by later modules.

### Notes
- Dummy rows allow reusing the same AIR width even when no layer work is pending; constraints are guarded by `is_not_dummy` to avoid accidentally constraining padding rows.
- The transcript math (5·`D_EF` per layer after sumcheck) must stay synchronized with `GkrInputAir`’s tidx bookkeeping.

## GkrLayerSumcheckAir (`src/gkr/sumcheck/air.rs`)

### Columns
| Field | Shape | Description |
| --- | --- | --- |
| `is_enabled` | scalar | Row selector.
| `proof_idx` | scalar | Proof counter.
| `layer_idx` | scalar | Layer whose sumcheck is being executed.
| `is_proof_start` | scalar | First sumcheck row for the proof.
| `is_first_round` | scalar | First round inside the layer.
| `is_dummy` | scalar | Padding flag.
| `is_last_layer` | scalar | Whether this layer is the final GKR layer.
| `round` | scalar | Sub-round index within the layer (0 .. layer_idx-1).
| `tidx` | scalar | Transcript cursor before reading evaluations.
| `ev1`, `ev2`, `ev3` | `[D_EF]` | Polynomial evaluations at points 1,2,3 (point 0 inferred).
| `claim_in`, `claim_out` | `[D_EF]` | Incoming/outgoing claims for each round.
| `prev_challenge`, `challenge` | `[D_EF]` | Previous xi component and the new random challenge.
| `eq_in`, `eq_out` | `[D_EF]` | Running eq accumulator before/after this round.

### Row Constraints
- **Looping**: `NestedForLoopSubAir<2>` iterates over `(proof_idx, layer_idx)` with per-layer rounds; emits `is_transition_round`/`is_last_round` flags.
- **Round counter**: `round` starts at 0 and increments each transition; final round enforces `round = layer_idx - 1`.
- **Eq accumulator**: `eq_in = 1` on the first round; `eq_out = update_eq(eq_in, prev_challenge, challenge)` and propagates forward.
- **Claim flow**: `claim_out` computed via `interpolate_cubic_at_0123` using `(claim_in - ev1)` as `ev0`; `next.claim_in = claim_out` across transitions.
- **Transcript timing**: Each transition bumps `next.tidx = tidx + 4·D_EF` (three observations + challenge sample).

### Interactions
- `sumcheck_input.receive`: first non-dummy round pulls `(layer_idx, is_last_layer, tidx, claim)` from `GkrLayerAir`.
- `sumcheck_output.send`: last non-dummy round returns `(claim_out, eq_at_r_prime)` to the layer AIR.
- `sumcheck_challenge.receive/send`: enforces challenge chaining between layers/rounds (`prev_challenge` from prior layer, `challenge` published for the next layer or eq export).
- `transcript_bus.observe_ext`: records `ev1/ev2/ev3`, followed by `sample_ext` of `challenge`.
- `xi_randomness_bus.send`: on final layer rows, exposes `challenge` (the last xi) for downstream consumers.

### Notes
- Dummy rows short-circuit all bus traffic; guard send/receive calls with `is_not_dummy`.
- The layout assumes cubic polynomials (degree 3) and would need updates if the sumcheck arity changes.

## GkrXiSamplerAir (`src/gkr/xi_sampler/air.rs`)

### Columns
| Field | Shape | Description |
| --- | --- | --- |
| `is_enabled` | scalar | Row selector.
| `proof_idx` | scalar | Proof counter.
| `is_first_challenge` | scalar | Marks the first xi of a proof’s sampler phase.
| `is_dummy` | scalar | Dummy padding flag.
| `idx` | scalar | Challenge index (offset from layer-derived xi count).
| `xi` | `[D_EF]` | Sampled challenge value.
| `tidx` | scalar | Transcript cursor for the sample.

### Row Constraints
- **Looping**: `NestedForLoopSubAir<1>` keeps `(proof_idx, is_first_challenge)` sequencing, emitting `is_transition_challenge` and `is_last_challenge` flags.
- **Index monotonicity**: On transitions, enforce `next.idx = idx + 1` and `next.tidx = tidx + D_EF`.
- **Boolean guards**: `is_dummy` flagged as boolean; all constraints wrap with `is_not_dummy` before talking to buses or transcript.

### Interactions
- `GkrXiSamplerBus.receive`: first non-dummy row per proof imports `(idx, tidx)` from `GkrInputAir`.
- `GkrXiSamplerBus.send`: on the final challenge, returns `(idx, tidx_end)` so the input AIR knows where transcript sampling stopped.
- `TranscriptBus.sample_ext`: samples the actual `xi` challenge at each enabled row.
- `XiRandomnessBus.send`: mirrors every sampled `xi` to the shared randomness channel for any module that depends on the full xi vector.

### Notes
- This AIR exists solely because the sampler interacts with transcript/lookups differently from the layer AIR; long term it may be folded into batch-constraint logic once shared randomness is enforced elsewhere.
