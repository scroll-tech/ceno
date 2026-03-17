## Main Module (`src/main`)

The Main module bridges the reduced GKR claim into a “global” sumcheck AIR. It receives the
`input_layer_claim` emitted by `GkrInputAir`, replays a one-layer sumcheck (currently a pass-through
check), and hands the resulting claim back to downstream modules.

### MainAir (`src/main/air.rs`)

| Column          | Shape    | Description                                                                 |
|-----------------|----------|-----------------------------------------------------------------------------|
| `is_enabled`    | scalar   | Row selector. Disabled rows carry padding.                                  |
| `proof_idx`     | scalar   | Outer loop counter shared with GKR inputs.                                  |
| `idx`           | scalar   | Module index within the proof (matches `GkrInputAir`).                      |
| `is_first_idx`  | scalar   | Flags the first row for each `(proof_idx, idx)` pair.                        |
| `is_first`      | scalar   | Always `1` on real rows (there is a single row per `(proof_idx, idx)`).     |
| `tidx`          | scalar   | Transcript cursor at which the Main claim applies.                          |
| `claim_in`      | `[D_EF]` | The folded claim received from `GkrInputAir`.                               |
| `claim_out`     | `[D_EF]` | The claim returned by `MainSumcheckAir` (expected to match `claim_in`).     |

#### Constraints

- `NestedForLoopSubAir<2>` enforces boolean enablement, padding-after-padding, and lexicographic
  ordering over `(proof_idx, idx)`, using `is_first_idx` / `is_first` to mark loop resets.
- On `is_first` rows, the AIR receives `MainMessage` and constrains the local columns to match the
  bus payload (`idx`, `tidx`, and `claim_in`).
- Every enabled row sends `MainSumcheckInputMessage { idx, tidx, claim }` to the sumcheck AIR.
- The AIR immediately receives `MainSumcheckOutputMessage` and constrains `claim_out` to equal the
  returned payload. This keeps transcript state explicit even though the current sumcheck logic is a
  no-op.
- A simple consistency check enforces `claim_in == claim_out`, ensuring the pass-through sumcheck
  cannot mutate the claim silently.

#### Bus Interactions

- **MainBus.receive** (from `GkrInputAir`): `(idx, tidx, claim_in)` on `is_first` rows.
- **MainSumcheckInputBus.send**: forwards `(idx, tidx, claim_in)` on every enabled row.
- **MainSumcheckOutputBus.receive**: ingests `(idx, claim_out)` (one message per `(proof_idx, idx)`
  because the sumcheck only emits on its `is_last_round`).
- **TranscriptBus**: currently unused (the transcript positions are enforced implicitly through the
  provided `tidx`), but columns are wired so future revisions can observe claims if needed.

### MainSumcheckAir (`src/main/sumcheck`)

| Column           | Shape    | Description                                                                 |
|------------------|----------|-----------------------------------------------------------------------------|
| `is_enabled`     | scalar   | Row selector.                                                               |
| `proof_idx`      | scalar   | Matches the producer AIR.                                                   |
| `idx`            | scalar   | Module index within the proof.                                              |
| `is_first_idx`   | scalar   | Flags the first row for each `(proof_idx, idx)` pair.                        |
| `is_first_round` | scalar   | Indicates the first round for the current `(proof_idx, idx)` block.         |
| `is_last_round`  | scalar   | Marks the final round; used to gate the output message.                     |
| `is_dummy`       | scalar   | Allows a placeholder row when `num_rounds = 0`.                             |
| `round`          | scalar   | Round counter (starts at 0 and increments each sub-round).                  |
| `tidx`           | scalar   | Transcript cursor for the current round (`+4·D_EF` per transition).         |
| `ev1/ev2/ev3`    | `[D_EF]` | Sumcheck polynomial evaluations at 1/2/3.                                   |
| `claim_in`       | `[D_EF]` | Claim entering the round.                                                   |
| `claim_out`      | `[D_EF]` | Claim produced by cubic interpolation (fed into the next round).            |
| `prev_challenge` | `[D_EF]` | The previous transcript challenge (ξ) used in the eq term.                  |
| `challenge`      | `[D_EF]` | The round’s sampled challenge (rᵢ).                                         |
| `eq_in`          | `[D_EF]` | Running eq evaluation prior to this round.                                  |
| `eq_out`         | `[D_EF]` | Updated eq evaluation after applying the round challenge.                   |

#### Constraints

- `NestedForLoopSubAir<2>` runs over `(proof_idx, idx)` while treating `is_first_round` as the
  innermost loop reset. It enforces boolean flags, padding-after-padding, and lexicographic
  ordering.
- `round` is zeroed on `is_first_round` rows and increments by 1 on transitions within the same
  `(proof_idx, idx)`. The transcript cursor `tidx` increases by `4·D_EF` per round.
- `is_last_round` is constrained to equal `NestedForLoopSubAir::local_is_last`, so it flips to 1 on
  the final enabled row for each `(proof_idx, idx)` pair.
- On `is_first_round`, the AIR receives `MainSumcheckInputMessage { idx, tidx, claim }` and seeds the
  local columns. `eq_in` is set to one, and `claim_in` is forced to the received payload.
- Each round computes `ev0 = claim_in - ev1`, feeds `ev0/ev1/ev2/ev3` through the optimized cubic
  interpolator, and constrains `claim_out`. `claim_out` is copied to the next row’s `claim_in` for
  transitions.
- Eq values update via `eq_out = eq_in * (ξ·rᵢ + (1-ξ)(1-rᵢ))`, with propagation to the next row on
  transitions. Dummy rows (for zero-round proofs) carry `is_dummy = 1`, which suppresses bus traffic.
- Only rows with `is_last_round = 1` may send the result back; all other rows keep the claim inside
  the module.

#### Bus Interactions

- **MainSumcheckInputBus.receive**: `(idx, tidx, claim_in)` on `is_first_round` rows (and only when
  `is_dummy = 0`).
- **MainSumcheckOutputBus.send**: `(idx, claim_out)` gated by `is_last_round` and `!is_dummy`, so the
  claim returns to `MainAir` exactly once per `(proof_idx, idx)`.

---

### Sumcheck Notes

The Main sumcheck now mirrors the GKR layer sumcheck structure: it emits one row per round, tracks
`round`/`eq`/challenge evolution, and only releases the folded claim on `is_last_round`. The current
trace generator still fills the evaluation/challenge fields with placeholder zeros until real tower
data is connected, so the AIR behaves as a pass-through while preserving the full protocol shape.
