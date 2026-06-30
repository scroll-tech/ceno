# Tower AIR Contract Findings

Date: 2026-06-25

This note records a design review of the tower AIR contracts using the math section in `docs/tower_air_spec.md` as the
source of truth. It is intentionally separate from the spec so the issues can be reviewed and resolved one by one.

## Ground Truth Summary

The tower layer reduction batches all product and LogUp specs with one flattened sequence of alpha powers:

```text
Prod_0, ..., Prod_{n_prod-1}, P_0, Q_0, P_1, Q_1, ...
```

For layer `i`, the sumcheck final evaluation must equal:

```text
eq(r_i, rho) * T_i(rho)
```

where `T_i(rho)` includes:

```text
sum_j alpha^j * Prod_j(rho, 0) * Prod_j(rho, 1)

+ sum_k alpha^(n_prod + 2k) * (
      P_k(rho, 0) * Q_k(rho, 1)
    + P_k(rho, 1) * Q_k(rho, 0)
  )

+ sum_k alpha^(n_prod + 2k + 1) * (
      Q_k(rho, 0) * Q_k(rho, 1)
  )
```

If another layer remains, tower then samples the merge challenge and fresh next-layer batching challenge, and derives:

```text
C_{i+1}(rho, mu)
```

from the interpolated child claims at `(rho, mu)`.

## Findings

### 1. Flattened alpha batching is not implemented across split claim AIRs

Severity: blocker

The math requires one consecutive alpha-power sequence across read products, write products, then LogUp `P/Q` terms.
Current `TowerLayerAir` sends the same raw `lambda` and `lambda_prime` to read, write, and LogUp claim AIRs:

- `src/tower/layer/air.rs`: TODO for write offset: `local.lambda^(num_read)`
- `src/tower/layer/air.rs`: TODO for LogUp offset: `local.lambda^(num_read + num_write)`

Each claim AIR trace initializes its local power to one:

- `src/tower/layer/prod_claim/trace.rs`: `pow_lambda = EF::ONE`
- `src/tower/layer/logup_claim/trace.rs`: `pow_lambda = EF::ONE`

This means write product powers restart at `alpha^0`, and LogUp powers restart at `alpha^0`, instead of using the
flattened offsets required by the math.

Expected contract:

- read claim AIR starts at `alpha^0`;
- write claim AIR starts at `alpha^(num_read_specs)`;
- LogUp claim AIR starts at `alpha^(num_read_specs + num_write_specs)`;
- LogUp folds each spec as `alpha^(offset + 2k) * P_k + alpha^(offset + 2k + 1) * Q_k`.

### 2. LogUp current claim drops the numerator cross term

Severity: blocker

The math requires the LogUp contribution to `T_i(rho)` to include both:

```text
P0 * Q1 + P1 * Q0
Q0 * Q1
```

The LogUp claim AIR computes `acc_p_cross` and `acc_q_cross`, but exports only `acc_q_cross` as `lambda_prime_claim`.
`acc_p_cross` is not sent to `TowerLayerAir`.

Relevant code:

- `src/tower/layer/logup_claim/air.rs`: computes `acc_p_cross`
- `src/tower/layer/logup_claim/air.rs`: sends `lambda_prime_claim: acc_q_with_cur`
- `src/tower/mod.rs`: `accumulate_logup_claims` returns only `(acc_sum, acc_q)`

This means `TowerLayerAir` cannot derive the correct `T_i(rho)` for LogUp specs.

Expected contract:

`TowerLogupClaimBus` must provide enough data for `TowerLayerAir` to compute the full LogUp contribution:

```text
sum_k alpha^(n_prod + 2k)     * (P0 * Q1 + P1 * Q0)
+ sum_k alpha^(n_prod + 2k+1) * (Q0 * Q1)
```

This likely requires either:

- exporting a single fully folded `current_claim` that includes both cross terms; or
- exporting separate numerator-cross and denominator-cross claims with explicit semantics.

### 3. Root/input claim anchoring is wrong or incomplete

Severity: blocker

The math requires initial read/write/LogUp out-evals to be observed and folded with the initial batching challenge.
Current `TowerInputRecord` only carries one `q0_claim`, and the trace copies it into all three root claims:

```text
r0_claim = q0_claim
w0_claim = q0_claim
q0_claim = q0_claim
```

Relevant code:

- `src/tower/input/trace.rs`
- `src/tower/layer/air.rs`: root row asserts `read_claim_prime == r0_claim`, `write_claim_prime == w0_claim`,
  `logup_claim_prime == q0_claim`

This cannot bind distinct read, write, and LogUp root folded claims correctly.

Expected contract:

`TowerInputAir` must provide the correct root folded claims derived from native verifier transcript state:

```text
read_root_claim
write_root_claim
logup_root_claim
```

or a single already-batched root claim, if the layer contract is redesigned around one combined claim.

### 4. ProofShape-to-Tower contract is still the old shape

Severity: major

The intended module boundary is:

```text
(proof_idx, chip_id, num_layers, num_read_specs, num_write_specs, num_logup_specs)
```

Current implementation still sends only:

```text
(idx, tidx, n_logup)
```

Relevant code:

- `src/bus.rs`: `TowerModuleMessage { idx, tidx, n_logup }`
- `src/proof_shape/proof_shape/air.rs`: sends `TowerModuleMessage`
- `src/tower/input/air.rs`: receives `TowerModuleMessage` and treats `n_logup` as `num_layers`

Proof shape already selects VK-derived read/write/LogUp counts internally, but those counts are not carried through the
TowerModuleBus contract.

Expected contract:

`TowerModuleBus` should identify one tower proof by `(proof_idx, chip_id)` and carry VK-derived tower shape:

```text
num_layers
num_read_specs
num_write_specs
num_logup_specs
```

`tidx` should not be shape metadata unless the transcript scheduling contract explicitly assigns it to proof-shape.

### 5. Dummy rows still send or receive claim bus messages

Severity: major

Product and LogUp claim AIRs define `is_not_dummy`, and many local constraints are gated by it. However, their bus
interactions use `local.is_enabled`, so dummy rows still affect permutation bus multiplicities.

Relevant code:

- `src/tower/layer/prod_claim/air.rs`: claim input receive uses `local.is_first * local.is_enabled`
- `src/tower/layer/prod_claim/air.rs`: claim output send uses `is_layer_end * local.is_enabled`
- `src/tower/layer/logup_claim/air.rs`: claim input receive uses `local.is_first * local.is_enabled`
- `src/tower/layer/logup_claim/air.rs`: claim output send uses `is_layer_end * local.is_enabled`

This matches the saved bus summary pattern:

- Bus 33 `TowerProdReadClaimInputBus`: dummy receives with no matching sender
- Bus 35 `TowerProdWriteClaimInputBus`: dummy receives with no matching sender
- Bus 37 `TowerLogupClaimInputBus`: dummy receives with no matching sender
- Bus 34/36/38: dummy or wrong folded-claim sends/receives

Expected contract:

Dummy rows must not send or receive claim messages unless there is an explicit zero-count boundary message consumed by a
matching AIR. The simplest expected rule is:

```text
bus_enable = local.is_first * is_not_dummy
send_enable = is_layer_end * is_not_dummy
```

### 6. Inactive specs are zero-filled and treated as active transcript observations

Severity: major

The math says specs with no remaining reduction round do not contribute to the next expected sum.

Current tower replay builds zero child evaluations for missing per-layer spec rounds, then pushes those rows into active
read/write/LogUp layer vectors. The claim trace then treats these zero rows as real rows and observes them through the
transcript bus.

Relevant code:

- `src/tower/mod.rs`: fills missing product evals with `[0, 0]`
- `src/tower/mod.rs`: fills missing LogUp evals with `[0, 0, 0, 0]`
- `src/tower/layer/prod_claim/trace.rs`: `is_real = row_in_layer < active_rows.len()`
- `src/tower/layer/logup_claim/trace.rs`: `is_real = row_in_layer < logup_rows.len()`

Expected contract:

The active row count for a layer should reflect only specs with actual proof-provided child claims for that layer.
Inactive specs should not:

- contribute zero terms as if they were real;
- consume transcript observations;
- send positive-count claim-folding messages.

### 7. Transcript ownership and ordering are underspecified versus native replay

Severity: major

Native replay performs:

1. observe all read/write/LogUp out-evals;
2. observe label `"combine subset evals"`;
3. sample alpha;
4. observe label `"product_sum"`;
5. sample root point;
6. for each layer, observe sumcheck labels/evals, sample rho challenges, observe merge label, sample mu;
7. for non-root layers, observe label and sample fresh next-layer alpha.

Relevant code:

- `src/tower/mod.rs`: `record_gkr_transcript`
- `src/tower/input/air.rs`: currently only samples `alpha_logup`
- `src/tower/layer/air.rs`: samples `lambda` and `mu`
- product/logup claim AIRs observe child claims

The design may be able to distribute transcript events across AIRs, but each event owner and exact `tidx` must be part of
the AIR contract. Otherwise the circuit can satisfy a different transcript schedule than the native verifier.

Expected contract:

The AIR sequence must assign each transcript event to exactly one AIR, in native verifier order, including labels and
out-eval observations.

### 8. XiRandomnessBus is still emitted, but the current design has no consumer

Severity: medium

The design discussion removed the optional randomness export, but `TowerLayerSumcheckAir` still sends `XiRandomnessBus`
messages on last-layer rows.

Relevant code:

- `src/tower/sumcheck/air.rs`: sends `XiRandomnessBus`

Saved bus summary shows:

```text
Bus 14 (XiRandomnessBus): 196 failure(s)
```

Expected contract:

Either remove this send, or specify a real consumer and protocol meaning. Under the current design, it should be removed.

### 9. `tower_air_spec.md` below the math section is stale

Severity: docs

The math section is the most accurate part of `tower_air_spec.md`, but several AIR sections below it contradict the
current intended design:

- `TowerInputAir` refers to `n_layer`, but code still has `n_logup`;
- `TowerLayerAir` says read/write/logup counts must equal `n_logup`;
- `TowerLogupClaimAir` appears twice;
- the first LogUp section says `acc_p_cross` remains internal, which contradicts the math;
- the second LogUp section is stale and says only `(lambda * q_xi) * pow_lambda`;
- `Xi randomness bus` is still documented.

Expected contract:

After the contract is settled, rewrite each AIR section in this order:

1. receives;
2. sends;
3. transcript events owned;
4. shape metadata trusted;
5. algebraic meaning of emitted claims;
6. local constraints.

## Suggested Resolution Order

1. Fix the protocol-level bus contracts first:
   - `TowerModuleBus`;
   - `TowerLayerInputBus`;
   - product/logup claim input/output buses.
2. Fix flattened batching offsets across read/write/LogUp claim AIRs.
3. Fix LogUp `current_claim` so it represents full `T_i(rho)` contribution.
4. Fix root folded claim inputs and transcript prefix ownership.
5. Fix zero-work and inactive-spec behavior.
6. Remove or wire `XiRandomnessBus`.
7. Rewrite `tower_air_spec.md` per-AIR sections to match the corrected contracts.

## Saved Log Evidence

The current grouped bus summary from the failed e2e run is:

```text
logs/e2e-20260625-201555.bus-summary.txt
```

Relevant failures:

```text
Bus 14 (XiRandomnessBus): 196 failure(s)
Bus 33 (TowerProdReadClaimInputBus): 10 failure(s)
Bus 34 (TowerProdReadClaimBus): 56 failure(s)
Bus 35 (TowerProdWriteClaimInputBus): 10 failure(s)
Bus 36 (TowerProdWriteClaimBus): 60 failure(s)
Bus 37 (TowerLogupClaimInputBus): 10 failure(s)
Bus 38 (TowerLogupClaimBus): 54 failure(s)
```

The input-bus failures on 33/35/37 are consistent with dummy claim AIR rows receiving messages that `TowerLayerAir` does
not send because layer-side sends are dummy-masked.
