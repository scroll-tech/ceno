# Tower AIR Review Checklist

Use this checklist when updating `tower_air_spec.md` or porting a spec change into the codebase. For each item, compare
the spec, the AIR implementation, and the trace-generation path that populates the columns.

## Protocol-Wide Checks

- [ ] Confirm the spec change is written in `tower_air_spec.md` before code changes are reviewed.
- [ ] Confirm transcript observations, samples, labels, and `tidx` arithmetic match the native verifier order.
- [ ] Confirm every bus message has one matching send/receive side, the same multiplicity, and the same `(proof_idx,
  chip_id, layer_idx)` scope where applicable.
- [ ] Confirm padding, dummy rows, and zero-count paths do not emit unintended bus traffic.
- [ ] Confirm `n_layer == 0` uses `r0_claim = 1`, `w0_claim = 1`, `p0_claim = 0`, `q0_claim = 1`, and the documented
  input-layer default.
- [ ] Confirm read, write, and LogUp batching-power offsets compose without gaps or overlaps.
- [ ] Confirm any protocol-level change is mirrored in recursive-verifier code if the native verifier contract changes.

## TowerInputAir

- [ ] Review columns against `src/tower/input/cols.rs` and witness assignment.
- [ ] Review row constraints for enablement, identity, zero-layer behavior, transcript math, and initial-claim assembly.
- [ ] Review root input bus sends for read, write, and LogUp claim AIRs.
- [ ] Review root claim bus receives for `(r0_claim, w0_claim, p0_claim, q0_claim)`.
- [ ] Review init bus receives for read, write, and LogUp contributions to `initial_tower_claim`.
- [ ] Review external interactions with `TowerModuleBus`, `TowerRootClaimBus`, `MainBus`, and `TranscriptBus`.

## TowerLayerAir

- [ ] Review columns against `src/tower/layer/cols.rs` and witness assignment.
- [ ] Review row constraints for layer looping, dummy rows, `lambda_cur` propagation, count consistency, and claim flow.
- [ ] Review layer input/output buses between `TowerInputAir` and `TowerLayerAir`.
- [ ] Review product and LogUp child input buses, including offsets and start/end batching powers.
- [ ] Review sumcheck input/output/challenge buses and their layer/round scopes.
- [ ] Review transcript timing for `lambda_next`, `mu`, and child-claim observation windows.

## TowerProdReadClaimAir and TowerProdWriteClaimAir

- [ ] Review shared columns against the product claim cols and both read/write witness paths.
- [ ] Review `DeriveLayerClaims` constraints for `A_mu`, `A_cross`, `lambda_next` powers, and `lambda_cur` powers.
- [ ] Review `DeriveOutputClaim` constraints for root output products and `C_1(r_1)` contribution.
- [ ] Review read/write `prod_offset`, `lambda_*_start`, and `num_prod_count` handling.
- [ ] Review layer-mode buses: product input receive and product sum-claim send.
- [ ] Review root-mode buses: root input receive, root output send, and init contribution send.
- [ ] Review transcript observations for product child claims and ensure mode gating is exact.

## TowerLogUpSumCheckClaimAir

- [ ] Review columns against the LogUp claim cols and witness assignment.
- [ ] Review `DeriveLayerClaims` constraints for `P_mu`, `Q_mu`, `P_cross`, `Q_cross`, and two-power batching steps.
- [ ] Review `DeriveOutputClaim` constraints for fractional accumulation `(p0_claim, q0_claim)` and `C_1(r_1)`
  contribution.
- [ ] Review `logup_offset`, `lambda_*_start`, and `num_logup_count` handling after read/write product specs.
- [ ] Review layer-mode buses: LogUp input receive and LogUp claim send.
- [ ] Review root-mode buses: LogUp root input receive and combined root/init claim send.
- [ ] Review transcript observations for LogUp child claims and ensure mode gating is exact.

## TowerLayerSumcheckAir

- [ ] Review columns against `src/tower/sumcheck/cols.rs` and witness assignment.
- [ ] Review row constraints for round counters, first/last layer flags, dummy rows, and cubic interpolation.
- [ ] Review eq accumulator initialization, update, and final export.
- [ ] Review sumcheck input receive, output send, and challenge receive/send buses.
- [ ] Review transcript observations for `ev1`, `ev2`, `ev3`, challenge sampling, and `tidx` transitions.
- [ ] Review the arity assumption if any layer or sumcheck polynomial degree changes.
