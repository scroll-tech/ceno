# Iteration 188 plan — TensorVM record ownership repair

## Objective

Trace and repair the shard-0 TensorVM custom/RAM read/write assignment mismatch
revealed by bounded mock proving after the PCS digest-spill milestone. Then
rerun a bounded mock check and one real heads-1 shard proof/verifier. Only if
both pass may the complete production shard set run.

## Evidence to explain

- Mock log: `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-mock.log`
- Exact memory multiplicity mismatch: `17,039,360`
- Missing PV V read raw tuple: `[2,1,532,2,0,0,524288,0]`
- Missing PV probability read raw tuple: `[2,1,532,3,0,2,1,268434910]`
- Missing projection-boundary tensor writes at rows `0..9` and `531..540`
- Prior digest proof log: `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-shard0-e2e-retry.log`

## Constraints

- Preserve TensorBus/RAM semantics, record identities, guest ABI, chip names,
  PIOP, PCS, transcript, equations, and proof format.
- Do not weaken mock/verifier checks or treat cross-shard ownership as a local
  match without proving the counterpart's shard and lifecycle.
- Fix only the TensorVM witness/constraint assignment or explicit shard-owned
  counterpart generation if the source trace proves it is omitted.
- Preserve committed digest-spill code and the safe four-head matrix descriptor;
  do not broaden the hard-coded 2^24 matrix reducer for head-1.

## Gates

1. Source-backed producer/consumer mapping for one PV V/probability record and
   one projection-boundary record, including shard ownership.
2. Minimal implementation, if required, with focused build/check.
3. Bounded mock proving with no unbounded repeat or host-retention leak.
4. One real heads-1 shard-0 base proof and independent Rust verifier.
5. Full production shard E2E only after gate 4 passes.
