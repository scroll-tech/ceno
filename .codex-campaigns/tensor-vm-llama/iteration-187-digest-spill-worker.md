# Iteration 187 — PCS digest spill refinement

## Verdict

`CHANGES_REQUIRED` — digest spill reached the intended lifecycle and eliminated
the Basefold main-slab allocation failure, but the final descriptor rerun
stopped in a GPU matrix-reduction residency incompatibility. Full 33-shard E2E
was not started because shard-0 did not independently verify.

## Acceptance criteria and evidence

| Criterion | Result |
|---|---|
| Digest-only D2H/H2D seam | PASS in source and runtime telemetry |
| Exact production build | PASS; binary SHA-256 `6a545241d44ce0d4e22d7ecffc021f42496665a1f415a3b42b8300e0ffabab0b` |
| Mock shard-0 | PASS exit; exact GPU-MLE materialization reached `TensorAttentionPVHeads00_00`; process later killed after remaining alive and holding GPU memory |
| Real shard-0 spill | PASS for spill/main slab/PCS restore in `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-shard0-e2e-retry.log` |
| Independent verifier | FAILED pre-fix descriptor: `non-matrix circuit TensorAttentionPVHeads00_00 carries matrix first-layer groups` |
| Descriptor correction rerun | Reached matrix reduction, then `production matrix reduction requires resident base-field columns` in `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-shard0-e2e-final.log` |
| Full 33-shard | NOT RUN; verifier gate not satisfied |

Successful real-run telemetry:

- D2H: `2,147,483,648` bytes, `1956.890978 ms`; H2D: same bytes, `1242.195262 ms`
- SHA-256 both directions: `c3d2b809f0eff6d1adb581d5d9fdf77a7a7e73432f4df65838151222f30982ef`
- Main slab request `9,017,975,824` bytes (`8600.21 MiB`) succeeded
- High water: pool `13363.23 MiB`, framebuffer `14559.56 MiB`, booked `14841.44 MiB`
- q' `3,116,671,376` bytes; retained `5,970,923,720` bytes
- Proof `1,507,497` bytes at `/home/wusm/data/cargo_tmp/proofs/iteration-187-digest-spill-shard0-proof-retry.bin`
- Wall `1:24.56`; maximum RSS `13,707,668 KiB`

OOM did **not** move to PCS: the 2-GiB digest was released, the 8.60-GiB
main slab succeeded, and the exact digest was restored before PCS opening. The
descriptor rerun failed later, before opening.

## Mutation summary

Worker changes are the existing Basefold host/device digest state and prover
lifecycle, plus the minimal `examples-builder/build.rs` guest rerun triggers.
`ceno_zkvm/src/scheme/matrix_reduction.rs` now accepts aligned 1-, 2-, and
4-head production suffixes while retaining reduction kind, columns, variable
counts, and shifts. `e2e.rs` remains unmodified.

The mock log contains unsuppressed diagnostics: missing custom counterparts for
PV probability/V reads and projection-boundary rows 531+, plus `RAM record
multiplicities differ ... 17039360`. These are not padded-only messages: the
checker compares recorded row keys/raw tuples. They indicate the existing
TensorVM boundary/custom assignment mismatch and need separate authorization.
The mock process was killed after completion text because it remained alive
holding 12,558 MiB; no repeat was attempted.

## Logs and next action

- Build log: `/home/wusm/data/cargo_tmp/logs/iteration-187-production-build-descriptor.log` (SHA-256 `35de59bcfc92180390f5d99599fd36b8cc14a1fee7894cc12b6f77ca04a25447`)
- Mock log: `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-mock.log` (SHA-256 `2a2524a9f535198b906bf22644faf117e6445a85ae77840d092bb718cb6d6954`)
- Descriptor rerun log: `/home/wusm/data/cargo_tmp/logs/iteration-187-digest-spill-shard0-e2e-final.log` (SHA-256 `9346617ba41b9789255cf2effd8141f491b354fbf4a2a34f6b80c7a9c6037cc0`)

Root should review the GPU PV witness representation causing the resident
base-field error and separately coordinate the TensorVM custom/RAM mismatch.
Do not run 33 shards until clean shard-0 proof verification passes.
