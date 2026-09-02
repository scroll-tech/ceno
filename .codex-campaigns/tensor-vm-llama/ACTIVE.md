# Tensor VM Llama campaign checkpoint

Schema: 2
Status: ACTIVE — iteration 189 provider-side TensorVM ownership design required
Root: `/root`
Active implementor: none (iteration 188 terminal; awaiting ownership-design scope)
Optional probe: none

## Goal and stop condition

First make one exact production attention layer base-prove and independently
verify on the local RTX 5070 Ti, then continue the existing ordered 32-layer
and llama-tiny gates. Do not begin recursion. The immediate objective is to
reduce base-resident committed columns enough to close the measured shard-0
~432 MiB GPU gap without changing the proof architecture or execution flow.

## Effective constraints

- Exact production dimensions are B1/S2048/H4096/32xD128/I11008. Each
  `RAM -> Tensor` through matching `Tensor -> RAM` is an atomic TensorState
  segment; shards may pack whole segments but never cut one.
- Preserve Architecture B MatMul/K128 PV, Q16/Q20 equations, TensorBus, RAM and
  Custom record identities, tower, Jagged, PCS, transcript/circuit IDs,
  verifier/recursion interfaces, guest ABI, and the original WitIn opening.
- No PIOP, transcript, PCS equations, eviction, or semantic rematerialization.
  The user explicitly authorizes one narrow internal commitment-state seam for
  PCS-digest D2H/H2D; no other host spill or new memory manager is allowed.
- Flat committed q' remains the sole witness-MLE authority. Every MLE is an
  exact view/subrange of canonical committed order; do not rebuild or copy it.
- Chip-local removal of redundant/derivable columns and ordinary degree-4-or-
  lower AIR constraints are in scope. Preserve authenticated inputs, outputs,
  buses, lookups, equations, and all read/write multisets.
- Preserve unrelated user changes. Use `CARGO_TARGET_DIR=/home/wusm/data/cargo_tmp`
  and `TMPDIR=/home/wusm/data/cargo_tmp/tmp`. One expensive E2E per meaningful
  implementation; no broad cargo tests or CPU proving.

## Acceptance gates

1. Exact shard-0 per-chip resident-q' breakdown and non-q' owner reconciliation.
2. Ranked top-five chip owners with source-backed column-reduction candidates,
   exact/bounded savings, soundness obligations, and verification plan.
3. An ordered chip-column campaign targeting at least 432 MiB peak relief
   without changing PIOP or flow.
4. After a separately authorized implementation milestone, one heads-1 shard
   must base-prove and independently verify before the 33-shard layer or
   17-shard packing experiment is run.

## Active task — iteration 189

Iteration 188 isolated and fixed the PV probability witness-index bug, but the
remaining provider/boundary counterpart class requires a separate ownership
design before implementation. Preserve the existing record identities and do
not fabricate Custom writes or weaken the mock/verifier. The next permitted
step is to scope a canonical provider-side counterpart mechanism; no shard
verifier or full-layer run is valid until that gate passes.

## Latest terminal result — iteration 188

The CUDA PV assignment now separates `probability_key = tile*128 + axis`
from `v_key = tile*128 + row_low7`, matching the AIR. `cuda_hal` release check
and the rebuilt production binary both passed. The bounded shard-0 mock reached
the ownership checks and exited 101: the PV probability/softmax mismatch is
absent; remaining aggregate deltas are Memory `17,039,360` and Custom
`9,175,041`, with total mismatch errors `52,428,271`. Remaining sampled classes
are projection/attention boundary Memory writes, QK q/k Custom reads, PV V
Custom reads, and projection-boundary Custom tensor/state writes. No shard
verifier or full 33-shard E2E was run because the mock gate failed.

Commit: ceno-gpu `a35608b5 fix(tensor-vm): align PV probability witness index`.
Artifact: `.codex-campaigns/tensor-vm-llama/iteration-188-worker.md`
SHA-256: `ae5dd86ef17b19523807ec24c4fcaf1453901d9a169ebe862550a21f30d10208`.
Mock log SHA-256: `91af02ce7feb35a63f9944d0db2d690a0993bd314d466297620bdff9876ddd9d`.

The earlier digest-spill checkpoint remains committed and valid; its shard-0
real prover completed without OOM, but independent verification still remains
gated by the ownership mismatch and the unsupported head-1 matrix reducer.

## Active task — iteration 188

Trace and repair the exact TensorVM custom/RAM counterpart mismatch from the
bounded mock run. Preserve all record identities and shard semantics; do not
weaken checks or broaden the unsupported head-1 matrix reducer. Plan:
`.codex-campaigns/tensor-vm-llama/iteration-188-plan.md`.

Continuation: the digest-spill implementation is committed and validated for
the main OOM, but full shards remain gated on the TensorVM assignment and
head-1 verifier blockers.

## Previous active task — iteration 187

Temporarily copy the Basefold/PCS digest D2H before batched-main, release its
device allocation, and H2D it immediately before PCS opening consumes it.
Changing the internal commitment-state representation to an explicit
host-backed/device-backed digest is authorized; PCS algorithms, transcript,
bytes, and public proof behavior must remain identical. Measure transfer
overhead, host RSS, peak VRAM, and whether the failure merely moves to PCS. Run
one heads-1 shard0 base proof plus independent Rust verification; only on PASS
run the complete production layer. No PIOP or existing flow change.

Plan: `.codex-campaigns/tensor-vm-llama/iteration-187-plan.md`.

## Latest terminal result — iteration 187

Digest spill reached the intended lifecycle on RTX 5070 Ti. The complete
2,147,483,648-byte Basefold digest moved D2H in 1956.890978 ms and H2D in
1242.195262 ms with identical SHA-256. Releasing it let the 9,017,975,824-byte
(8600.21 MiB) main slab allocate; no OOM moved to PCS, and the digest restored
before opening. Proof size was 1,507,497 bytes, wall time 1:24.56, and peak
telemetry was pool 13,363.23 MiB / framebuffer 14,559.56 MiB / booked
14,841.44 MiB. The initial verifier failure was a head-1 descriptor-name bug;
the generalized matcher then exposed a separate PV matrix reducer requirement
for resident base-field columns. Full 33-shard E2E is gated until shard-0
independent verification passes. Mock proving logged substantial TensorVM
custom/RAM mismatches and was killed while retaining 12,558 MiB.

The head-1 descriptor broadening was reverted: the shared matrix reducer is
hard-coded for 24 variables/4-head rows, while head-1 has 22 variables. Making
the verifier accept that name without a head-count-aware reduction would be
unsound. Mock diagnostics also report substantial existing TensorVM custom/RAM
record mismatches; do not run the full layer until a clean shard-0 verifier gate
exists.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-187-digest-spill-worker.md`
SHA-256: `b0a6d8a08e4d5e3a027339da3bbbbaf6e729f1613a597def6a9e2d83ff2ae8cc`

Follow-up mock diagnosis: keyed records such as PV V read
`[2,1,532,2,0,0,524288,0]`, PV probability read
`[2,1,532,3,0,2,1,268434910]`, and projection-boundary writes are missing on
the opposite side of the shard-0 aggregate. Memory record multiplicity differs
by exactly 17,039,360. This is real assignment/ownership evidence, not padding
noise; trace the producer/counterpart before attempting the full layer.

## Latest terminal result — iteration 186

Exclusive clean 5070 Ti retry began with 15,093 MiB free and no foreign
process, yet the unchanged 8,600.21-MiB main slab failed with 61.19 MiB free.
q' 3,116,671,376 B; retained 5,970,923,720 B; 1,324 MLEs/2,478 terms/degree4.
No proof or verifier/full-layer result. Do not repeat unchanged; the next
authorized experiment is PCS digest host spill.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-186-worker.md`
SHA-256: `08f61cb29959c8f79315bfcc5f2a750fc1e44e959344aed1380fc8dd7b33fea2`

## Iteration 187 initial result

The digest owner is `BasefoldCommitmentWithWitness.codeword.digest_buf`, used
by `batch_open` through `view_digest_by_layers`. The internal host-backed/device-
backed seam is implemented while PCS call sites remain unchanged; `cuda_hal`
builds. The top-level attempt stopped at `e2e.rs` errors before E2E; rerun the
exact accepted production feature set before classifying the environment.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-187-worker.md`
SHA-256: `c4db2e8121c4b52bcea19174775fd76aef0154c88b2afaf2bfcb9ef71b8c0461`

## Prior terminal result — iteration 184

Exact flat q' is 3,366,232,464 B. Top owners are PV 960 MiB, ShardRAM leaf
742 MiB, projection input 480 MiB, QK 416 MiB, and Softmax 416 MiB; together
93.886%. A surgical sequence removes PV's fourth high4 bits, two Softmax linear
intermediates, four PV zero indicators, and five QK coordinate witnesses. Its
conservative modeled relief is 224 MiB q' plus 320 MiB main workspace = 544 MiB,
with degree<=4 and unchanged records/PIOP/flow. No source change or E2E occurred.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-184-worker.md`
SHA-256: `424322710305b9f2efef579a21e408a41ff19120090733465b8f18a17114f9d2`

## Iteration 185 refinement state

PV-A/SM-A/PV-B/QK-A pass focused algebra, Rust/CUDA maps, degree and record
counts. Exact q' fell 224 MiB to 3,131,351,440 B and main slab fell 320 MiB to
9,047,335,952 B, but shard0 still OOMed with 44.50 MiB free before proof.
Retained use was 5,985,603,784 B; no verifier/full-layer result exists. The
pre-authorized next change is SR-A only: remove seven ShardRAM x columns that
duplicate final Poseidon outputs, expected 42 MiB simultaneous relief, then one
final shard0 proof/verifier attempt. Original worker is yellow and must rotate.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-185-worker.md`
SHA-256: `7556b613322e94308e3a0ebb658a58da88b8093c34f00c08b2c05fd06c70f6c8`

SR-A then removed seven duplicate ShardRAM leaf-x columns exactly: q' is
3,116,671,376 B, retained 5,970,923,720 B, and main slab 9,017,975,824 B.
The run still OOMed with 46.50 MiB free, but an unrelated qemu process held
253 MiB. SR-A passes witness, records, commitment, tower and degree4 gates.
After the terminal artifact, qemu exited; read-only telemetry shows GPU total
16,303 MiB, used757 MiB, free15,093 MiB. One clean unchanged retry is justified.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-185-sra-worker.md`
SHA-256: `cbeec35af9ed6b20907e46847d06e8a73b85d61cc04ee5035b1fca6c321871a3`

## Latest terminal result — iteration 186

The user-requested exclusive-GPU retry began with 15,093 MiB free and no
compute process, but still OOMed at main round0: q' 3,116,671,376 B, retained
5,970,923,720 B, 1324 MLEs/2478 terms/degree4, slab 9,017,975,824 B, and
61.19 MiB CUDA free. Wall52.99s, RSS13,663,460KiB. No proof, verifier,
prod_r/prod_w verdict, or full-layer run exists. Do not repeat unchanged on
5070 Ti. Preserve the current diff; next authority is another degree<=4
chip-column reduction or the frozen build on remote4090.

Artifact: `.codex-campaigns/tensor-vm-llama/iteration-186-worker.md`
SHA-256: `08f61cb29959c8f79315bfcc5f2a750fc1e44e959344aed1380fc8dd7b33fea2`

Implementation authority granted by user; proceed through shard0 and full-layer
base-proof/verifier gates without another planning stop.

## Prior terminal result — iteration 183

PV Phase 2 uses the supported Boolean fallback: Dynamic16, map60/10, high4
rejects16, exact4R/3W and Q20 equations preserved. The one-key DPK lifecycle
removed a stale 639,646,776 B eager non-first key. Yet shard0 OOMs before proof:
q' 3,366,232,464 B, retained 6,153,375,944 B, degree4 main slab 9,382,880,272 B,
~432 MiB gap. Base4 51/10 allocated but required forbidden degree5 and was
restored. ShardRAM and main workspace are live proof data, not stale buffers.

Commits: ceno `bd02f124`; ceno-gpu `5b8a77a6`.
Artifact: `.codex-campaigns/tensor-vm-llama/iteration-183-worker.md`
SHA-256: `04427a4b405c3268e6ab931ef936df96d4f99494e3952887d7b392dc0058f2c8`

## Handoff

- Baseline tips must remain ceno `bd02f124`, ceno-gpu `5b8a77a6`.
- Primary log is `/home/wusm/data/cargo_tmp/logs/iteration-183-heads1-shard0-pv-bool-single-dpk-e2e.log`.
- The earlier invalid segmented-q 34-shard checkpoint is not a sound baseline.
- Shard0 fails before shard count matters; profile the current sound flat q'.
- Reconcile the complete 3,366,232,464 B q' total, not scheduler reservations.
- ShardRAM measured total is 866,123,776 B including its EC tree.
- Do not revive direct degree17 or base4 degree5 PV candidates.
- Detailed prior history is in `.codex-campaigns/tensor-vm-llama/history.md`.
