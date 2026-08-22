# Campaign: I061-R Preflight-Pure Layered FullTracer

## Checkpoint metadata

- Schema: `manage-long-campaign/v2`
- Updated: `2026-08-22T17:28:00+08:00`
- Size limit: 24 KiB
- Historical archive: `artifacts/fulltracer-gpu-ingress/archive/`
- Normal resume: read only this checkpoint and the current evidence linked below.

## Goal

Build a record-free executor directly from `PreflightProduction`, remove all preflight-only accounting, then restore FullTracer semantics cumulatively through L0-L8. Each completed layer is correctness-gated and measured before the next begins. Final promotion retains the <=600 ms median, >=100 ms saving, and p95 gates.

## Effective constraints

- Campaign mode remains active from the preceding campaign. Root owns planning, transitions, checkpoint updates, and user updates. One reusable implementor owns one end-to-end layer envelope at a time; no overlapping mutations.
- Worker watermarks: below 65% continue; 65-79% stop broadening and preserve evidence; at 80% start no new command or mutation, write a continuation artifact, and return `ROTATION_REQUIRED`.
- Branch: `I061R-preflight-pure-layered-fulltracer`, corrective source handoff
  `0a7c111ffc1ba01b7260bec70c739e8bb3a66fa5` over parent `14808ce7`.
  Preserve all unrelated untracked files.
- Production preflight generation and cache identity are immutable. No public API changes. Layer selection, diagnostics, and early stop remain internal or benchmark-only. Every experimental layer has a distinct layer/schema cache identity.
- Build the executor from `PreflightProduction`, but remove planner/tracking/accounting work instead of adding block behavior to replay. L0 emits zero records.
- Preserve generic L0-L5 as correctness oracles. The active implementation
  spine is compact-first: L1C Skeleton, L2C Values, L3C Registers, L4C
  Memory/MMIO, L5C Future access, L6C Exceptional closure, L7 Compact Closure,
  then L8 ping/pong.
- Compact developing principle: payload size, store shape, and generated-code
  footprint are joint acceptance criteria. Emit the smallest stable family
  record with forward, non-overlapping, destination-read-free stores; never
  materialize a generic row, patch the destination, or convert post hoc. Prefer
  shared generated assembly when it preserves local forward stores while
  preventing instruction-cache/iTLB amplification.
- L1C causal evidence: physical bytes fell 88.2353% (136 to 16 bytes/row),
  native median fell 80.655% (1,258.194 to 243.395 ms), scalar median stayed
  effectively flat (30.099 to 29.685 ms), and peak RSS fell 1,371,436 KiB.
  Therefore attribute the gain to eliminated poison/write amplification and
  cache/writeback pressure, not to changed execution semantics.
- Intermediate canonical runs execute both shards and stop immediately after replay, before arena validation, GPU witness assignment, proof, or verification. Only an explicit expected-stop marker is accepted.
- Canonical workload: cached block 23,587,691, chain 1, cell cap 2,684,354,560, chunk capacity 262,144, existing canonical environment. Never expose RPC URLs.
- Per layer transition: warm both modes once; run five paired alternating same-binary samples per mode; report median, nearest-rank p95, absolute/percent delta, native/scalar split, bytes, records/chunks, RSS, and allocation growth.
- Retain all prior correctness checks. A failed layer is diagnosed and refined independently; do not begin a later layer before correctness and the five-sample delta are recorded.
- L7 reports generic bytes, compact bytes, compact bandwidth, routing/reservation cost, and net timing. L8 preserves exact-boundary sealing, two-slot ownership/event recycling, stable warmed pointers/capacities, no allocation growth, and exact 53/22 topology.
- Full GPU assignment/downstream proof runs only after L8 is byte-identical. Promotion uses one warm-up and five alternating final/control samples.
- Production default must be the fastest correctness-complete same-binary path
  on full Reth replay plus GPU witness generation. Packed compact is the active
  candidate; explicit SoA remains an oracle/debug override and generic
  FullTracer remains the control/fallback until paired promotion passes.
- Handoff comparison is data-first: compare latest packed-default GPU witness,
  exact pre-refactor GPU witness, and the same pre-refactor CPU witness on shard
  0/1. Run one excluded warm-up and three measured full proofs per scenario in
  rotated order. Do not impose an arbitrary materiality threshold or begin a
  new optimization; diagnose and rank actions if `latest GPU > old GPU >> old
  CPU` is unsupported.

## Acceptance ladder

- [x] L0: exact registers, memory, PC, cycles, instruction count, exits/traps versus production preflight; zero records and no planner/tracking work.
- [x] L1: slot reservation, ordinal/cycle, instruction, PC/next-PC, operand addresses/presence equal `FullTracerDirect`; disabled fields poisoned.
- [x] L2: RS1/RS2, RD before/after, memory before/after values exact.
- [x] L3: block-local register predecessor stamps and touched-register commit exact for aliases, loops, branches.
- [x] L4: step-exact memory predecessors/latest-state and heap/hint bounds exact without deferred-MMIO state.
- [x] L5: resident future-access cursor, row/syscall masks, and cursor closure exact.
- [x] L1C: compact-first skeleton rows, exact decoded L1 equality, zero generic
  rows/post-hoc compaction, and positive replay/physical-byte reduction.
- [x] L2C: direct compact values, exact decoded L2 equality, forward stores,
  zero generic rows/patching/conversion, and measured against L1C.
- [x] L3C-L6C: cumulatively restore predecessors, memory/MMIO, future access,
  and exceptional semantics on the same compact-first spine.
- [x] L6: syscalls/indexes, traps, dynamic/memory-guard fallbacks, mid-block resume, counters, and complete generic `StepRecord` equality.
- [x] L7: direct family-routed packed-AoS output byte-identical to compact
  `GpuReplayDirect`/`GpuTypedSoaArena`, transactional family reservation,
  static local ranks, and measured write delta. The arena is typed by family;
  each family payload is packed AoS bytes, not field-SoA.
- [x] L8: descriptor/family closure, ping/pong ownership and recycling, stable storage, CPU/GPU matrices, derived records, public values, boundaries, and exact 53/22 topology.
- [x] Final: exact 19,184,811 instructions, 76,739,248 cycles, boundaries `[4,54689816,76739248]`, no CUDA/OOM/nondeterminism/callback drift/allocation growth/pool leak, and promotion timing gates pass.

## Active task

- Task ID: `I061-R-H3`.
- Status: complete / `PASS`.
- Corrective commit: `0a7c111ffc1ba01b7260bec70c739e8bb3a66fa5`.
- Exact triple: Ceno `0a7c111f`, ceno-gpu `ddb71c98`, benchmark `3e2222a2`.
- Result: source-provenanced shared-packed default passes the three-way handoff
  comparison. Latest/old-GPU/old-CPU replay medians are
  593.609/722.579/1,137 ms; witness medians are 1,346/1,541/4,120 ms.
- Evidence root: `/home/wusm/data/codex-fulltracer-handoff-h1/h3-comparison/`.

## Active agents

- Worker ID: none; H3 was completed directly from the H2 authority.
- Latest verdict and current authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/H3/terminal-report.md`
  (`3b47dc3840895617600d25ed4def27b3b5e1428b90d0ce51070944b1146ec9c7`).
- Completed L7 workers and measurement rotations are retired; do not reuse for
  L8. L7 terminal authority is linked below.
- Completed L6C workers: `/root/implementor_i061r_l6c`,
  `/root/implementor_i061r_l6c_resume`, `/root/implementor_i061r_l6c_measure`;
  do not reuse for L7.
- Completed L5C workers: `/root/implementor_i061r_l5c`,
  `/root/implementor_i061r_l5c_resume`, `/root/implementor_i061r_l5c_measure`;
  do not reuse for L6C.
- Completed L4C workers: `/root/implementor_i061r_l4c`,
  `/root/implementor_i061r_l4c_measure`; do not reuse for L5C.
- Completed L3C workers: `/root/implementor_i061r_l3c`,
  `/root/implementor_i061r_l3c_resume`, `/root/implementor_i061r_l3c_measure`,
  `/root/implementor_i061r_l3c_cachefix`; do not reuse for L4C.
- Completed L2C workers: `/root/implementor_i061r_l2c`,
  `/root/implementor_i061r_l2c_resume`; do not reuse for L3C.
- Retired: prior L3-L5 workers and continuations; do not reuse.
- Probe: none.

## Latest result

- Current branch has the corrective shared-packed default committed at
  `0a7c111ffc1ba01b7260bec70c739e8bb3a66fa5`; its pre-refactor comparison
  authority is `4b4c95ca24beb240ac6e5efa5968122d00e4b5c7`.
- The former I061 v2 hybrid patch and terminal report are archived at `artifacts/fulltracer-gpu-ingress/archive/I061-v2-rejected-hybrid/ARCHIVE.md`. Patch SHA-256 is `19faaed1bf77bf4e2de8f783cf42bae39dcf1db2ec7846631b740e06f8d61fb0`; report SHA-256 is `6a09c1a6b402dad299e334ad5ec31a67c9518f0bdf240b77728399230b26b7bf`.
- Earlier I061 evidence is a rejected hybrid implementation, not a verdict on the preflight-pure layered architecture.
- I059 remains the no-replay canonical identity authority: report `artifacts/fulltracer-gpu-ingress/I059/terminal-report.md`, SHA-256 `aa28df13fd91b8c7fce38fbada7a21d6cebd3fe959581d256623806d5231f041`.
- I061-R L0 terminal verdict is `PASS / READY_FOR_L1`. Authority: `artifacts/fulltracer-gpu-ingress/I061-R/L0/terminal-report.md`, SHA-256 `0811c8bb448b2ab90e692aa6418cfa456b5e6639fbe1e3b67ab17df454cdee5e`.
- L0 five-pair median/p95 replay: 50.669956/51.424548 ms; control: 743.988875/751.872854 ms; median delta -693.318919 ms (-93.1894%). Exact canonical state/count/boundaries/digest/PC/exit; zero bytes, records, and chunks. L0 cumulative floor is 50.669956 ms.
- Retained Ceno binary-diff SHA-256: `1a5023e9a393b391cf21dfafea472caa74021cec5c8f5bf7c4b88009e52a6f04`; retained benchmark diff SHA-256: `fd7dc2905b3b47ac19fdce210318840d68e288e69ed41d954aecc16f0bbd2fe6`.
- I061-R L1 terminal verdict is `PASS / READY_FOR_L2`. Authority: `artifacts/fulltracer-gpu-ingress/I061-R/L1/terminal-report.md`, SHA-256 `3010dc1503818484c8d0065368b9148c428e92d4d409aa9fdaf7745b9a0ce717`.
- L1 five-pair median/p95 replay: 1,283.474162/1,301.180708 ms; paired L0: 50.727838/51.161313 ms; median delta +1,232.746324 ms (+2430.1180%). Exact 19,184,811 skeleton rows, 2,609,134,296 bytes, 2 shards/chunks, canonical identity, and poisoned disabled fields. L1 is the current primary/material bottleneck.
- I061-R L2 terminal verdict is `PASS / READY_FOR_L3`. Authority: `artifacts/fulltracer-gpu-ingress/I061-R/L2/terminal-report.md`, SHA-256 `3905da102003168fa0d9fe39f3741bc6f5650da0f70b44426a4f5b8173fac29d`.
- L2 five-pair median/p95 replay: 1,304.944516/1,336.767678 ms; paired L1: 1,289.805785/1,301.658048 ms; median delta +15.138731 ms (+1.1737%), non-material. Exact values, poison invariants, canonical identity, 19,184,811 rows, 2,609,134,296 bytes, and 2 chunks.
- I061-R L3 terminal verdict is `PASS / READY_FOR_L4`. Authority: `artifacts/fulltracer-gpu-ingress/I061-R/L3/terminal-report.md`, SHA-256 `7d28dd166e52aa1440e2c4ef186994677de0a741ae5da35d2e37e7a37a82b5be`.
- L3 five-pair median/p95 replay: 1,334.178491/1,360.694226 ms; paired L2: 1,287.939763/1,311.710972 ms; median delta +46.238728 ms (+3.5901%), narrowly non-material. Exact predecessor cycles, poison invariants, canonical identity, rows/bytes/topology.
- I061-R L4 terminal verdict is `PASS / READY_FOR_L5`. Authority: `artifacts/fulltracer-gpu-ingress/I061-R/L4/terminal-report.md`, SHA-256 `1f3f47fb5696f81b5f32956637c00b5dc9794b00e91d3a7ecffc398404d9dd29`.
- L4 five-pair median/p95 replay: 1,384.950789/1,415.643817 ms; paired L3: 1,324.364627/1,359.738019 ms; median delta +60.586162 ms (+4.5747%), material by >=50 ms. Exact memory chains/bounds, poison invariants, canonical identity, rows/bytes/topology.
- Current cumulative Ceno diff SHA-256: `ac5c883ce393f943f791a29ae3817e42bdc84b4452e35ddf4b567188be6a2d0f`; benchmark diff SHA-256: `702456774c8c4d848b32232c5ee68f6db6cea18ead23549ec836680f0cad64a3`.
- Positive layer ranking: L1 +1,232.746 ms (primary), L4 +60.586 ms (material), L3 +46.239 ms, L2 +15.139 ms. L4 cumulative cost above L0 is +1,334.281 ms.
- I061-R L5 terminal verdict is `PASS / READY_FOR_L6`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L5/terminal-report.md`.
- I061-R L1C terminal verdict is `PASS / READY_FOR_L2C`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L1C/terminal-report.md`. Five-pair
  median/p95 is 273.024252/275.122707 ms versus L1
  1,288.174999/1,301.788681 ms; median reduction 1,015.150747 ms (78.8038%).
  Physical bytes are 306,956,976 versus 2,609,134,296; logical decoded bytes
  remain identical. Same-binary SHA-256 is
  `a8ef538c55c65010913fdf2c7116489e4c9f2f5056fa4262b03f154f40a1d176`.
- I061-R L2C terminal verdict is `PASS / READY_FOR_L3C`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L2C/terminal-report.md`, SHA-256
  `d56eb0235f0703289537a7fd770750cb6e5af08c4a8e8350cf58859ba5968b28`.
  Five-pair median/p95 is 389.827767/392.058709 ms versus L1C
  273.511133/277.571600 ms; value semantics add 116.316634 ms (+42.5272%),
  entirely native. Physical bytes are 495,918,948 (81.0% below generic L2),
  with explicit 16/20/24/28-byte families and 6.462390 weighted stores/row.
- I061-R L3C terminal verdict is `PASS / READY_FOR_L4C`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L3C/terminal-report.md`, SHA-256
  `8ca825099c458d5a8eebe14372ee64e7ffe92000048d27a669a22e77c6966658`.
  Five-pair median/p95 is 424.524425/426.182982 ms versus L2C
  394.262854/408.216488 ms; predecessor semantics add 30.261571 ms (+7.6755%),
  below the 50 ms materiality gate. Dense ordinal-free 6-byte headers reduce
  physical bytes to 442,852,495 (-10.7006%) despite adding 27-bit predecessor
  lanes. All ten samples matched canonical identity, rows, topology, and
  fallbacks. The bounded temporary-cache nonce repair preserves permanent
  cache/schema identity and is covered at the 255-byte component limit.
- I061-R L4C terminal verdict is `PASS / READY_FOR_L5C`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L4C/terminal-report.md`, SHA-256
  `af242f219701962eb41fb307ed1777d01d54f1d47890e4af355ba6576587efe1`.
  Five-pair median/p95 is 435.782686/439.330895 ms versus L3C
  418.848810/432.038913 ms; memory/MMIO semantics add 16.933876 ms (+4.0430%),
  below the materiality gate. Physical bytes are 465,396,992 (+5.0907%): only
  load/store add one 27-bit predecessor and ECALL adds post heap/hint bounds;
  all families remain <=28 bytes and accepted samples are exact.
- I061-R L5C terminal verdict is `PASS / READY_FOR_L6C`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L5C/terminal-report.md`, SHA-256
  `7a9df76faaa205aa845d362b3421bfe8f50d4545a5e03fba19327a2ccb25d48c`.
  Five-pair median/p95 is 469.785927/475.274110 ms versus L4C
  441.264762/445.426372 ms; paired median cost is 29.319942 ms (+6.6445%),
  below the materiality gate. Physical bytes are 475,628,045 (+2.1983%),
  including 1,019,854 compact syscall-mask bytes. Schema2 closes exact-boundary
  cache identity; every accepted run has exact cursor closure and canonical
  identity, rows, topology, and fallbacks.
- I061-R L6C terminal verdict is `PASS / READY_FOR_L7`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L6C/terminal-report.md`, SHA-256
  `a17dd6e7612090ffce22ef0c29ea68931c26ecaa9cbb61eda8be60fce2d03b9f`.
  Five-pair median/p95 is 526.636464/534.084886 ms versus L5C
  470.259163/480.072014 ms; complete exceptional/syscall equality adds
  56.377301 ms (+11.9886%), material but cumulative replay remains below
  600 ms. Physical bytes are 537,027,635: hot rows/masks unchanged, plus
  2,781,450 header and 58,618,140 op bytes. All accepted samples are exact.
- I061-R L7 terminal verdict is `PASS / READY_FOR_L8`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L7/terminal-report.md`, SHA-256
  `7d0a0b83e25f93f417dad1a314a99a53f80672979d1b6613a4ce321ec92a5628`.
  Five-pair median/p95 is 599.441755/604.594478 ms versus L6C
  526.691508/549.113519 ms; compact routing closure adds 72.750247 ms
  (+13.8127%). Exact physical bytes are 584,400,562 versus 2,609,134,296
  logical generic bytes; family bytes/stores are 521,096,076/66,376,135.
  Topology is exactly 75 ranges (53/22), and median remains below 600 ms by
  0.558245 ms. Host reservation/routing median is 137.080644 ms and inclusive
  native pack/route median is 359.030209 ms.
- I061-R L8 measurement verdict is `CHANGES_REQUIRED`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L8/terminal-report.md`, SHA-256
  `b745586eb32fa47cb735757470ec684c07d1a7b3996f1b012f1c81a680160707`.
  All proof/ownership/stability gates pass, but FINAL omitted the compact-source
  selector and emitted 807,825,072 SoA bytes instead of 521,096,076 packed
  family bytes. Replay median/p95 was 1,771.610/1,806.906 ms versus CONTROL
  844/860 ms; RSS improved by 1,934,732 KiB. Packed-default refinement required.
- I061-R L8 static-AOT verdict is `CHANGES_REQUIRED`. Current authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L8/terminal-report.md`, SHA-256
  `3fc2cedb61268e10a17f80e4404f45f0b107405f144f3d6729216292f187cade`.
  FINAL is the fastest verified default: replay median/p95 601.014/608.941 ms
  versus same-binary CONTROL 622/641 ms; witness 1,367/1,398 versus
  1,837/1,869 ms; RSS improves 1,952,732 KiB. Formal <=600 ms and >=100 ms
  saving gates require ~79 ms more replay reduction.
- I061-R L8 final-round verdict is
  `HALT / CHANGES_REQUIRED / LAST_BEST_DEFAULT_RESTORED`. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/L8/verdict-implementor-i061r-l8-owner-warm.md`,
  SHA-256 `696da0aae4101447acb3156658238dbb05f146e03e2aa5f096eb40817b91816c`.
  The regenerated candidate passed full proof and every semantic, packed-byte,
  75=53/22, ownership, pool, and default gate, but replay was 761.933659 ms.
  Generated DSO size was 1,221,691,992 bytes, 2.318588x the accepted DSO.
  The exact 601.014019 ms median static authority is restored and focused-valid:
  emulator 7/7, GPU/AOT check, fmt/diffs/locks. Seven-file diff is
  `c35a113e52313e5d362e0cc3036fdef7186327980391045688f94afc7e02eedd`.
  Rejected patch SHA is `3e6436c1e3e8227b3fb960c1d8e7133cf0803fa01c89268f3c8b30aaf353e42f`;
  rejected DSO/meta are absent and its binary is non-authoritative.
- I061-R H2 verdict is `PASS`. Commit `0a7c111f` makes the source-provenanced
  shared packer default. The empty cache produced a 542,964,312-byte DSO; warm
  proof and all five samples matched 521,096,076 bytes, 75=53/22 topology,
  proof/ownership/cleanup gates, and exact workload identity. Median/p95 replay
  is 593.609482/607.139310 ms; witness 1,346 ms, assignment 489 ms, app proof
  6,663.920382 ms, and E2E 8,825.214694 ms. Authority:
  `artifacts/fulltracer-gpu-ingress/I061-R/H2/iteration-1-worker.md`.

## Recent task index

- I059: canonical no-replay witness identity authority.
- I060: candidates rejected and production restored.
- I061: correctness-complete hybrid block replay rejected for performance; archived.
- I061-R-L0: complete; exact record-free floor measured.
- I061-R-L1: complete; skeleton rows exact, +1,232.746 ms material delta.
- I061-R-L2: complete; value fields exact, +15.139 ms non-material delta.
- I061-R-L3: complete; register predecessors exact, +46.239 ms narrowly non-material.
- I061-R-L4: complete; memory chains/bounds exact, +60.586 ms material delta.
- I061-R-L5: complete; exact masks/cursor closure, +128.975 ms versus L4.
- I061-R-L1C: complete; 273.024 ms median, -78.804% versus L1, 306,956,976 physical bytes.
- I061-R-L2C: complete; exact values, 389.828 ms median, 495,918,948 bytes.
- I061-R-L3C: complete; exact predecessors, 424.524 ms median, 442,852,495 bytes.
- I061-R-L4C: complete; exact memory/MMIO, 435.783 ms median, 465,396,992 bytes.
- I061-R-L5C: complete; exact future access, 469.786 ms median, 475,628,045 bytes.
- I061-R-L6C: complete; full equality, 526.636 ms median, 537,027,635 bytes.
- I061-R-L7: complete; exact bytes/topology, 599.442 ms median, 584,400,562 bytes.
- I061-R-H2: complete; reproducible shared-packed default passes all source,
  DSO-size, proof, topology, ownership, cleanup, and timing gates.
- I061-R-H3: complete; three-way full-proof comparison supports
  `latest GPU > old GPU >> old CPU` in replay/witness scope.

## Handoff

- Preserve every generic oracle identity/test/report, L1C-L7 strict
  markers, decoders, layout assertions, and forward-store assembly checks.
- Preserve L3C ordinal-free 20-bit PC/25-bit instruction header, 27-bit
  predecessor lanes, exact alias/subcycle ordering, independent row/byte
  cursors, two-tag accounting, and strict launcher.
- Preserve L4C's 28-byte load/store and 18-byte ECALL layouts, exact resident
  memory order, heap/hint bounds, and native/scalar transitions.
- Preserve L5C schema2, <=29-byte rows, 11-byte syscall masks, exact resident
  cursor validation/closure, source access order, and mixed syscall coverage.
- Preserve L6C schema2, 30-byte every-ECALL headers, 20-byte ops, unchanged hot
  rows/masks, authoritative syscall semantics, and complete decoded equality.
- Preserve L7 schema1, `MaybeUninit` initialized-prefix safety, transactional
  static ranks, exact family bytes/stores, 75 ranges (53/22), and L6C side
  streams. L8 must reuse these owned bytes directly without CPU repacking.
- L8 owns lifecycle only: two warmed slots, explicit GPU-event handoff/recycle,
  stable pointers/capacities, descriptor closure, derived/public outputs, and
  failure cleanup. Any steady-state allocation or premature reuse is a gate
  failure.
- Keep one-pass forward writes. Reject whole-row initialization, destination
  loads/RMW, scattered patching, generic allocation, and post-hoc conversion.
- Record L8 ownership/handoff correctness and final/control GPU measurements
  under `artifacts/fulltracer-gpu-ingress/I061-R/L8/`, then close the campaign
  only after final exactness, stability, and promotion timing gates pass.
- Preserve replay emitter source/schema/variant provenance, the shared-packed
  production default, and the fully inlined path as diagnostic-only.
- H3 is a good handoff state. Keep `0a7c111f` as production default; retain old
  CPU as correctness/fallback and the old GPU triple as historical authority.
  A future replay campaign may profile the latest shard-1 ~4 ms median
  regression, but it is non-blocking and does not authorize an architecture
  change.
