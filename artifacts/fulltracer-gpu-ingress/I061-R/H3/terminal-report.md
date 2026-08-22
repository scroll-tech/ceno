# I061-R H3 FullTracer hand-off comparison

Date: 2026-08-22

## Verdict

`PASS / GOOD_HANDOFF_STATE` for the touched FullTracer and witness-generation
scope. Lower is better, so the measured ordering is:

`latest packed AOT + GPU > old compact AOT + GPU >> old AOT + CPU`.

The latest default improves on old GPU witness generation, while old GPU
witness generation remains substantially faster than old CPU witness
generation. The formerly small whole-run improvement is explained by overlap
and by setup/proof work outside this scope, not by a small witness improvement.

## Revisions and artifacts

- Latest triple: Ceno `0a7c111ffc1ba01b7260bec70c739e8bb3a66fa5`,
  ceno-gpu `ddb71c98`, benchmark `3e2222a2`. Binary SHA-256:
  `627343fd00a9b2ddbcc4cc262de72bf81068eac83e2244b453a8bcd2e57285cc`.
- Latest replay cache key is ABI78, variant `shared-packed`, emitter digest
  `0f4b1cc086a07b29413675438daff7b571d0a67332428e240444404d03a7a0bf`.
  The 542,964,312-byte DSO SHA-256 is
  `d93c626aa6e72d9a21b5cc305c39ee70f6762049b5c61721b94fdafd21f22e22`.
- Old triple: Ceno `4b4c95ca24beb240ac6e5efa5968122d00e4b5c7`,
  ceno-gpu `5bc43b5f1053918e307d01f0ec34017de6d54bac`, benchmark
  `085b59e0257df390ad2d1698e006a34b6cec8584`. Binary SHA-256:
  `4f90c6da4e775f1979bf282593f9e72b63e87235ed96b8aa3614b1781ded635d`.
- Old replay uses its independently generated 526,912,088-byte ABI77 DSO,
  SHA-256
  `1400a928caba4d5ae294c2d5204546fab304242d37094c8330b632d027f7a2d8`.
  No old artifact was copied, renamed, or relabelled.

All scenarios used the cached chain-1 block 23,587,691, AVX2,
`CUDA_ARCH=120`, lanes=4, cache level 1, jagged height 23, cell cap
2,684,354,560, and chunk capacity 262,144. Old GPU explicitly enabled the
old compact source gate; old CPU disabled GPU witness generation and used AOT
FullTracer replay. The GPU proof backend remained enabled in all three.

The old execute gate and every proof matched 19,184,811 instructions,
76,739,248 cycles, two shards, and boundaries `[4,54689816,76739248]`.
Each measured log reports `CUDA Backend Enabled`, an expected cache hit, a
verified recursion aggregation proof, and exit status zero.

## Measured medians

Latest uses five previously accepted samples. Each old scenario has one
excluded warm and three unreplaced measured samples in rotated order
`GPU1, CPU1, CPU2, GPU2, GPU3, CPU3`.

| Metric (ms) | Latest GPU | Old GPU | Old CPU |
|---|---:|---:|---:|
| FullTracer replay shard 0 | 464.164 | 594.268 | 511 |
| FullTracer replay shard 1 | 132.295 | 128.311 | 621 |
| FullTracer replay total | 593.609 | 722.579 | 1,137 |
| Witness shard 0 | 986 | 1,140 | 2,370 |
| Witness shard 1 | 355 | 391 | 1,750 |
| Witness total | 1,346 | 1,541 | 4,120 |
| Assignment total | 489 | 574 | 2,342 |
| App proof | 6,663.920 | 6,752.455 | 8,700.740 |
| App + recursion proof | 8,825.215 | 8,984.145 | 11,046.821 |
| Process wall clock | 30,100 | 30,310 | 32,150 |

Total replay raw samples are latest
`[599.108222, 593.609482, 607.139310, 591.672876, 591.844887]`, old GPU
`[729.585837, 718.713789, 722.578923]`, and old CPU
`[1137, 1112, 1181]` ms. Total witness raw samples are latest
`[1346, 1328, 1351, 1344, 1356]`, old GPU `[1541, 1544, 1520]`, and old CPU
`[4200, 4090, 4120]` ms.

## Comparison and diagnosis

- Latest versus old GPU: replay is 128.969 ms lower (`17.85%`, `1.217x`
  speedup), witness is 195 ms lower (`12.65%`, `1.145x`), and assignment is
  85 ms lower (`14.81%`). The replay gain is shard-0 driven; shard 1 is about
  4 ms slower at the median and is not a hand-off blocker.
- Old GPU versus old CPU: replay is 414.421 ms lower (`36.45%`, `1.574x`),
  witness is 2,579 ms lower (`62.60%`, `2.674x`), and assignment is 1,768 ms
  lower (`75.49%`, `4.080x`). This supports `>>` for witness generation.
- Latest versus old CPU: replay is `1.915x`, witness `3.061x`, and assignment
  `4.789x` faster.
- Old GPU versus CPU looks small only when judging the entire process wall
  clock: 30.31 versus 32.15 seconds (`5.72%`). Base setup, GPU proof, and
  recursion dominate that number, and CPU witness work overlaps downstream GPU
  proving. In the touched witness span and app-proof critical path the gain is
  large: 4.120 to 1.541 seconds and 8.701 to 6.752 seconds respectively.

## Campaign actions

1. Keep `0a7c111f` shared-packed ABI78 emitter as the performant production
   default and treat this state as ready for hand-off.
2. Preserve source/schema/variant cache provenance, 75=53/22 topology, compact
   byte/store gates, proof/ownership/cleanup checks, and the generic oracle.
3. Retain old CPU witness only as the correctness/fallback path and the old GPU
   triple only as a historical comparison authority.
4. If further replay work is requested, profile the latest shard-1 ~4 ms median
   regression first; do not change architecture or block this hand-off for it.

Raw evidence is under
`/home/wusm/data/codex-fulltracer-handoff-h1/h3-comparison/`; latest five-run
evidence is under
`/home/wusm/data/codex-fulltracer-handoff-h1/shared-packed-reproduction/measurements/`.
