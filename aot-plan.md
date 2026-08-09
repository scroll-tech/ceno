# Ceno AOT Follow-Up Plan

## Packed Memory Result (2026-08-09)

The production AOT memory representation now packs each dense memory cell as
`{u32 latest-access instruction ordinal, u32 guest value}`. The global tracer
cycle remains `u64`; only the memory-cell stamp is compressed, and it is
decoded back to the exact memory subcycle (`ordinal << 2 | 3`). Native and Rust
memory paths preserve the low value half and update the high access half only
when proof-compatible tracing requires it.

Five warm samples were collected for both the previous implementation and the
packed candidate. Artifact compilation was excluded from the reported AOT
Preflight execution span.

| Block | Variant | AOT Preflight samples (s) | Mean (s) | Median (s) | Peak RSS samples (KiB) | Mean RSS (KiB) |
| --- | --- | --- | ---: | ---: | --- | ---: |
| 25580200 | baseline | 12.292142109, 12.480104235, 12.658609300, 12.613870775, 12.372804636 | 12.483506211 | 12.480104235 | 2871524, 2870532, 2870440, 2871292, 2870792 | 2870916.0 |
| 25580200 | packed | 12.273612961, 12.524734029, 12.517461685, 12.378223122, 12.405117018 | 12.419829763 | 12.405117018 | 2687020, 2686816, 2686376, 2685400, 2686080 | 2686338.4 |
| 25687400 | baseline | 8.618121079, 8.633817295, 8.755350706, 8.699744061, 8.705862503 | 8.682579129 | 8.699744061 | 2513720, 2513528, 2514084, 2514348, 2514908 | 2514117.6 |
| 25687400 | packed | 8.473666819, 8.581467122, 8.599169813, 8.718595133, 8.608360408 | 8.596251859 | 8.599169813 | 2361256, 2359820, 2360364, 2361148, 2360040 | 2360525.6 |

For block 25580200 the five-run mean improves by 0.063676448s (0.51%) and
mean peak RSS falls by 184577.6 KiB (6.43%). Block 25687400 improves by 1.00%
in mean execution time and 6.11% in mean peak RSS. Every sample produced block
hash `34439c597563024690ce3c91a082c34507569c7e18cc4d1b3b68550b791a2773`
for block 25580200 or
`d9beb945e65579fa6d95d14012936cf8c7dcf7c52ed54d96f53aa3b0538ff899`
for block 25687400, with unchanged instruction totals (994896527 and
663258404) and cycles (3979586112 and 2653033620). Focused `ceno_emul`,
`ceno_host`, AOT integration, and proof-facing witness checks passed.

Conclusion: keep the packed representation for its material memory reduction,
but do not treat it as the latency solution. Its 0.51% target-block time gain
is far below the feature-selection gate.

The corrected OpenVM comparison uses its cached AOT native span, not the outer
`sdk.execute` span that also performs assembly generation and shared-library
compilation. Two local `execute_e1` samples were 1.47s and 1.51s (1.49s mean)
for 600039843 guest instructions. Ceno executes 994896527 instructions for the
same block and hash: 394856684 additional instructions, or 1.658x OpenVM's
count. Earlier access-tracking trims bottomed out near 10.55s, so tracking alone
cannot explain the remaining execution gap.

### Pure AOT diagnostic baseline

The first warm benchmark-only pure artifact for block 25580200 completed in
5.914101908s and preserved the required block hash, zero exit code, and all
994896527 guest instructions. The measured split was 2.996984944s outside Rust
fallbacks and 2.917116964s inside 2036036 fallbacks. Of those, 550681 were
dynamic-PC recovery steps and the remainder were ecalls. Artifact setup was
332.453771ms on the warm cache path and is excluded from the execution number.
Peak process RSS was 431468 KiB. The artifact identity was
`a38e283553d65fa5c9a44042218415d7cfd0cf71919cfb3c2794eeb618dd4b34-abi28-pure-x86_64-linux`.

Exploratory trim: register/control-only basic blocks accounted retired
instructions once per block instead of once per instruction, with a cold exact
budget fallback preserving `max_steps`. The comparable execution reached the
same hash, exit code, instruction count, and fallback counts in 5.890454992s
(2.959418556s outside fallbacks and 2.931036436s inside). The observed 0.023646916s
(0.40%) improvement is far below both retention gates and was not repeated as a
five-run candidate. The trim was removed. This rejects block accounting in its
limited register/control-only form; it does not rule out a broader design that
also safely covers memory blocks.

Retained candidate: pure native instructions now keep next PC in the resident
dispatch register and use a pure completion sequence rather than storing and
reloading next PC through `AotRuntimeContext`, mirroring it on the stack, and
checking callback status. Five warm samples pinned to CPU 0 on an AMD Ryzen 9
5900XT with the `schedutil` governor were:

| Sample | Total (s) | Outside fallbacks (s) | Fallback (s) | Peak RSS (KiB) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 5.128647843 | 2.350559900 | 2.778087943 | 424816 |
| 2 | 5.169784328 | 2.373606283 | 2.796178045 | 421856 |
| 3 | 5.167623989 | 2.380161737 | 2.787462252 | 430508 |
| 4 | 5.160250988 | 2.377315099 | 2.782935889 | 424804 |
| 5 | 5.174068376 | 2.380187852 | 2.793880524 | 425204 |

The median is 5.167623989s total, 2.377315099s outside fallbacks, and
2.787462252s in fallbacks. Every sample matched the required hash, exit code,
994896527 instructions, and identical fallback counts. Relative to the first
warm ABI-28 baseline, total time improves by 0.746477919s (12.62%), clearing
both retention gates. The retained artifact identity ends in
`abi30-pure-x86_64-linux`.

The control block 25687400 also matched its required hash and zero exit code,
executed 663258404 instructions, and completed in 3.715457166s total
(1.702176507s outside fallbacks and 2.013280659s in fallbacks). No prior pure
baseline exists for a valid percentage-regression claim; production packed
Preflight remained faster than its recorded unpacked control baseline.

The 3.0s pure target is not yet met. The retained change puts native-only time
below the target, but 2036036 Rust fallbacks still consume a 2.79s median. The
next measured priority is ecall/fallback execution, especially the 600576
secp256k1-double, 299171 secp256k1-add, 195780 Keccak-permute, and 195777
Keccak-XOR-in calls, rather than further access-tracking work.

### Pure AOT host profile and rejected register-base trim

A CPU-0-pinned `perf stat` run of the ABI-30 artifact retired 89,405,298,386
host instructions in 31,088,216,292 cycles (2.88 IPC), with 9,409,144,338
branches, 151,589,372 branch misses (1.61%), and 502,526,983 cache misses.
This measures the whole benchmark process, while the benchmark's own split for
that instrumented run was 2.4776s native and 2.9302s in fallbacks.

The matching `perf record` profile was dominated by fallback crypto rather than
native dispatch: secp256k1 modular inversion was 17.31% of samples,
`tiny_keccak::keccakf` 3.53%, secp256k1 field multiplication 3.50%, k256 point
addition 2.44%, secp256k1 field squaring 2.35%, and Keccak software code 1.90%.
The AOT dispatch loop was 2.08%, the hottest native AOT memory symbol 1.37%, and
`aot_exec_one` 1.27%. These data reinforce the fallback-first priority.

A follow-up trim pinned the guest register-file base in callee-saved `%r14` for
pure artifacts. Five warm target/control pairs were alternated on CPU 0:

| Sample | Target total (s) | Target native (s) | Target fallback (s) | Control total (s) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 5.166670944 | 2.242645256 | 2.924025688 | 3.637591930 |
| 2 | 5.172576993 | 2.243702951 | 2.928874042 | 3.648101970 |
| 3 | 5.193288135 | 2.261705102 | 2.931583033 | 3.645297047 |
| 4 | 5.145129991 | 2.246988275 | 2.898141716 | 3.643232283 |
| 5 | 5.154314029 | 2.238116090 | 2.916197939 | 3.642553004 |

The target medians were 5.166670944s total, 2.243702951s native, and
2.924025688s fallback. The total is only 0.000953045s (0.018%) below the
ABI-30 median, far below both retention gates. The control median was
3.643232283s and did not regress. All ten runs matched their expected hashes,
zero exit codes, and instruction counts. The trim and its ABI bump were
removed.

## Implemented In This Pass

Current base commit before block-boundary planner work: `8d5cf094 Make Preflight AOT shard-aware`.

- Extended direct native `PreflightTracer` support to shard-planned configs instead of only the default full-shard config.
  - Direct mode now works with finite `max_cycle_per_shard`.
  - Direct mode now works with finite `max_cell_per_shard`.
  - Direct mode now works when a `StepCellExtractor` is present for native non-`ECALL` instructions.
- Added runtime per-instruction step-cell metadata for AOT Preflight runs.
  - AOT compilation remains program-only.
  - `run_to_halt` builds a dense step-cell table from the active `PreflightTracer` config.
  - Native emitted code loads the current instruction's static step-cell cost from that table.
- Kept `ECALL` and syscall witness behavior Rust-owned.
- Added native shard-planner counter updates for direct Preflight:
  - current cells
  - current cycle-in-shard
  - current step count
  - shard id / first-shard cell target
  - max cycle and max cell limits
- Kept shard boundary vector mutation Rust-owned.
  - Native code calls a narrow helper only when a split is detected.
  - The helper pushes the boundary, updates `current_shard_start_cycle`, updates `max_step_shard`, and resets current-shard counters.
- Kept `NextCycleAccess` map mutation Rust-owned.
  - Native code still updates dense latest-access cells directly.
  - Native code calls the access helper only for first touches or accesses whose previous cycle is before the current shard start.
- Added direct native Preflight memory support for stores.
  - Native `SB`, `SH`, and `SW` now record Preflight memory accesses directly on the heap/stack/hints fast path.
  - Native loads and stores update heap/stack/hints min/max range state directly so zkVM final-memory collection sees stack/heap/hint ranges.
  - Misaligned, `prog_data`, and non-standard memory ranges continue to fall back to Rust slow paths.
- Limited AOT basic-block emission to statically reachable blocks from the ELF entry.
  - This prevents Reth-sized guests from spending minutes writing multi-GB assembly for unreachable instruction space.
  - Indirect `JALR` targets not in the static graph continue through the existing dynamic Rust single-step fallback.
- Fixed AOT witness replay shard indexing.
  - Replay now returns local `FullTracer` step indices after `start_new_shard()`.
  - This fixes the Reth shard-1 panic: `step index 15915783 out of bounds 1`.
- Added shard-aware direct Preflight tests:
  - finite cycle shard parity
  - finite cell shard parity with a test `StepCellExtractor`
  - native store final-access parity
  - shard boundaries and `max_step_shard` parity
- Added direct Preflight block-boundary shard planning, now the default direct Preflight path.
  - Native code still updates exact per-instruction Preflight access cycles.
  - Eligible compute/control basic blocks batch only planner cell/cycle/step counter updates.
  - Shard-limit checks move from every instruction to basic-block entry for eligible blocks.
  - Blocks containing memory ops, `JALR`, `ECALL`, or unsupported opcodes keep the exact per-instruction direct planner path.
  - Block cell costs are built at run time from the active `StepCellExtractor`, matching the existing per-instruction step-cell table ownership.
  - This mode is intentionally approximate at shard cuts: a single eligible block can overrun a limit because cuts are only considered before block entry.
- Fused native memory range classification with direct Preflight heap/stack/hints min/max updates.
  - The memory fast path now updates only the already-classified region instead of scanning all tracked regions again in the generic post-step hook.
  - Misaligned and non-standard memory ranges still fall back to Rust-owned behavior.
- Cached direct Preflight access bookkeeping values once per native step.
  - Native code loads the dense latest-access base pointer, current cycle, and current shard start once per step.
  - Register and memory access updates reuse those cached values.
  - The rare first-touch or next-cycle-boundary helper path reloads the cache after returning.
- Extended the Step 5 simple-memory block direction with additional basic-block-boundary guard hoisting.
  - Commit: `7521b744 Hoist AOT preflight block guards`.
  - Follow-up cleanup: removed the `CENO_AOT_BLOCK_SHARD_PLAN` gate and made the fastest accepted block-planned path unconditional.
  - Follow-up cleanup also removed AOT env knobs for profile sample size, profile root cap, setup-time all-static compile, and debug max-step override. Profile sampling now uses fixed defaults of `30_000_000` steps and `8192` roots.
  - For block-planned AOT Preflight blocks, the `trace_next_pc == pc` busy-loop guard now runs once at basic-block exit instead of after every native step.
  - The per-step busy-loop guard remains on exact/non-block-planned paths.
  - This is valid for the existing block-planned path because basic-block partitioning already terminates blocks at static branches, `JAL`, `JALR`, `ECALL`, and invalid instructions, and eligible planned blocks exclude dynamic mid-block control flow.
  - The memory fast-path guard now hoists the register-array pointer load once per block instead of once per memory access guard.
  - Validation:
    - `cargo fmt --check`
    - `cargo test -p ceno_emul --features aot-x86_64 aot::tests -- --nocapture`
    - `cargo check -p ceno_zkvm --features aot-x86_64`
  - Reth measurements versus the Step 5 baseline:
    - Block `23587691`: `494.768628ms` -> `494.567954ms`, effectively neutral.
    - Block `23817600`: `6843.316513ms` -> `6568.146808ms`, about `4.0%` faster.
  - Keep rationale: meets the acceptance policy because one block improves by more than `1%` and the other is not slower by more than `0.5%`.
  - Other guards considered:
    - `max_steps` is already partially protected by `emit_preflight_direct_block_budget_guard`; fully removing per-step handling requires splitting `emit_after_step` because it also handles halt/error and step count updates.
    - cycle/pending-step updates may be movable for register-only block-atomic paths, but memory-exact blocks still need exact access-cycle bookkeeping.
    - memory bounds are already moved/suppressed for Step 5 eligible memory blocks, so further work there should focus on exactness-preserving reductions only.

- Added a Ceno-side `AotRuntimeContext` and `AotInstance` alias.
- Changed the generated native entry ABI to receive runtime context, slow-path helper, and native trace helper.
- Exposed a crate-private VM register pointer for AOT codegen.
- Added native x86 execution for the first register-only ALU tier:
  - `ADD`, `SUB`, `XOR`, `OR`, `AND`
  - `ADDI`, `XORI`, `ORI`, `ANDI`
- Extended native compute support:
  - `SLL`, `SRL`, `SRA`, `SLT`, `SLTU`
  - `SLLI`, `SRLI`, `SRAI`, `SLTI`, `SLTIU`
- Added native x86 execution for branch and direct jump control flow:
  - `BEQ`, `BNE`, `BLT`, `BGE`, `BLTU`, `BGEU`
  - `JAL`, `JALR`
- Added native x86 execution for multiply:
  - `MUL`, `MULH`, `MULHSU`, `MULHU`
- Added native x86 execution for divide/remainder:
  - `DIV`, `DIVU`, `REM`, `REMU`
  - Handles divide-by-zero and signed-overflow RISC-V semantics before using x86 division.
- Added feature-gated native x86 execution for `u16limb_circuit` opcodes:
  - `LUI`, `AUIPC`
- Added guarded native x86 execution for word memory:
  - `LB`, `LH`, `LW`, `LBU`, `LHU`, `SB`, `SH`, `SW`
  - Fast path handles aligned heap/stack/hints accesses.
  - Misaligned and non-standard-range accesses fall back to the Rust slow path for exact traps and `prog_data` behavior.
- Preserved existing basic-block partitioning and direct-successor native jumps.
- Preserved interpreter-equivalent trace order for native ALU steps through a narrow trace finalizer:
  - fetch
  - maxtouch-before
  - rs1/rs2 reads
  - rd write
  - PC after
  - maxtouch-after
  - advance / shard planning / next access tracking
- Added differential unit coverage for native arithmetic, wrapping immediates, `x0` writes, register parity, and `StepRecord` parity.
- Added differential unit coverage for shift masking, arithmetic shifts, signed comparisons, unsigned comparisons, negative immediates, register parity, and `StepRecord` parity.
- Added differential unit coverage for native branches, skipped fallthrough instructions, `JAL` link writes, register parity, and `StepRecord` parity.
- Added differential unit coverage for native `JALR`, dynamic target dispatch, and exact slow-path misalignment traps.
- Added differential unit coverage for native multiply low-word and signed/unsigned high-word behavior, register parity, and `StepRecord` parity.
- Added differential unit coverage for native divide/remainder, divide-by-zero behavior, signed-overflow behavior, register parity, and `StepRecord` parity.
- Added feature-gated differential unit coverage for native `LUI/AUIPC`.
- Added pure native AOT execution mode that skips per-instruction Rust trace callbacks.
- Added an ignored loop-heavy perf probe that reports compile time separately from interpreter, traced AOT, and pure AOT execution.
- Added differential unit coverage for native `LW/SW`, dense memory writes, memory `StepRecord` parity, and exact slow-path misalignment traps.
- Added differential unit coverage for byte/halfword load sign extension, zero extension, byte/halfword stores, range access faults, register parity, and memory `StepRecord` parity.
- Split native opcode dispatch into explicit compute, control-flow, and memory families.
- Added coverage that unsupported opcodes such as `DIV`, `JALR`, and `ECALL` remain on the slow path.

## Verified

- `cargo test -p ceno_emul --features aot-x86_64 aot::tests -- --nocapture`
- `cargo check -p ceno_emul --features aot-x86_64`
- `cargo check -p ceno_zkvm --features aot-x86_64`
- `cargo test -p ceno_emul --features aot-x86_64 aot_preflight_block_plan_matches_without_shard_cuts -- --nocapture`
- `cargo fmt --check`
- `RUST_MIN_STACK=536870912 cargo test -p ceno_zkvm --features aot-x86_64 'e2e::tests::fibonacci_guest_aot_emulates' -- --nocapture`
- `RUST_MIN_STACK=33554432 cargo test -p ceno_zkvm --features aot-x86_64 keccak_syscall_guest_aot_emulates -- --nocapture`
- `cargo test -p ceno_emul --release --features aot-x86_64 aot::tests::aot_pure_perf_probe -- --ignored --nocapture`
- Reth 23587691, `CENO_MAX_CELL_PER_SHARD=805306368`, CPU witgen, GPU proving, cache level 1, `CENO_GPU_JAGGED_RESHAPE_LOG_HEIGHT=23`.

Latest loop-heavy micro probe:

- steps: 3,000,003
- compile/load: 26.35 ms
- interpreter: 60.72 ms
- traced AOT execution: 38.56 ms, 1.575x faster than interpreter
- pure AOT execution: 7.54 ms, 8.056x faster than interpreter

Note: the keccak AOT e2e overflowed the default Rust test-thread stack without `RUST_MIN_STACK`, then passed with a 32 MiB stack after the native memory-bound fix.

Reth 23587691 two-shard run:

- Interpreter baseline log: `sanity_23587691_interp_aotcmp_aotfeat_witgen0_cache1_h23_maxcell6_20260713_163422.log`
  - preflight-execute: 799 ms
  - program executed: 24,790,776 instructions / 99,163,108 cycles
  - shards: 2, boundaries `[4, 63663136, 99163108]`
  - app create_proof: 12.828576875 s
  - recursion create_proof: 2.368983105 s
  - total create_proof: 15.22831466 s
- AOT profile-root log: `sanity_23587691_aot_directnopcmirror_fullprofile_witgen0_cache1_h23_maxcell6_20260713_174927.log`
  - AOT profile sampled: 24,790,776 steps in 846.289728 ms, roots=5359 selected_roots=5359
  - AOT compile/load: 54.816362632 s, blocks=15196, reachable_instructions=133818
  - preflight-execute: 589 ms
  - AOT execution time inside preflight: 589.324545 ms
  - fallback_steps: 243,501 (0.98%)
  - program executed: 24,790,776 instructions / 99,163,108 cycles
  - shards: 2, boundaries `[4, 63663136, 99163108]`
  - app create_proof including AOT profile/compile: 70.088989506 s
  - app create_proof excluding AOT profile/compile setup: about 14.426337146 s
  - recursion create_proof: 2.35438281 s
  - total create_proof including AOT setup: 72.475381522 s
- AOT register-static access experiment: `sanity_23587691_aot_regstatic_fullprofile_witgen0_cache1_h23_maxcell6_20260713_175903.log`
  - AOT profile sampled: 24,790,776 steps in 865.003249 ms, roots=5359 selected_roots=5359
  - AOT compile/load: 53.548994192 s, blocks=15196, reachable_instructions=133818
  - preflight-execute: 594 ms
  - AOT execution time inside preflight: 593.891493 ms
  - fallback_steps: 243,501 (0.98%)
  - app create_proof including AOT profile/compile: 69.133466161 s
  - recursion create_proof: 2.382841375 s
  - total create_proof including AOT setup: 71.548594398 s
- AOT block-boundary shard planner experiment: `sanity_23587691_aot_blockplan_fullprofile_witgen0_cache1_h23_maxcell6_20260713_184117.log`
  - historical env: `CENO_AOT_BLOCK_SHARD_PLAN=1`; this path is now default.
  - AOT profile sampled: 24,790,776 steps in 843.246204 ms, roots=5359 selected_roots=5359
  - AOT compile/load: 53.004060935 s, blocks=15196, reachable_instructions=133818
  - preflight-execute: 570 ms
  - AOT execution time inside preflight: 570.282164 ms
  - fallback_steps: 243,501 (0.98%)
  - shards: 2, boundaries `[4, 63663136, 99163108]`
  - app create_proof including AOT profile/compile: 68.629844087 s
  - app create_proof excluding AOT profile/compile setup: about 14.782536948 s
  - recursion create_proof: 2.435336288 s
  - total create_proof including AOT setup: 71.096151264 s
  - preflight speedup over interpreter: `799 / 570.282164 = 1.40x`
  - preflight improvement over direct per-instruction shard planner AOT: `589.324545 / 570.282164 = 1.03x`
- AOT block planner plus fused memory-bound update: `sanity_23587691_aot_blockplan_memfuse_fullprofile_witgen0_cache1_h23_maxcell6_20260713_185252.log`
  - historical env: `CENO_AOT_BLOCK_SHARD_PLAN=1`; this path is now default.
  - AOT profile sampled: 24,790,776 steps in 850.078361 ms, roots=5359 selected_roots=5359
  - AOT compile/load: 53.531814868 s, blocks=15196, reachable_instructions=133818
  - preflight-execute: 545 ms
  - AOT execution time inside preflight: 545.429258 ms
  - fallback_steps: 243,501 (0.98%)
  - shards: 2, boundaries `[4, 63663136, 99163108]`
  - app create_proof including AOT profile/compile: 68.550592785 s
  - app create_proof excluding AOT profile/compile setup: about 14.168699556 s
  - recursion create_proof: 2.342365743 s
  - total create_proof including AOT setup: 70.924246523 s
  - preflight speedup over interpreter: `799 / 545.429258 = 1.46x`
  - preflight improvement over block-boundary planner: `570.282164 / 545.429258 = 1.05x`
- AOT block planner plus fused memory bounds plus cached access bookkeeping: `sanity_23587691_aot_blockplan_memfuse_accesscache_fullprofile_witgen0_cache1_h23_maxcell6_20260713_185858.log`
  - historical env: `CENO_AOT_BLOCK_SHARD_PLAN=1`; this path is now default.
  - AOT profile sampled: 24,790,776 steps in 848.554958 ms, roots=5359 selected_roots=5359
  - AOT compile/load: 55.723621655 s, blocks=15196, reachable_instructions=133818
  - preflight-execute: 533 ms
  - AOT execution time inside preflight: 532.595503 ms
  - fallback_steps: 243,501 (0.98%)
  - shards: 2, boundaries `[4, 63663136, 99163108]`
  - app create_proof including AOT profile/compile: 71.018177266 s
  - app create_proof excluding AOT profile/compile setup: about 14.445996653 s
  - recursion create_proof: 2.340359624 s
  - total create_proof including AOT setup: 73.389153783 s
  - preflight speedup over interpreter: `799 / 532.595503 = 1.50x`
  - preflight improvement over fused memory-bound update: `545.429258 / 532.595503 = 1.02x`
- Non-AOT control run accidentally using `CENO_AOT=1` without `CENO_EMULATOR_BACKEND=aot`: `sanity_23587691_aot_regstatic_fullprofile_witgen0_cache1_h23_maxcell6_20260713_175549.log`
  - preflight-execute: 803 ms
  - app create_proof: 12.151200913 s
  - total create_proof: 14.626959181 s
- Setup-time static-leader compile experiment: `sanity_23587691_aot_setupstatic_witgen0_cache1_h23_maxcell6_20260713_181007.log`
  - failed during base setup with `AOT setup compile failed: No space left on device (os error 28)`
  - large `/tmp/ceno-aot-*` temp directories were removed after the failure
  - interpretation: compiling every static leader is not viable for Reth 23587691 in the current assembly/object pipeline; the setup compile path has been removed.

Current Reth interpretation: the original apparent hang was compile/codegen blowup, not a native execution infinite loop. Profile-root AOT now keeps fallback under 1%, but direct Preflight still only reaches about `799 / 589 = 1.36x` over interpreter on this Reth shape. The remaining bottleneck is native direct Preflight bookkeeping itself, not Rust fallback coverage. Setup-time all-static compile remains architecturally interesting, but a no-profile static leader candidate set is too large for the current codegen path and is no longer kept as a runtime switch.

## Next Steps

Target: support all RV32IM instructions in native AOT except `ECALL`. Done.

- Keep `ECALL` Rust-owned for halt handling, syscall witnesses, public I/O, and other side effects.
- Keep `INVALID` as a trap, not a supported instruction.
- Once those gaps are closed, harden fallback policy so any executed unsupported non-`ECALL` instruction errors explicitly instead of silently interpreting.

1. Extend native compute support. Done.
   - Added `SLL`, `SRL`, `SRA`, `SLT`, `SLTU`.
   - Added `SLLI`, `SRLI`, `SRAI`, `SLTI`, `SLTIU`.
   - Added differential tests for shift masking, signed comparisons, unsigned comparisons, and sign extension.

2. Add native branch and jump support. Done.
   - Added native x86 for `BEQ`, `BNE`, `BLT`, `BGE`, `BLTU`, `BGEU`.
   - Added native `JAL`.
   - Kept `JALR` slow-path initially.
   - Added tests for taken branches, skipped fallthrough instructions, loop/max-step behavior, direct successor jumps, and `JAL` link writes.

3. Add native multiply support. Done.
   - Added native x86 for `MUL`, `MULH`, `MULHSU`, `MULHU`.
   - Kept `DIV`, `DIVU`, `REM`, `REMU` slow-path until profiling proves they matter.
   - Added tests for signed/unsigned high-word behavior and wrapping.

4. Add memory support. Done.
   - Added guarded native `LW` and `SW`.
   - Added guarded native `LB`, `LH`, `LBU`, `LHU`, `SB`, `SH`.
   - Preserved exact misalignment behavior by falling back to the Rust slow path outside the aligned fast path.
   - Added tests for dense memory reads/writes, sign extension, zero extension, memory trace parity, misalignment traps, and platform range faults.

5. Split emitters by opcode family. Done.
   - Moved native emission selection out of the monolithic assembly writer loop.
   - Added explicit compute, control-flow, and memory opcode family classification.
   - Kept unsupported executed instructions explicit and visible through slow-path classification coverage.

6. Close remaining native RV32IM gaps. Done.
   - Added native `DIV`, `DIVU`, `REM`, `REMU` with divide-by-zero and signed-overflow semantics.
   - Added native `JALR` with dynamic target dispatch and exact misalignment behavior.
   - Added feature-gated native `LUI` and `AUIPC` when `u16limb_circuit` is enabled.

7. Harden fallback policy.
   - Keep `ECALL` Rust-owned.
   - Keep `INVALID` as an explicit trap.
   - Hard-error at execution time for any unsupported non-`ECALL` instruction.
   - Current code still slow-paths unsupported instructions through Rust.
   - Final AOT perf mode should hard-error for unsupported hot-path instructions instead of silently interpreting them.

8. Improve runtime metadata.
   - Add precomputed per-PC metadata for slow paths.
   - Add a dense PC-to-label dispatch table to replace linear compare dispatch.
   - Track compile/load time separately from execution time in all perf reports.

9. Broaden tracer coverage.
   - Keep `PreflightTracer` as the first-class throughput path.
   - Pure AOT now exceeds the 10x loop-heavy target; traced AOT is still limited by per-instruction Rust trace callbacks.
   - Next performance gap: native or batched `PreflightTracer` emission to close traced AOT toward pure AOT.
   - Add full `FullTracer` byte-for-byte `StepRecord` differential tests across native ALU, branch, multiply, and memory tiers.
   - Keep syscall witnesses Rust-owned through slow-path helpers.

10. Run guest and workload gates.
   - `fibonacci_guest_aot_emulates`
   - `keccak_syscall_guest_aot_emulates`
   - Reth-style cached loop-heavy workload
   - Require pure execution to reach at least 10x interpreter speedup on loop-heavy workloads before calling AOT perf-ready.
