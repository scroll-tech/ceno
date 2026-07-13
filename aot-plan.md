# Ceno AOT Follow-Up Plan

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
