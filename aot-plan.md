# Ceno AOT Follow-Up Plan

## Implemented In This Pass

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
- Added differential unit coverage for native `LW/SW`, dense memory writes, memory `StepRecord` parity, and exact slow-path misalignment traps.
- Added differential unit coverage for byte/halfword load sign extension, zero extension, byte/halfword stores, range access faults, register parity, and memory `StepRecord` parity.
- Split native opcode dispatch into explicit compute, control-flow, and memory families.
- Added coverage that unsupported opcodes such as `DIV`, `JALR`, and `ECALL` remain on the slow path.

## Verified

- `cargo test -p ceno_emul --features aot-x86_64 aot::tests -- --nocapture`
- `cargo check -p ceno_emul --features aot-x86_64`
- `RUST_MIN_STACK=33554432 cargo test -p ceno_zkvm --features aot-x86_64 fibonacci_guest_aot_emulates -- --nocapture`

Note: the Fibonacci AOT e2e overflowed the default Rust test-thread stack without `RUST_MIN_STACK`, then passed with a 32 MiB stack.

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
   - Add full `FullTracer` byte-for-byte `StepRecord` differential tests across native ALU, branch, multiply, and memory tiers.
   - Keep syscall witnesses Rust-owned through slow-path helpers.

10. Run guest and workload gates.
   - `fibonacci_guest_aot_emulates`
   - `keccak_syscall_guest_aot_emulates`
   - Reth-style cached loop-heavy workload
   - Require pure execution to reach at least 10x interpreter speedup on loop-heavy workloads before calling AOT perf-ready.
