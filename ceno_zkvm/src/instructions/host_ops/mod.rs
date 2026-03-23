//! Host-side operations for GPU-CPU hybrid witness generation.
//!
//! Contains lookup/shard side-effect collection abstractions and CPU fallback paths.

mod lk_ops;
mod sink;
mod emit;
mod cpu_fallback;

// Re-export all public types for convenience
pub use lk_ops::*;
pub use sink::*;
pub use emit::*;
pub use cpu_fallback::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{
            Instruction, cpu_assign_instances, cpu_collect_shard_side_effects,
            cpu_collect_side_effects,
            riscv::{
                AddInstruction, JalInstruction, JalrInstruction, LwInstruction, SbInstruction,
                branch::{BeqInstruction, BltInstruction},
                div::{DivInstruction, RemuInstruction},
                logic::AndInstruction,
                mulh::{MulInstruction, MulhInstruction},
                shift::SraInstruction,
                shift_imm::SlliInstruction,
                slt::SltInstruction,
                slti::SltiInstruction,
            },
        },
        structs::ProgramParams,
        witness::LkMultiplicity,
    };
    use ceno_emul::{
        ByteAddr, Change, InsnKind, PC_STEP_SIZE, ReadOp, StepRecord, WordAddr, WriteOp,
        encode_rv32,
    };
    use ff_ext::GoldilocksExt2;
    use gkr_iop::tables::LookupTable;

    type E = GoldilocksExt2;

    fn assert_side_effects_match<I: Instruction<E>>(
        config: &I::InstructionConfig,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
    ) {
        let indices: Vec<usize> = (0..steps.len()).collect();

        let mut assign_ctx = ShardContext::default();
        let (_, expected_lk) = cpu_assign_instances::<E, I>(
            config,
            &mut assign_ctx,
            num_witin,
            num_structural_witin,
            steps,
            &indices,
        )
        .unwrap();

        let mut collect_ctx = ShardContext::default();
        let actual_lk =
            cpu_collect_side_effects::<E, I>(config, &mut collect_ctx, steps, &indices).unwrap();

        assert_eq!(flatten_lk(&expected_lk), flatten_lk(&actual_lk));
        assert_eq!(
            assign_ctx.get_addr_accessed(),
            collect_ctx.get_addr_accessed()
        );
        assert_eq!(
            flatten_records(assign_ctx.read_records()),
            flatten_records(collect_ctx.read_records())
        );
        assert_eq!(
            flatten_records(assign_ctx.write_records()),
            flatten_records(collect_ctx.write_records())
        );
    }

    fn assert_shard_side_effects_match<I: Instruction<E>>(
        config: &I::InstructionConfig,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
    ) {
        let indices: Vec<usize> = (0..steps.len()).collect();

        let mut assign_ctx = ShardContext::default();
        let (_, expected_lk) = cpu_assign_instances::<E, I>(
            config,
            &mut assign_ctx,
            num_witin,
            num_structural_witin,
            steps,
            &indices,
        )
        .unwrap();

        let mut collect_ctx = ShardContext::default();
        let actual_lk =
            cpu_collect_shard_side_effects::<E, I>(config, &mut collect_ctx, steps, &indices)
                .unwrap();

        assert_eq!(
            expected_lk[LookupTable::Instruction as usize],
            actual_lk[LookupTable::Instruction as usize]
        );
        for (table_idx, table) in actual_lk.iter().enumerate() {
            if table_idx != LookupTable::Instruction as usize {
                assert!(
                    table.is_empty(),
                    "unexpected non-fetch shard-only multiplicity in table {table_idx}: {table:?}"
                );
            }
        }
        assert_eq!(
            assign_ctx.get_addr_accessed(),
            collect_ctx.get_addr_accessed()
        );
        assert_eq!(
            flatten_records(assign_ctx.read_records()),
            flatten_records(collect_ctx.read_records())
        );
        assert_eq!(
            flatten_records(assign_ctx.write_records()),
            flatten_records(collect_ctx.write_records())
        );
    }

    fn flatten_records(
        records: &[std::collections::BTreeMap<WordAddr, crate::e2e::RAMRecord>],
    ) -> Vec<(WordAddr, u64, u64, usize)> {
        records
            .iter()
            .flat_map(|table| {
                table
                    .iter()
                    .map(|(addr, record)| (*addr, record.prev_cycle, record.cycle, record.shard_id))
            })
            .collect()
    }

    fn flatten_lk(
        multiplicity: &gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
    ) -> Vec<Vec<(u64, usize)>> {
        multiplicity
            .iter()
            .map(|table| {
                let mut entries = table
                    .iter()
                    .map(|(key, count)| (*key, *count))
                    .collect::<Vec<_>>();
                entries.sort_unstable();
                entries
            })
            .collect()
    }

    #[test]
    fn test_add_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "add_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AddInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs2 = 16 + i;
                let lhs = 10 + i as u32;
                let rhs = 100 + i as u32;
                let insn = encode_rv32(InsnKind::ADD, rs1, rs2, rd, 0);
                StepRecord::new_r_instruction(
                    4 + (i as u64) * 4,
                    ByteAddr(0x1000 + i as u32 * 4),
                    insn,
                    lhs,
                    rhs,
                    Change::new(0, lhs.wrapping_add(rhs)),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<AddInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_and_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "and_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs2 = 16 + i;
                let lhs = 0xdead_0000 | i as u32;
                let rhs = 0x00ff_ff00 | ((i as u32) << 8);
                let insn = encode_rv32(InsnKind::AND, rs1, rs2, rd, 0);
                StepRecord::new_r_instruction(
                    4 + (i as u64) * 4,
                    ByteAddr(0x2000 + i as u32 * 4),
                    insn,
                    lhs,
                    rhs,
                    Change::new(0, lhs & rhs),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<AndInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_add_shard_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "add_shard_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AddInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs2 = 16 + i;
                let lhs = 10 + i as u32;
                let rhs = 100 + i as u32;
                let insn = encode_rv32(InsnKind::ADD, rs1, rs2, rd, 0);
                StepRecord::new_r_instruction(
                    84 + (i as u64) * 4,
                    ByteAddr(0x5000 + i as u32 * 4),
                    insn,
                    lhs,
                    rhs,
                    Change::new(0, lhs.wrapping_add(rhs)),
                    0,
                )
            })
            .collect();

        assert_shard_side_effects_match::<AddInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_and_shard_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "and_shard_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs2 = 16 + i;
                let lhs = 0xdead_0000 | i as u32;
                let rhs = 0x00ff_ff00 | ((i as u32) << 8);
                let insn = encode_rv32(InsnKind::AND, rs1, rs2, rd, 0);
                StepRecord::new_r_instruction(
                    100 + (i as u64) * 4,
                    ByteAddr(0x5100 + i as u32 * 4),
                    insn,
                    lhs,
                    rhs,
                    Change::new(0, lhs & rhs),
                    0,
                )
            })
            .collect();

        assert_shard_side_effects_match::<AndInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_lw_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "lw_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            LwInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs1_val = 0x1000u32 + (i as u32) * 16;
                let imm = (i as i32) * 4 - 4;
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                let mem_val = 0xabc0_0000 | i as u32;
                let insn = encode_rv32(InsnKind::LW, rs1, 0, rd, imm);
                let mem_read = ReadOp {
                    addr: WordAddr::from(ByteAddr(mem_addr)),
                    value: mem_val,
                    previous_cycle: 0,
                };
                StepRecord::new_im_instruction(
                    4 + (i as u64) * 4,
                    ByteAddr(0x3000 + i as u32 * 4),
                    insn,
                    rs1_val,
                    Change::new(0, mem_val),
                    mem_read,
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<LwInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_lw_shard_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "lw_shard_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            LwInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..4)
            .map(|i| {
                let rd = 2 + i;
                let rs1 = 8 + i;
                let rs1_val = 0x1400u32 + (i as u32) * 16;
                let imm = (i as i32) * 4 - 4;
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                let mem_val = 0xabd0_0000 | i as u32;
                let insn = encode_rv32(InsnKind::LW, rs1, 0, rd, imm);
                let mem_read = ReadOp {
                    addr: WordAddr::from(ByteAddr(mem_addr)),
                    value: mem_val,
                    previous_cycle: 0,
                };
                StepRecord::new_im_instruction(
                    116 + (i as u64) * 4,
                    ByteAddr(0x5200 + i as u32 * 4),
                    insn,
                    rs1_val,
                    Change::new(0, mem_val),
                    mem_read,
                    0,
                )
            })
            .collect();

        assert_shard_side_effects_match::<LwInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_beq_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "beq_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            BeqInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [
            (true, 0x1122_3344, 0x1122_3344),
            (false, 0x5566_7788, 0x99aa_bbcc),
        ];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (taken, lhs, rhs))| {
                let pc = ByteAddr(0x4000 + i as u32 * 4);
                let next_pc = if taken {
                    ByteAddr(pc.0 + 8)
                } else {
                    pc + PC_STEP_SIZE
                };
                StepRecord::new_b_instruction(
                    4 + i as u64 * 4,
                    Change::new(pc, next_pc),
                    encode_rv32(InsnKind::BEQ, 8 + i as u32, 16 + i as u32, 0, 8),
                    lhs,
                    rhs,
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<BeqInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_blt_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "blt_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            BltInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(true, (-2i32) as u32, 1u32), (false, 7u32, (-3i32) as u32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (taken, lhs, rhs))| {
                let pc = ByteAddr(0x4100 + i as u32 * 4);
                let next_pc = if taken {
                    ByteAddr(pc.0.wrapping_sub(8))
                } else {
                    pc + PC_STEP_SIZE
                };
                StepRecord::new_b_instruction(
                    12 + i as u64 * 4,
                    Change::new(pc, next_pc),
                    encode_rv32(InsnKind::BLT, 4 + i as u32, 5 + i as u32, 0, -8),
                    lhs,
                    rhs,
                    10,
                )
            })
            .collect();

        assert_side_effects_match::<BltInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_jal_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "jal_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            JalInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let offsets = [8, -8];
        let steps: Vec<_> = offsets
            .into_iter()
            .enumerate()
            .map(|(i, offset)| {
                let pc = ByteAddr(0x4200 + i as u32 * 4);
                StepRecord::new_j_instruction(
                    20 + i as u64 * 4,
                    Change::new(pc, ByteAddr(pc.0.wrapping_add_signed(offset))),
                    encode_rv32(InsnKind::JAL, 0, 0, 3 + i as u32, offset),
                    Change::new(0, (pc + PC_STEP_SIZE).into()),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<JalInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_jalr_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "jalr_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            JalrInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(100u32, 3), (0x4010u32, -5)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (rs1, imm))| {
                let pc = ByteAddr(0x4300 + i as u32 * 4);
                let next_pc = ByteAddr(rs1.wrapping_add_signed(imm) & !1);
                StepRecord::new_i_instruction(
                    28 + i as u64 * 4,
                    Change::new(pc, next_pc),
                    encode_rv32(InsnKind::JALR, 2 + i as u32, 0, 6 + i as u32, imm),
                    rs1,
                    Change::new(0, (pc + PC_STEP_SIZE).into()),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<JalrInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_slt_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "slt_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SltInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [((-1i32) as u32, 0u32), (5u32, (-2i32) as u32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                let insn =
                    encode_rv32(InsnKind::SLT, 9 + i as u32, 10 + i as u32, 11 + i as u32, 0);
                StepRecord::new_r_instruction(
                    36 + i as u64 * 4,
                    ByteAddr(0x4400 + i as u32 * 4),
                    insn,
                    lhs,
                    rhs,
                    Change::new(0, ((lhs as i32) < (rhs as i32)) as u32),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<SltInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_slti_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "slti_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SltiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(0u32, -1), ((-2i32) as u32, 1)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (rs1, imm))| {
                let insn = encode_rv32(InsnKind::SLTI, 12 + i as u32, 0, 13 + i as u32, imm);
                let pc = ByteAddr(0x4500 + i as u32 * 4);
                StepRecord::new_i_instruction(
                    44 + i as u64 * 4,
                    Change::new(pc, pc + PC_STEP_SIZE),
                    insn,
                    rs1,
                    Change::new(0, ((rs1 as i32) < imm) as u32),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<SltiInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_sra_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "sra_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SraInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(0x8765_4321u32, 4u32), (0xf000_0000u32, 31u32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                let shift = rhs & 31;
                let rd = ((lhs as i32) >> shift) as u32;
                StepRecord::new_r_instruction(
                    52 + i as u64 * 4,
                    ByteAddr(0x4600 + i as u32 * 4),
                    encode_rv32(InsnKind::SRA, 6 + i as u32, 7 + i as u32, 8 + i as u32, 0),
                    lhs,
                    rhs,
                    Change::new(0, rd),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<SraInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_slli_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "slli_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SlliInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(0x1234_5678u32, 3), (0x0000_0001u32, 31)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (rs1, imm))| {
                let pc = ByteAddr(0x4700 + i as u32 * 4);
                StepRecord::new_i_instruction(
                    60 + i as u64 * 4,
                    Change::new(pc, pc + PC_STEP_SIZE),
                    encode_rv32(InsnKind::SLLI, 9 + i as u32, 0, 10 + i as u32, imm),
                    rs1,
                    Change::new(0, rs1.wrapping_shl((imm & 31) as u32)),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<SlliInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_sb_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "sb_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SbInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let steps: Vec<_> = (0..2)
            .map(|i| {
                let rs1 = 0x4800u32 + i * 16;
                let rs2 = 0x1234_5600u32 | i;
                let imm = i as i32 - 1;
                let addr = ByteAddr::from(rs1.wrapping_add_signed(imm));
                let prev = 0x4030_2010u32 + i;
                let shift = (addr.shift() * 8) as usize;
                let mut next = prev & !(0xff << shift);
                next |= (rs2 & 0xff) << shift;
                StepRecord::new_s_instruction(
                    68 + i as u64 * 4,
                    ByteAddr(0x4800 + i * 4),
                    encode_rv32(InsnKind::SB, 11 + i, 12 + i, 0, imm),
                    rs1,
                    rs2,
                    WriteOp {
                        addr: addr.waddr(),
                        value: Change::new(prev, next),
                        previous_cycle: 4,
                    },
                    8,
                )
            })
            .collect();

        assert_side_effects_match::<SbInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_mul_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "mul_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            MulInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(2u32, 11u32), (u32::MAX, 17u32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                StepRecord::new_r_instruction(
                    76 + i as u64 * 4,
                    ByteAddr(0x4900 + i as u32 * 4),
                    encode_rv32(
                        InsnKind::MUL,
                        13 + i as u32,
                        14 + i as u32,
                        15 + i as u32,
                        0,
                    ),
                    lhs,
                    rhs,
                    Change::new(0, lhs.wrapping_mul(rhs)),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<MulInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_mulh_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "mulh_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            MulhInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(2i32, -11i32), (i32::MIN, -1i32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                let outcome = ((lhs as i64).wrapping_mul(rhs as i64) >> 32) as u32;
                StepRecord::new_r_instruction(
                    84 + i as u64 * 4,
                    ByteAddr(0x4a00 + i as u32 * 4),
                    encode_rv32(
                        InsnKind::MULH,
                        16 + i as u32,
                        17 + i as u32,
                        18 + i as u32,
                        0,
                    ),
                    lhs as u32,
                    rhs as u32,
                    Change::new(0, outcome),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<MulhInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_div_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "div_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            DivInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(17i32, -3i32), (i32::MIN, -1i32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                let out = if rhs == 0 {
                    -1i32
                } else {
                    lhs.wrapping_div(rhs)
                } as u32;
                StepRecord::new_r_instruction(
                    92 + i as u64 * 4,
                    ByteAddr(0x4b00 + i as u32 * 4),
                    encode_rv32(
                        InsnKind::DIV,
                        19 + i as u32,
                        20 + i as u32,
                        21 + i as u32,
                        0,
                    ),
                    lhs as u32,
                    rhs as u32,
                    Change::new(0, out),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<DivInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_remu_side_effects_match_assign_instance() {
        let mut cs = ConstraintSystem::<E>::new(|| "remu_side_effects");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            RemuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let cases = [(17u32, 3u32), (0x8000_0001u32, 0u32)];
        let steps: Vec<_> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (lhs, rhs))| {
                let out = if rhs == 0 { lhs } else { lhs % rhs };
                StepRecord::new_r_instruction(
                    100 + i as u64 * 4,
                    ByteAddr(0x4c00 + i as u32 * 4),
                    encode_rv32(
                        InsnKind::REMU,
                        22 + i as u32,
                        23 + i as u32,
                        24 + i as u32,
                        0,
                    ),
                    lhs,
                    rhs,
                    Change::new(0, out),
                    0,
                )
            })
            .collect();

        assert_side_effects_match::<RemuInstruction<E>>(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &steps,
        );
    }

    #[test]
    fn test_lk_op_encodings_match_cpu_multiplicity() {
        let ops = [
            LkOp::AssertU16 { value: 7 },
            LkOp::DynamicRange { value: 11, bits: 8 },
            LkOp::AssertU14 { value: 5 },
            LkOp::Fetch { pc: 0x1234 },
            LkOp::DoubleU8 { a: 1, b: 2 },
            LkOp::And { a: 3, b: 4 },
            LkOp::Or { a: 5, b: 6 },
            LkOp::Xor { a: 7, b: 8 },
            LkOp::Ltu { a: 9, b: 10 },
            LkOp::Pow2 { value: 12 },
            LkOp::ShrByte {
                shift: 3,
                carry: 17,
                bits: 2,
            },
        ];

        let mut lk = LkMultiplicity::default();
        for op in ops {
            for (table, key) in op.encode_all() {
                lk.increment(table, key);
            }
        }

        let finalized = lk.into_finalize_result();
        assert_eq!(finalized[LookupTable::Dynamic as usize].len(), 3);
        assert_eq!(finalized[LookupTable::Instruction as usize].len(), 1);
        assert_eq!(finalized[LookupTable::DoubleU8 as usize].len(), 3);
        assert_eq!(finalized[LookupTable::And as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Or as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Xor as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Ltu as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Pow as usize].len(), 1);
    }
}
