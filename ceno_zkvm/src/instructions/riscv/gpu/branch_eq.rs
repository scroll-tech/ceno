use ceno_gpu::common::witgen_types::BranchEqColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig;

/// Extract column map from a constructed BranchConfig (BEQ/BNE variant).
pub fn extract_branch_eq_column_map<E: ExtensionField>(
    config: &BranchConfig<E>,
    num_witin: usize,
) -> BranchEqColumnMap {
    let rs1_limbs: [u32; 2] = {
        let limbs = config.read_rs1.wits_in().expect("rs1 WitIn");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rs2_limbs: [u32; 2] = {
        let limbs = config.read_rs2.wits_in().expect("rs2 WitIn");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };

    let branch_taken = config.eq_branch_taken_bit.as_ref().unwrap().id as u32;
    let diff_inv_marker: [u32; 2] = {
        let markers = config.eq_diff_inv_marker.as_ref().unwrap();
        [markers[0].id as u32, markers[1].id as u32]
    };

    let pc = config.b_insn.vm_state.pc.id as u32;
    let next_pc = config.b_insn.vm_state.next_pc.unwrap().id as u32;
    let ts = config.b_insn.vm_state.ts.id as u32;

    let rs1_id = config.b_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.b_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let d = &config.b_insn.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    let rs2_id = config.b_insn.rs2.id.id as u32;
    let rs2_prev_ts = config.b_insn.rs2.prev_ts.id as u32;
    let rs2_lt_diff: [u32; 2] = {
        let d = &config.b_insn.rs2.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    let imm = config.b_insn.imm.id as u32;

    BranchEqColumnMap {
        rs1_limbs,
        rs2_limbs,
        branch_taken,
        diff_inv_marker,
        pc,
        next_pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        imm,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::branch::BeqInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_branch_eq_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            BeqInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_branch_eq_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        for (i, &col) in flat.iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i,
                col,
                col,
                col_map.num_cols
            );
        }
        let mut seen = std::collections::HashSet::new();
        for &col in &flat {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_branch_eq_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_beq_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            BeqInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let insn_code = encode_rv32(InsnKind::BEQ, 2, 3, 0, 8);
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let rs1 = ((i as u32) * 137) ^ 0xABCD;
                let rs2 = if i % 3 == 0 {
                    rs1
                } else {
                    ((i as u32) * 89) ^ 0x1234
                };
                let taken = rs1 == rs2;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let pc_after = if taken {
                    ByteAddr(pc.0 + 8)
                } else {
                    pc + PC_STEP_SIZE
                };
                let cycle = 4 + (i as u64) * 4;
                StepRecord::new_b_instruction(
                    cycle,
                    Change::new(pc, pc_after),
                    insn_code,
                    rs1,
                    rs2,
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, BeqInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_branch_eq_column_map(&config, num_witin);
        let shard_ctx_gpu = ShardContext::default();
        let shard_offset = shard_ctx_gpu.current_shard_offset_cycle();
        let steps_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                steps.as_ptr() as *const u8,
                steps.len() * std::mem::size_of::<StepRecord>(),
            )
        };
        let gpu_records = hal.inner.htod_copy_stream(None, steps_bytes).unwrap();
        let indices_u32: Vec<u32> = indices.iter().map(|&i| i as u32).collect();
        let gpu_result = hal
            .witgen_branch_eq(&col_map, &gpu_records, &indices_u32, shard_offset, 1, None)
            .unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();
        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "Size mismatch");

        let mut mismatches = 0;
        for row in 0..n {
            for c in 0..num_witin {
                let gpu_val = gpu_data[c * n + row];
                let cpu_val = cpu_data[row * num_witin + c];
                if gpu_val != cpu_val {
                    if mismatches < 10 {
                        eprintln!(
                            "Mismatch at row={}, col={}: GPU={:?}, CPU={:?}",
                            row, c, gpu_val, cpu_val
                        );
                    }
                    mismatches += 1;
                }
            }
        }
        assert_eq!(mismatches, 0, "Found {} mismatches", mismatches);
    }
}
