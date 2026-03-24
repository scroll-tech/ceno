use ceno_gpu::common::witgen::types::BranchEqColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{extract_rs1, extract_rs2, extract_state_branching, extract_uint_limbs};
use crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig;

/// Extract column map from a constructed BranchConfig (BEQ/BNE variant).
pub fn extract_branch_eq_column_map<E: ExtensionField>(
    config: &BranchConfig<E>,
    num_witin: usize,
) -> BranchEqColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs1, "read_rs1");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs2, "read_rs2");

    let branch_taken = config.eq_branch_taken_bit.as_ref().unwrap().id as u32;
    let diff_inv_marker: [u32; 2] = {
        let markers = config.eq_diff_inv_marker.as_ref().unwrap();
        [markers[0].id as u32, markers[1].id as u32]
    };

    let (pc, next_pc, ts) = extract_state_branching(&config.b_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.b_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.b_insn.rs2);
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
        crate::instructions::gpu::colmap_base::validate_column_map(&flat, col_map.num_cols);
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
        let gpu_result = hal.witgen
            .witgen_branch_eq(&col_map, &gpu_records, &indices_u32, shard_offset, 1, 0, 0, None, None)
            .unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.witness.device_buffer.to_vec().unwrap();
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
