use ceno_gpu::common::witgen::types::BranchCmpColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rs1, extract_rs2, extract_state_branching, extract_uint_limbs,
    },
    riscv::branch::branch_circuit_v2::BranchConfig,
};

/// Extract column map from a constructed BranchConfig (BLT/BGE/BLTU/BGEU variant).
pub fn extract_branch_cmp_column_map<E: ExtensionField>(
    config: &BranchConfig<E>,
    num_witin: usize,
) -> BranchCmpColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs1, "read_rs1");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs2, "read_rs2");

    let lt_config = config.uint_lt_config.as_ref().unwrap();
    let cmp_lt = lt_config.cmp_lt.id as u32;
    let a_msb_f = lt_config.a_msb_f.id as u32;
    let b_msb_f = lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        lt_config.diff_marker[0].id as u32,
        lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = lt_config.diff_val.id as u32;

    let (pc, next_pc, ts) = extract_state_branching(&config.b_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.b_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.b_insn.rs2);
    let imm = config.b_insn.imm.id as u32;

    BranchCmpColumnMap {
        rs1_limbs,
        rs2_limbs,
        cmp_lt,
        a_msb_f,
        b_msb_f,
        diff_marker,
        diff_val,
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
        instructions::{Instruction, riscv::branch::BltInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    use crate::instructions::gpu::utils::column_map::test_colmap;
    test_colmap!(
        test_extract_branch_cmp_column_map,
        BltInstruction<E>,
        extract_branch_cmp_column_map
    );

    #[test]
    fn test_gpu_witgen_branch_cmp_correctness() {
        use crate::{
            e2e::ShardContext, instructions::gpu::utils::test_helpers::assert_witness_colmajor_eq,
        };
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_blt_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            BltInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let insn_code = encode_rv32(InsnKind::BLT, 2, 3, 0, -8);
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let rs1 = ((i as i32) * 137 - 500) as u32;
                let rs2 = ((i as i32) * 89 - 300) as u32;
                let taken = (rs1 as i32) < (rs2 as i32);
                let pc = ByteAddr(0x2000 + (i as u32) * 4);
                let pc_after = if taken {
                    ByteAddr(pc.0.wrapping_sub(8))
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
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, BltInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_branch_cmp_column_map(&config, num_witin);
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
            .witgen
            .witgen_branch_cmp(
                &col_map,
                &gpu_records,
                &indices_u32,
                shard_offset,
                1,
                0,
                0,
                None,
                None,
            )
            .unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.witness.device_buffer.to_vec().unwrap();
        assert_witness_colmajor_eq(&gpu_data, cpu_witness.values(), n, num_witin);
    }
}
