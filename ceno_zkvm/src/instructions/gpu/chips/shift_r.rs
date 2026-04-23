use ceno_gpu::common::witgen::types::ShiftRColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::shift::shift_circuit_v2::ShiftRTypeConfig,
};

/// Extract column map from a constructed ShiftRTypeConfig (R-type: SLL/SRL/SRA).
pub fn extract_shift_r_column_map<E: ExtensionField>(
    config: &ShiftRTypeConfig<E>,
    num_witin: usize,
) -> ShiftRColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rs2_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs2_read, "rs2_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

    // ShiftBase
    let bit_shift_marker: [u32; 8] =
        std::array::from_fn(|i| config.shift_base_config.bit_shift_marker[i].id as u32);
    let limb_shift_marker: [u32; 4] =
        std::array::from_fn(|i| config.shift_base_config.limb_shift_marker[i].id as u32);
    let bit_multiplier_left = config.shift_base_config.bit_multiplier_left.id as u32;
    let bit_multiplier_right = config.shift_base_config.bit_multiplier_right.id as u32;
    let b_sign = config.shift_base_config.b_sign.id as u32;
    let bit_shift_carry: [u32; 4] =
        std::array::from_fn(|i| config.shift_base_config.bit_shift_carry[i].id as u32);

    ShiftRColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_bytes,
        rs2_bytes,
        rd_bytes,
        bit_shift_marker,
        limb_shift_marker,
        bit_multiplier_left,
        bit_multiplier_right,
        b_sign,
        bit_shift_carry,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::shift::SllInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    use crate::instructions::gpu::utils::column_map::test_colmap;
    test_colmap!(
        test_extract_shift_r_column_map,
        SllInstruction<E>,
        extract_shift_r_column_map
    );

    #[test]
    fn test_gpu_witgen_shift_r_correctness() {
        use crate::{
            e2e::ShardContext, instructions::gpu::utils::test_helpers::assert_witness_colmajor_eq,
        };
        use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_shift_r_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SllInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        const EDGE_CASES: &[(u32, u32)] = &[
            (0, 0),
            (1, 0),          // shift by 0
            (1, 31),         // shift to MSB
            (u32::MAX, 0),   // no shift
            (u32::MAX, 16),  // shift half
            (u32::MAX, 31),  // shift max
            (0x80000000, 1), // INT_MIN << 1
            (0xDEADBEEF, 4), // nibble shift
        ];

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let (rs1, rs2) = if i < EDGE_CASES.len() {
                    EDGE_CASES[i]
                } else {
                    ((i as u32).wrapping_mul(0x01010101), (i as u32) % 32)
                };
                let rd_after = rs1 << (rs2 & 0x1F);
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::SLL, 2, 3, 4, 0);
                StepRecord::new_r_instruction(
                    cycle,
                    pc,
                    insn_code,
                    rs1,
                    rs2,
                    Change::new((i as u32) % 200, rd_after),
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, SllInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_shift_r_column_map(&config, num_witin);
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
            .witgen_shift_r(
                &col_map,
                &gpu_records,
                &indices_u32,
                shard_offset,
                0,
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
