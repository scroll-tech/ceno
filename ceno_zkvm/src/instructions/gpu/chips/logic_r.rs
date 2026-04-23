use ceno_gpu::common::witgen::types::LogicRColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::logic::logic_circuit::LogicConfig,
};

/// Extract column map from a constructed LogicConfig (R-type: AND/OR/XOR).
pub fn extract_logic_r_column_map<E: ExtensionField>(
    config: &LogicConfig<E>,
    num_witin: usize,
) -> LogicRColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rs2_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs2_read, "rs2_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

    LogicRColumnMap {
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
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::logic::AndInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    use crate::instructions::gpu::utils::column_map::test_colmap;
    test_colmap!(
        test_extract_logic_r_column_map,
        AndInstruction<E>,
        extract_logic_r_column_map
    );

    #[test]
    fn test_gpu_witgen_logic_r_correctness() {
        use crate::{
            e2e::ShardContext,
            instructions::gpu::{
                dispatch,
                utils::test_helpers::{assert_full_gpu_pipeline, assert_witness_colmajor_eq},
            },
        };
        use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_and_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        const EDGE_CASES: &[(u32, u32)] = &[
            (0, 0),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
            (0, u32::MAX),
            (0xAAAAAAAA, 0x55555555), // alternating bits
            (0xFFFF0000, 0x0000FFFF), // no overlap
            (0xDEADBEEF, 0xFFFFFFFF), // identity
            (0x12345678, 0x00000000), // zero
        ];

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let (rs1, rs2) = if i < EDGE_CASES.len() {
                    EDGE_CASES[i]
                } else {
                    (
                        0xDEAD_0000u32 | (i as u32),
                        0x00FF_FF00u32 | ((i as u32) << 8),
                    )
                };
                let rd_after = rs1 & rs2; // AND
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::AND, 2, 3, 4, 0);
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

        // CPU path
        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, cpu_lkm) =
            crate::instructions::cpu_assign_instances::<E, AndInstruction<E>>(
                &config,
                &mut shard_ctx,
                num_witin,
                num_structural_witin,
                &steps,
                &indices,
            )
            .unwrap();
        let cpu_witness = &cpu_rmms[0];

        // GPU path
        let col_map = extract_logic_r_column_map(&config, num_witin);
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
            .witgen_logic_r(
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

        assert_full_gpu_pipeline::<E, AndInstruction<E>>(
            &config,
            &steps,
            dispatch::GpuWitgenKind::LogicR(0),
            &cpu_rmms,
            &cpu_lkm,
            &shard_ctx,
            num_witin,
            num_structural_witin,
        );
    }
}
