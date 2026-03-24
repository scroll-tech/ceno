use ceno_gpu::common::witgen::types::LogicIColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::gpu::utils::colmap_base::{extract_rd, extract_rs1, extract_state, extract_uint_limbs};
use crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig;

/// Extract column map from a constructed LogicConfig (I-type v2: ANDI/ORI/XORI).
pub fn extract_logic_i_column_map<E: ExtensionField>(
    config: &LogicConfig<E>,
    num_witin: usize,
) -> LogicIColumnMap {
    let im = &config.i_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");
    let imm_lo_bytes = extract_uint_limbs::<E, 2, _, _>(&config.imm_lo, "imm_lo");
    let imm_hi_bytes = extract_uint_limbs::<E, 2, _, _>(&config.imm_hi, "imm_hi");

    LogicIColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_bytes,
        rd_bytes,
        imm_lo_bytes,
        imm_hi_bytes,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::logic_imm::AndiInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_logic_i_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_logic_i");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_logic_i_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();
        crate::instructions::gpu::utils::colmap_base::validate_column_map(&flat, col_map.num_cols);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_logic_i_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32u};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_logic_i_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        const EDGE_CASES: &[(u32, u32)] = &[
            (0, 0),
            (u32::MAX, 0xFFF), // all bits AND max imm
            (u32::MAX, 0),
            (0, 0xFFF),
            (0xAAAAAAAA, 0x555), // alternating
            (0xFFFF0000, 0xFFF),
            (0x12345678, 0x000),
            (0xDEADBEEF, 0xABC),
        ];

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let (rs1, imm) = if i < EDGE_CASES.len() {
                    EDGE_CASES[i]
                } else {
                    (
                        (i as u32).wrapping_mul(0x01010101) ^ 0xabed_5eff,
                        (i as u32) % 4096,
                    )
                };
                let rd_after = rs1 & imm; // ANDI
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let insn_code = encode_rv32u(InsnKind::ANDI, 2, 0, 4, imm);
                StepRecord::new_i_instruction(
                    cycle,
                    Change::new(pc, pc + PC_STEP_SIZE),
                    insn_code,
                    rs1,
                    Change::new((i as u32) % 200, rd_after),
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, AndiInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_logic_i_column_map(&config, num_witin);
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
            .witgen_logic_i(&col_map, &gpu_records, &indices_u32, shard_offset, 0, 0, 0, None, None)
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
