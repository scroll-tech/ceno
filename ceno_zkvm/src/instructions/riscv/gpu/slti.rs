use ceno_gpu::common::witgen::types::SltiColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{extract_rd, extract_rs1, extract_state, extract_uint_limbs};
use crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig;

/// Extract column map from a constructed SetLessThanImmConfig (SLTI/SLTIU).
pub fn extract_slti_column_map<E: ExtensionField>(
    config: &SetLessThanImmConfig<E>,
    num_witin: usize,
) -> SltiColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;

    // UIntLimbsLT comparison gadget
    let cmp_lt = config.uint_lt_config.cmp_lt.id as u32;
    let a_msb_f = config.uint_lt_config.a_msb_f.id as u32;
    let b_msb_f = config.uint_lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        config.uint_lt_config.diff_marker[0].id as u32,
        config.uint_lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = config.uint_lt_config.diff_val.id as u32;

    let (pc, ts) = extract_state(&config.i_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.i_insn.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.i_insn.rd);

    SltiColumnMap {
        rs1_limbs,
        imm,
        imm_sign,
        cmp_lt,
        a_msb_f,
        b_msb_f,
        diff_marker,
        diff_val,
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::slti::SltiInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_slti_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SltiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_slti_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();
        crate::instructions::riscv::gpu::colmap_base::validate_column_map(&flat, col_map.num_cols);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_slti_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_slti_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SltiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let rs1 = ((i as i32) * 137 - 500) as u32;
                let imm = ((i as i32) % 2048 - 1024) as i32; // -1024..1023
                let rd_after = if (rs1 as i32) < (imm as i32) {
                    1u32
                } else {
                    0u32
                };
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::SLTI, 2, 0, 4, imm);
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
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, SltiInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_slti_column_map(&config, num_witin);
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
            .witgen_slti(&col_map, &gpu_records, &indices_u32, shard_offset, 1, 0, 0, None, None)
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
