use ceno_gpu::common::witgen::types::JalColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{extract_rd, extract_state_branching, extract_uint_limbs};
use crate::instructions::riscv::jump::jal_v2::JalConfig;

/// Extract column map from a constructed JalConfig.
pub fn extract_jal_column_map<E: ExtensionField>(
    config: &JalConfig<E>,
    num_witin: usize,
) -> JalColumnMap {
    let jm = &config.j_insn;

    let (pc, next_pc, ts) = extract_state_branching(&jm.vm_state);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&jm.rd);
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

    JalColumnMap {
        pc,
        next_pc,
        ts,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rd_bytes,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::jump::JalInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_jal_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_jal");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            JalInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_jal_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();
        crate::instructions::riscv::gpu::colmap_base::validate_column_map(&flat, col_map.num_cols);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_jal_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_jal_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            JalInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                // JAL offset must be even; use small positive/negative offsets
                let offset = (((i as i32) % 256) - 128) * 2; // even offsets
                let new_pc = ByteAddr(pc.0.wrapping_add_signed(offset));
                let rd_after: u32 = (pc + PC_STEP_SIZE).into();
                let cycle = 4 + (i as u64) * 4;
                let insn_code = encode_rv32(InsnKind::JAL, 0, 0, 4, offset);
                StepRecord::new_j_instruction(
                    cycle,
                    Change::new(pc, new_pc),
                    insn_code,
                    Change::new((i as u32) % 200, rd_after),
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, JalInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_jal_column_map(&config, num_witin);
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
            .witgen_jal(&col_map, &gpu_records, &indices_u32, shard_offset, 0, 0, None, None)
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
