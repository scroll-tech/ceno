use ceno_gpu::common::witgen_types::SltiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig;

/// Extract column map from a constructed SetLessThanImmConfig (SLTI/SLTIU).
pub fn extract_slti_column_map<E: ExtensionField>(
    config: &SetLessThanImmConfig<E>,
    num_witin: usize,
) -> SltiColumnMap {
    // rs1_read: UInt (2 u16 limbs)
    let rs1_limbs: [u32; 2] = {
        let limbs = config
            .rs1_read
            .wits_in()
            .expect("rs1_read should have WitIn limbs");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };

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

    // I-type base: StateInOut + ReadRS1 + WriteRD
    let pc = config.i_insn.vm_state.pc.id as u32;
    let ts = config.i_insn.vm_state.ts.id as u32;

    let rs1_id = config.i_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.i_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rs1.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    let rd_id = config.i_insn.rd.id.id as u32;
    let rd_prev_ts = config.i_insn.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let limbs = config
            .i_insn
            .rd
            .prev_value
            .wits_in()
            .expect("WriteRD prev_value should have WitIn limbs");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rd.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

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

        for (i, &col) in flat.iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i, col, col, col_map.num_cols
            );
        }
        let mut seen = std::collections::HashSet::new();
        for &col in &flat {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
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
                let rd_after = if (rs1 as i32) < (imm as i32) { 1u32 } else { 0u32 };
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
            &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
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
        let gpu_result = hal
            .witgen_slti(&col_map, &gpu_records, &indices_u32, shard_offset, 1, None)
            .unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();
        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "Size mismatch");

        let flat = col_map.to_flat();
        let mut mismatches = 0;
        for row in 0..n {
            for &col in &flat {
                let c = col as usize;
                let gpu_val = gpu_data[row * num_witin + c];
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
