use ceno_gpu::common::witgen_types::ShiftIColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmConfig;

/// Extract column map from a constructed ShiftImmConfig (I-type: SLLI/SRLI/SRAI).
pub fn extract_shift_i_column_map<E: ExtensionField>(
    config: &ShiftImmConfig<E>,
    num_witin: usize,
) -> ShiftIColumnMap {
    // StateInOut
    let pc = config.i_insn.vm_state.pc.id as u32;
    let ts = config.i_insn.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = config.i_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.i_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rs1.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // WriteRD
    let rd_id = config.i_insn.rd.id.id as u32;
    let rd_prev_ts = config.i_insn.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let limbs = config
            .i_insn
            .rd
            .prev_value
            .wits_in()
            .expect("rd prev_value WitIns");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rd.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // UInt8 byte limbs
    let rs1_bytes: [u32; 4] = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 4);
        [
            l[0].id as u32,
            l[1].id as u32,
            l[2].id as u32,
            l[3].id as u32,
        ]
    };
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written WitIns");
        assert_eq!(l.len(), 4);
        [
            l[0].id as u32,
            l[1].id as u32,
            l[2].id as u32,
            l[3].id as u32,
        ]
    };

    // Immediate
    let imm = config.imm.id as u32;

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

    ShiftIColumnMap {
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
        imm,
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
        instructions::{Instruction, riscv::shift_imm::SlliInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_shift_i_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_shift_i");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SlliInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_shift_i_column_map(&config, cb.cs.num_witin as usize);
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
    fn test_gpu_witgen_shift_i_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_shift_i_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SlliInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
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
                let (rs1, shamt) = if i < EDGE_CASES.len() {
                    let (r, s) = EDGE_CASES[i];
                    (r, s as i32)
                } else {
                    ((i as u32).wrapping_mul(0x01010101), (i as i32) % 32)
                };
                let rd_after = rs1 << (shamt as u32);
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::SLLI, 2, 0, 4, shamt);
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
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, SlliInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_shift_i_column_map(&config, num_witin);
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
            .witgen_shift_i(&col_map, &gpu_records, &indices_u32, shard_offset, 0, None)
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
