use ceno_gpu::common::witgen_types::SbColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::memory::store_v2::StoreConfig;

/// Extract column map from a constructed StoreConfig (SB variant, N_ZEROS=0).
pub fn extract_sb_column_map<E: ExtensionField>(
    config: &StoreConfig<E, 0>,
    num_witin: usize,
) -> SbColumnMap {
    let sm = &config.s_insn;

    // StateInOut (not branching)
    let pc = sm.vm_state.pc.id as u32;
    let ts = sm.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = sm.rs1.id.id as u32;
    let rs1_prev_ts = sm.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let d = &sm.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // ReadRS2
    let rs2_id = sm.rs2.id.id as u32;
    let rs2_prev_ts = sm.rs2.prev_ts.id as u32;
    let rs2_lt_diff: [u32; 2] = {
        let d = &sm.rs2.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // WriteMEM
    let mem_prev_ts = sm.mem_write.prev_ts.id as u32;
    let mem_lt_diff: [u32; 2] = {
        let d = &sm.mem_write.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // Store-specific
    let rs1_limbs: [u32; 2] = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rs2_limbs: [u32; 2] = {
        let l = config.rs2_read.wits_in().expect("rs2_read WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let prev_mem_val: [u32; 2] = {
        let l = config
            .prev_memory_value
            .wits_in()
            .expect("prev_memory_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let mem_addr: [u32; 2] = {
        let l = config
            .memory_addr
            .addr
            .wits_in()
            .expect("memory_addr WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    // SB-specific: 2 low_bits (bit_0, bit_1)
    assert_eq!(config.memory_addr.low_bits.len(), 2, "SB should have 2 low_bits");
    let mem_addr_bit_0 = config.memory_addr.low_bits[0].id as u32;
    let mem_addr_bit_1 = config.memory_addr.low_bits[1].id as u32;

    // MemWordUtil fields (SB has N_ZEROS=0 so these exist)
    let mem_word_util = config
        .next_memory_value
        .as_ref()
        .expect("SB must have next_memory_value (MemWordUtil)");
    assert_eq!(mem_word_util.prev_limb_bytes.len(), 2);
    let prev_limb_bytes: [u32; 2] = [
        mem_word_util.prev_limb_bytes[0].id as u32,
        mem_word_util.prev_limb_bytes[1].id as u32,
    ];
    assert_eq!(mem_word_util.rs2_limb_bytes.len(), 1);
    let rs2_limb_byte = mem_word_util.rs2_limb_bytes[0].id as u32;
    let expected_limb = mem_word_util
        .expected_limb
        .as_ref()
        .expect("SB must have expected_limb")
        .id as u32;

    SbColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        mem_prev_ts,
        mem_lt_diff,
        rs1_limbs,
        rs2_limbs,
        imm,
        imm_sign,
        prev_mem_val,
        mem_addr,
        mem_addr_bit_0,
        mem_addr_bit_1,
        prev_limb_bytes,
        rs2_limb_byte,
        expected_limb,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::memory::SbInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_sb_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_sb");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SbInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_sb_column_map(&config, cb.cs.num_witin as usize);
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
    fn test_gpu_witgen_sb_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{
            ByteAddr, Change, InsnKind, StepRecord, WordAddr, WriteOp, encode_rv32,
        };
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_sb_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SbInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let imm_values: [i32; 4] = [0, 1, -1, -3];
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let rs1_val = 0x1000u32 + (i as u32) * 16;
                let rs2_val = (i as u32) * 111 % 1000000;
                let imm: i32 = imm_values[i % imm_values.len()];
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                let prev_mem_val = (i as u32) * 77 % 500000;
                // SB stores the low byte of rs2 into the selected byte
                let bit_0 = mem_addr & 1;
                let bit_1 = (mem_addr >> 1) & 1;
                let rs2_byte = (rs2_val & 0xFF) as u8;
                let byte_idx = (bit_1 * 2 + bit_0) as usize;
                let mut bytes = prev_mem_val.to_le_bytes();
                bytes[byte_idx] = rs2_byte;
                let new_mem_val = u32::from_le_bytes(bytes);
                let cycle = 4 + (i as u64) * 4;
                let insn_code = encode_rv32(InsnKind::SB, 2, 3, 0, imm);

                let mem_write_op = WriteOp {
                    addr: WordAddr::from(ByteAddr(mem_addr & !3)),
                    value: Change::new(prev_mem_val, new_mem_val),
                    previous_cycle: 0,
                };

                StepRecord::new_s_instruction(
                    cycle,
                    pc,
                    insn_code,
                    rs1_val,
                    rs2_val,
                    mem_write_op,
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) =
            crate::instructions::cpu_assign_instances::<E, SbInstruction<E>>(
                &config,
                &mut shard_ctx,
                num_witin,
                num_structural_witin,
                &steps,
                &indices,
            )
            .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_sb_column_map(&config, num_witin);
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
            .witgen_sb(&col_map, &gpu_records, &indices_u32, shard_offset, None)
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
