use ceno_gpu::common::witgen::types::ShColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{
    extract_rs1, extract_rs2, extract_state, extract_uint_limbs, extract_write_mem,
};
use crate::instructions::riscv::memory::store_v2::StoreConfig;

/// Extract column map from a constructed StoreConfig (SH variant, N_ZEROS=1).
pub fn extract_sh_column_map<E: ExtensionField>(
    config: &StoreConfig<E, 1>,
    num_witin: usize,
) -> ShColumnMap {
    let sm = &config.s_insn;

    let (pc, ts) = extract_state(&sm.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&sm.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&sm.rs2);
    let (mem_prev_ts, mem_lt_diff) = extract_write_mem(&sm.mem_write);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let prev_mem_val = extract_uint_limbs::<E, 2, _, _>(&config.prev_memory_value, "prev_memory_value");
    let mem_addr = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");

    // SH-specific: 1 low_bit (bit_1 for halfword select)
    assert_eq!(
        config.memory_addr.low_bits.len(),
        1,
        "SH should have 1 low_bit"
    );
    let mem_addr_bit_1 = config.memory_addr.low_bits[0].id as u32;

    ShColumnMap {
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
        mem_addr_bit_1,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::memory::ShInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_sh_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_sh");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            ShInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_sh_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();
        crate::instructions::gpu::colmap_base::validate_column_map(&flat, col_map.num_cols);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_sh_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, WordAddr, WriteOp, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_sh_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            ShInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let imm_values: [i32; 4] = [0, 2, -2, -6];
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let rs1_val = 0x1000u32 + (i as u32) * 16;
                let rs2_val = (i as u32) * 111 % 1000000;
                let imm: i32 = imm_values[i % imm_values.len()];
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                // SH stores the low halfword of rs2 into the selected halfword
                let prev_mem_val = (i as u32) * 77 % 500000;
                let bit_1 = (mem_addr >> 1) & 1;
                let rs2_hw = rs2_val & 0xFFFF;
                let new_mem_val = if bit_1 == 0 {
                    (prev_mem_val & 0xFFFF0000) | rs2_hw
                } else {
                    (prev_mem_val & 0x0000FFFF) | (rs2_hw << 16)
                };
                let cycle = 4 + (i as u64) * 4;
                let insn_code = encode_rv32(InsnKind::SH, 2, 3, 0, imm);

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
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, ShInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_sh_column_map(&config, num_witin);
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
            .witgen_sh(&col_map, &gpu_records, &indices_u32, shard_offset, 0, 0, 0, None, None)
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
