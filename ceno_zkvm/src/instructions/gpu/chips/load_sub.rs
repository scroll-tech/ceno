use ceno_gpu::common::witgen::types::LoadSubColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_read_mem, extract_rs1, extract_state, extract_uint_limbs,
    },
    riscv::memory::load_v2::LoadConfig,
};

/// Extract column map from a constructed LoadConfig for sub-word loads (LH/LHU/LB/LBU).
pub fn extract_load_sub_column_map<E: ExtensionField>(
    config: &LoadConfig<E>,
    num_witin: usize,
) -> LoadSubColumnMap {
    let im = &config.im_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);
    let (mem_prev_ts, mem_lt_diff) = extract_read_mem(&im.mem_read);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let mem_addr = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");
    let mem_read = extract_uint_limbs::<E, 2, _, _>(&config.memory_read, "memory_read");

    // Infer variant from config: LB/LBU have 2 low_bits, LH/LHU have 1.
    let low_bits = &config.memory_addr.low_bits;
    let is_byte = low_bits.len() == 2;

    let addr_bit_1 = if is_byte {
        low_bits[1].id as u32
    } else {
        assert_eq!(low_bits.len(), 1, "LH/LHU should have 1 low_bit");
        low_bits[0].id as u32
    };

    let target_limb = config
        .target_limb
        .expect("sub-word loads must have target_limb")
        .id as u32;

    // LB/LBU: addr_bit_0, target_byte, dummy_byte
    let (addr_bit_0, target_byte, dummy_byte) = if is_byte {
        let bytes = config
            .target_limb_bytes
            .as_ref()
            .expect("LB/LBU must have target_limb_bytes");
        assert_eq!(bytes.len(), 2);
        (
            Some(low_bits[0].id as u32),
            Some(bytes[0].id as u32),
            Some(bytes[1].id as u32),
        )
    } else {
        (None, None, None)
    };

    // Signed loads have signed_extend_config
    let msb = config.signed_extend_config.as_ref().map(|sec| sec.msb().id as u32);

    LoadSubColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        mem_prev_ts,
        mem_lt_diff,
        rs1_limbs,
        imm,
        imm_sign,
        mem_addr,
        mem_read,
        addr_bit_1,
        target_limb,
        addr_bit_0,
        target_byte,
        dummy_byte,
        msb,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::memory::{LbInstruction, LbuInstruction, LhInstruction, LhuInstruction},
        },
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    use crate::instructions::gpu::utils::column_map::test_colmap;
    test_colmap!(test_extract_lh_column_map, LhInstruction<E>, extract_load_sub_column_map);
    test_colmap!(test_extract_lhu_column_map, LhuInstruction<E>, extract_load_sub_column_map);
    test_colmap!(test_extract_lb_column_map, LbInstruction<E>, extract_load_sub_column_map);
    test_colmap!(test_extract_lbu_column_map, LbuInstruction<E>, extract_load_sub_column_map);

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_load_sub_correctness() {
        use crate::e2e::ShardContext;
        use crate::instructions::gpu::utils::test_helpers::assert_witness_colmajor_eq;
        use ceno_emul::{ByteAddr, Change, InsnKind, ReadOp, StepRecord, WordAddr, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        // Test all 4 variants
        let variants: &[(InsnKind, bool, bool, &str)] = &[
            (InsnKind::LH, false, true, "LH"),
            (InsnKind::LHU, false, false, "LHU"),
            (InsnKind::LB, true, true, "LB"),
            (InsnKind::LBU, true, false, "LBU"),
        ];

        for &(insn_kind, is_byte, is_signed, name) in variants {
            eprintln!("Testing {} GPU vs CPU correctness...", name);

            let mut cs = ConstraintSystem::<E>::new(|| format!("test_{}", name.to_lowercase()));
            let mut cb = CircuitBuilder::new(&mut cs);

            // We need to construct the right instruction type
            let config = match insn_kind {
                InsnKind::LH => {
                    LhInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::LHU => {
                    LhuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::LB => {
                    LbInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::LBU => {
                    LbuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                _ => unreachable!(),
            };
            let num_witin = cb.cs.num_witin as usize;
            let num_structural_witin = cb.cs.num_structural_witin as usize;

            let n = 1024;
            let imm_values: [i32; 4] = if is_byte {
                [0, 1, -1, -3]
            } else {
                [0, 2, -2, -6]
            };

            let steps: Vec<StepRecord> = (0..n)
                .map(|i| {
                    let pc = ByteAddr(0x1000 + (i as u32) * 4);
                    let rs1_val = 0x1000u32 + (i as u32) * 16;
                    let imm: i32 = imm_values[i % imm_values.len()];
                    let mem_addr = rs1_val.wrapping_add_signed(imm);
                    let mem_val = (i as u32) * 111 % 500000;

                    // Compute rd_after based on load type
                    let shift = mem_addr & 3;
                    let bit_1 = (shift >> 1) & 1;
                    let bit_0 = shift & 1;
                    let target_limb: u16 = if bit_1 == 0 {
                        (mem_val & 0xFFFF) as u16
                    } else {
                        (mem_val >> 16) as u16
                    };
                    let rd_after = match insn_kind {
                        InsnKind::LH => (target_limb as i16) as i32 as u32,
                        InsnKind::LHU => target_limb as u32,
                        InsnKind::LB => {
                            let byte = if bit_0 == 0 {
                                (target_limb & 0xFF) as u8
                            } else {
                                ((target_limb >> 8) & 0xFF) as u8
                            };
                            (byte as i8) as i32 as u32
                        }
                        InsnKind::LBU => {
                            let byte = if bit_0 == 0 {
                                (target_limb & 0xFF) as u8
                            } else {
                                ((target_limb >> 8) & 0xFF) as u8
                            };
                            byte as u32
                        }
                        _ => unreachable!(),
                    };
                    let rd_before = (i as u32) % 200;
                    let cycle = 4 + (i as u64) * 4;
                    let insn_code = encode_rv32(insn_kind, 2, 0, 4, imm);

                    let mem_read_op = ReadOp {
                        addr: WordAddr::from(ByteAddr(mem_addr & !3)),
                        value: mem_val,
                        previous_cycle: 0,
                    };

                    StepRecord::new_im_instruction(
                        cycle,
                        pc,
                        insn_code,
                        rs1_val,
                        Change::new(rd_before, rd_after),
                        mem_read_op,
                        0,
                    )
                })
                .collect();
            let indices: Vec<usize> = (0..n).collect();

            // CPU path
            let mut shard_ctx = ShardContext::default();
            let (cpu_rmms, _lkm) = match insn_kind {
                InsnKind::LH => crate::instructions::cpu_assign_instances::<E, LhInstruction<E>>(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap(),
                InsnKind::LHU => crate::instructions::cpu_assign_instances::<E, LhuInstruction<E>>(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap(),
                InsnKind::LB => crate::instructions::cpu_assign_instances::<E, LbInstruction<E>>(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap(),
                InsnKind::LBU => crate::instructions::cpu_assign_instances::<E, LbuInstruction<E>>(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap(),
                _ => unreachable!(),
            };
            let cpu_witness = &cpu_rmms[0];

            // GPU path
            let col_map = extract_load_sub_column_map(&config, num_witin);
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
            let load_width: u32 = if is_byte { 8 } else { 16 };
            let is_signed_u32: u32 = if is_signed { 1 } else { 0 };
            let gpu_result = hal
                .witgen
                .witgen_load_sub(
                    &col_map,
                    &gpu_records,
                    &indices_u32,
                    shard_offset,
                    load_width,
                    is_signed_u32,
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
            eprintln!("{} GPU vs CPU: PASS ({} instances)", name, n);
        }
    }
}
