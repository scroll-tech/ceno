use ceno_gpu::common::witgen::types::MulColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::mulh::mulh_circuit_v2::MulhConfig,
};

/// Extract column map from a constructed MulhConfig.
/// mul_kind: 0=MUL, 1=MULH, 2=MULHU, 3=MULHSU
pub fn extract_mul_column_map<E: ExtensionField>(
    config: &MulhConfig<E>,
    num_witin: usize,
) -> MulColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let rd_low: [u32; 2] = [config.rd_low[0].id as u32, config.rd_low[1].id as u32];

    // MULH/MULHU/MULHSU have rd_high + extensions; MUL does not.
    let (rd_high, rs1_ext, rs2_ext) = match config.rd_high.as_ref() {
        Some(h) => (
            Some([h[0].id as u32, h[1].id as u32]),
            Some(config.rs1_ext.expect("MULH variants must have rs1_ext").id as u32),
            Some(config.rs2_ext.expect("MULH variants must have rs2_ext").id as u32),
        ),
        None => (None, None, None),
    };

    MulColumnMap {
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
        rs1_limbs,
        rs2_limbs,
        rd_low,
        rd_high,
        rs1_ext,
        rs2_ext,
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
            riscv::mulh::{MulInstruction, MulhInstruction, MulhsuInstruction, MulhuInstruction},
        },
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    use crate::instructions::gpu::utils::column_map::test_colmap;
    test_colmap!(test_extract_mul_column_map, MulInstruction<E>, extract_mul_column_map);
    test_colmap!(test_extract_mulh_column_map, MulhInstruction<E>, extract_mul_column_map);
    test_colmap!(test_extract_mulhu_column_map, MulhuInstruction<E>, extract_mul_column_map);
    test_colmap!(test_extract_mulhsu_column_map, MulhsuInstruction<E>, extract_mul_column_map);

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_mul_correctness() {
        use crate::e2e::ShardContext;
        use crate::instructions::gpu::utils::test_helpers::assert_witness_colmajor_eq;
        use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let variants: &[(InsnKind, u32, &str)] = &[
            (InsnKind::MUL, 0, "MUL"),
            (InsnKind::MULH, 1, "MULH"),
            (InsnKind::MULHU, 2, "MULHU"),
            (InsnKind::MULHSU, 3, "MULHSU"),
        ];

        for &(insn_kind, mul_kind, name) in variants {
            eprintln!("Testing {} GPU vs CPU correctness...", name);

            let mut cs = ConstraintSystem::<E>::new(|| format!("test_{}", name.to_lowercase()));
            let mut cb = CircuitBuilder::new(&mut cs);

            let config = match insn_kind {
                InsnKind::MUL => {
                    MulInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::MULH => {
                    MulhInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::MULHU => {
                    MulhuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                InsnKind::MULHSU => {
                    MulhsuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default())
                        .unwrap()
                }
                _ => unreachable!(),
            };
            let num_witin = cb.cs.num_witin as usize;
            let num_structural_witin = cb.cs.num_structural_witin as usize;

            const EDGE_CASES: &[(u32, u32)] = &[
                (0, 0),                   // zero * zero
                (0, 12345),               // zero * non-zero
                (12345, 0),               // non-zero * zero
                (1, 1),                   // identity
                (u32::MAX, 1),            // max * 1
                (1, u32::MAX),            // 1 * max
                (u32::MAX, u32::MAX),     // max * max
                (0x80000000, 2),          // INT_MIN * 2 (for MULH)
                (2, 0x80000000),          // 2 * INT_MIN
                (0xFFFFFFFF, 0xFFFFFFFF), // (-1) * (-1) for signed
                (0x80000000, 0xFFFFFFFF), // INT_MIN * (-1)
                (0x7FFFFFFF, 0x7FFFFFFF), // INT_MAX * INT_MAX
            ];

            let n = 1024;
            let steps: Vec<StepRecord> = (0..n)
                .map(|i| {
                    let pc = ByteAddr(0x1000 + (i as u32) * 4);
                    let (rs1_val, rs2_val) = if i < EDGE_CASES.len() {
                        EDGE_CASES[i]
                    } else {
                        (
                            (i as u32).wrapping_mul(12345).wrapping_add(7),
                            (i as u32).wrapping_mul(54321).wrapping_add(13),
                        )
                    };
                    let rd_after = match insn_kind {
                        InsnKind::MUL => rs1_val.wrapping_mul(rs2_val),
                        InsnKind::MULH => {
                            ((rs1_val as i32 as i64).wrapping_mul(rs2_val as i32 as i64) >> 32)
                                as u32
                        }
                        InsnKind::MULHU => {
                            ((rs1_val as u64).wrapping_mul(rs2_val as u64) >> 32) as u32
                        }
                        InsnKind::MULHSU => {
                            ((rs1_val as i32 as i64).wrapping_mul(rs2_val as i64) >> 32) as u32
                        }
                        _ => unreachable!(),
                    };
                    let rd_before = (i as u32) % 200;
                    let cycle = 4 + (i as u64) * 4;
                    let insn_code = encode_rv32(insn_kind, 2, 3, 4, 0);

                    StepRecord::new_r_instruction(
                        cycle,
                        pc,
                        insn_code,
                        rs1_val,
                        rs2_val,
                        Change::new(rd_before, rd_after),
                        0,
                    )
                })
                .collect();
            let indices: Vec<usize> = (0..n).collect();

            // CPU path
            let mut shard_ctx = ShardContext::default();
            let (cpu_rmms, _lkm) = match insn_kind {
                InsnKind::MUL => crate::instructions::cpu_assign_instances::<E, MulInstruction<E>>(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap(),
                InsnKind::MULH => {
                    crate::instructions::cpu_assign_instances::<E, MulhInstruction<E>>(
                        &config,
                        &mut shard_ctx,
                        num_witin,
                        num_structural_witin,
                        &steps,
                        &indices,
                    )
                    .unwrap()
                }
                InsnKind::MULHU => {
                    crate::instructions::cpu_assign_instances::<E, MulhuInstruction<E>>(
                        &config,
                        &mut shard_ctx,
                        num_witin,
                        num_structural_witin,
                        &steps,
                        &indices,
                    )
                    .unwrap()
                }
                InsnKind::MULHSU => {
                    crate::instructions::cpu_assign_instances::<E, MulhsuInstruction<E>>(
                        &config,
                        &mut shard_ctx,
                        num_witin,
                        num_structural_witin,
                        &steps,
                        &indices,
                    )
                    .unwrap()
                }
                _ => unreachable!(),
            };
            let cpu_witness = &cpu_rmms[0];

            // GPU path
            let col_map = extract_mul_column_map(&config, num_witin);
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
                .witgen_mul(
                    &col_map,
                    &gpu_records,
                    &indices_u32,
                    shard_offset,
                    mul_kind,
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
