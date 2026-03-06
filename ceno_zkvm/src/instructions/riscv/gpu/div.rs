use ceno_gpu::common::witgen_types::DivColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::div::div_circuit_v2::DivRemConfig;

/// Extract column map from a constructed DivRemConfig.
/// div_kind: 0=DIV, 1=DIVU, 2=REM, 3=REMU
pub fn extract_div_column_map<E: ExtensionField>(
    config: &DivRemConfig<E>,
    num_witin: usize,
) -> DivColumnMap {
    let r = &config.r_insn;

    // R-type base
    let pc = r.vm_state.pc.id as u32;
    let ts = r.vm_state.ts.id as u32;

    let rs1_id = r.rs1.id.id as u32;
    let rs1_prev_ts = r.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let d = &r.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    let rs2_id = r.rs2.id.id as u32;
    let rs2_prev_ts = r.rs2.prev_ts.id as u32;
    let rs2_lt_diff: [u32; 2] = {
        let d = &r.rs2.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    let rd_id = r.rd.id.id as u32;
    let rd_prev_ts = r.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let l = r.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let d = &r.rd.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // Div-specific: operand limbs
    let dividend: [u32; 2] = {
        let l = config.dividend.wits_in().expect("dividend WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let divisor: [u32; 2] = {
        let l = config.divisor.wits_in().expect("divisor WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let quotient: [u32; 2] = {
        let l = config.quotient.wits_in().expect("quotient WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let remainder: [u32; 2] = {
        let l = config.remainder.wits_in().expect("remainder WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    // Sign/control bits
    let dividend_sign = config.dividend_sign.id as u32;
    let divisor_sign = config.divisor_sign.id as u32;
    let quotient_sign = config.quotient_sign.id as u32;
    let remainder_zero = config.remainder_zero.id as u32;
    let divisor_zero = config.divisor_zero.id as u32;

    // Inverse witnesses
    let divisor_sum_inv = config.divisor_sum_inv.id as u32;
    let remainder_sum_inv = config.remainder_sum_inv.id as u32;
    let remainder_inv: [u32; 2] = [
        config.remainder_inv[0].id as u32,
        config.remainder_inv[1].id as u32,
    ];

    // sign_xor
    let sign_xor = config.sign_xor.id as u32;

    // remainder_prime
    let remainder_prime: [u32; 2] = {
        let l = config.remainder_prime.wits_in().expect("remainder_prime WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    // lt_marker
    let lt_marker: [u32; 2] = [
        config.lt_marker[0].id as u32,
        config.lt_marker[1].id as u32,
    ];

    // lt_diff
    let lt_diff = config.lt_diff.id as u32;

    DivColumnMap {
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
        dividend,
        divisor,
        quotient,
        remainder,
        dividend_sign,
        divisor_sign,
        quotient_sign,
        remainder_zero,
        divisor_zero,
        divisor_sum_inv,
        remainder_sum_inv,
        remainder_inv,
        sign_xor,
        remainder_prime,
        lt_marker,
        lt_diff,
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
            riscv::div::{DivInstruction, DivuInstruction, RemInstruction, RemuInstruction},
        },
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    fn test_column_map_validity(col_map: &DivColumnMap) {
        let (n_entries, flat) = col_map.to_flat();
        for (i, &col) in flat[..n_entries].iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i, col, col, col_map.num_cols
            );
        }
        let mut seen = std::collections::HashSet::new();
        for &col in &flat[..n_entries] {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }

    #[test]
    fn test_extract_div_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_div");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            DivInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let col_map = extract_div_column_map(&config, cb.cs.num_witin as usize);
        test_column_map_validity(&col_map);
    }

    #[test]
    fn test_extract_divu_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_divu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            DivuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let col_map = extract_div_column_map(&config, cb.cs.num_witin as usize);
        test_column_map_validity(&col_map);
    }

    #[test]
    fn test_extract_rem_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_rem");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            RemInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let col_map = extract_div_column_map(&config, cb.cs.num_witin as usize);
        test_column_map_validity(&col_map);
    }

    #[test]
    fn test_extract_remu_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_remu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            RemuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let col_map = extract_div_column_map(&config, cb.cs.num_witin as usize);
        test_column_map_validity(&col_map);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_div_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let variants: &[(InsnKind, u32, &str)] = &[
            (InsnKind::DIV, 0, "DIV"),
            (InsnKind::DIVU, 1, "DIVU"),
            (InsnKind::REM, 2, "REM"),
            (InsnKind::REMU, 3, "REMU"),
        ];

        for &(insn_kind, div_kind, name) in variants {
            eprintln!("Testing {} GPU vs CPU correctness...", name);

            let mut cs = ConstraintSystem::<E>::new(|| format!("test_{}", name.to_lowercase()));
            let mut cb = CircuitBuilder::new(&mut cs);

            let config = match insn_kind {
                InsnKind::DIV => DivInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap(),
                InsnKind::DIVU => DivuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap(),
                InsnKind::REM => RemInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap(),
                InsnKind::REMU => RemuInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap(),
                _ => unreachable!(),
            };
            let num_witin = cb.cs.num_witin as usize;
            let num_structural_witin = cb.cs.num_structural_witin as usize;

            let n = 1024;

            const EDGE_CASES: &[(u32, u32)] = &[
                (0, 1),                    // 0 / 1
                (1, 1),                    // 1 / 1
                (0, 0),                    // 0 / 0 (zero divisor)
                (12345, 0),                // non-zero / 0 (zero divisor)
                (u32::MAX, 0),             // max / 0 (zero divisor)
                (0x80000000, 0),           // INT_MIN / 0 (zero divisor)
                (0x80000000, 0xFFFFFFFF),  // INT_MIN / -1 (signed overflow!)
                (0x7FFFFFFF, 0xFFFFFFFF),  // INT_MAX / -1
                (0xFFFFFFFF, 0xFFFFFFFF),  // -1 / -1
                (0x80000000, 1),           // INT_MIN / 1
                (0x80000000, 2),           // INT_MIN / 2
                (u32::MAX, u32::MAX),      // max / max
                (u32::MAX, 1),             // max / 1
                (1, u32::MAX),             // 1 / max
            ];

            let steps: Vec<StepRecord> = (0..n)
                .map(|i| {
                    let pc = ByteAddr(0x1000 + (i as u32) * 4);
                    // Use edge cases first, then varied values with zero divisor
                    let (rs1_val, rs2_val) = if i < EDGE_CASES.len() {
                        EDGE_CASES[i]
                    } else {
                        let rs1 = (i as u32).wrapping_mul(12345).wrapping_add(7);
                        let rs2 = if i % 50 == 0 {
                            0 // test zero divisor
                        } else {
                            (i as u32).wrapping_mul(54321).wrapping_add(13)
                        };
                        (rs1, rs2)
                    };
                    let rd_after = match insn_kind {
                        InsnKind::DIV => {
                            if rs2_val == 0 {
                                u32::MAX // -1 as u32
                            } else {
                                (rs1_val as i32).wrapping_div(rs2_val as i32) as u32
                            }
                        }
                        InsnKind::DIVU => {
                            if rs2_val == 0 {
                                u32::MAX
                            } else {
                                rs1_val / rs2_val
                            }
                        }
                        InsnKind::REM => {
                            if rs2_val == 0 {
                                rs1_val
                            } else {
                                (rs1_val as i32).wrapping_rem(rs2_val as i32) as u32
                            }
                        }
                        InsnKind::REMU => {
                            if rs2_val == 0 {
                                rs1_val
                            } else {
                                rs1_val % rs2_val
                            }
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
                InsnKind::DIV => crate::instructions::cpu_assign_instances::<E, DivInstruction<E>>(
                    &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
                ).unwrap(),
                InsnKind::DIVU => crate::instructions::cpu_assign_instances::<E, DivuInstruction<E>>(
                    &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
                ).unwrap(),
                InsnKind::REM => crate::instructions::cpu_assign_instances::<E, RemInstruction<E>>(
                    &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
                ).unwrap(),
                InsnKind::REMU => crate::instructions::cpu_assign_instances::<E, RemuInstruction<E>>(
                    &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
                ).unwrap(),
                _ => unreachable!(),
            };
            let cpu_witness = &cpu_rmms[0];

            // GPU path
            let col_map = extract_div_column_map(&config, num_witin);
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
                .witgen_div(&col_map, &gpu_records, &indices_u32, shard_offset, div_kind, None)
                .unwrap();

            let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
                gpu_result.device_buffer.to_vec().unwrap();
            let cpu_data = cpu_witness.values();
            assert_eq!(gpu_data.len(), cpu_data.len(), "{}: Size mismatch", name);

            let mut mismatches = 0;
            for row in 0..n {
                for c in 0..num_witin {
                    let gpu_val = gpu_data[c * n + row];
                    let cpu_val = cpu_data[row * num_witin + c];
                    if gpu_val != cpu_val {
                        if mismatches < 10 {
                            eprintln!(
                                "{}: Mismatch at row={}, col={}: GPU={:?}, CPU={:?}",
                                name, row, c, gpu_val, cpu_val
                            );
                        }
                        mismatches += 1;
                    }
                }
            }
            assert_eq!(mismatches, 0, "{}: Found {} mismatches", name, mismatches);
            eprintln!("{} GPU vs CPU: PASS ({} instances)", name, n);
        }
    }
}
