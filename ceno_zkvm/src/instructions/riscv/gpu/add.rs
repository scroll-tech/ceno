use ceno_gpu::common::witgen_types::AddColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::arith::ArithConfig;

/// Extract column map from a constructed ArithConfig (ADD variant).
///
/// This reads all WitIn.id values from the config tree and packs them
/// into an AddColumnMap suitable for GPU kernel dispatch.
pub fn extract_add_column_map<E: ExtensionField>(
    config: &ArithConfig<E>,
    num_witin: usize,
) -> AddColumnMap {
    // StateInOut
    let pc = config.r_insn.vm_state.pc.id as u32;
    let ts = config.r_insn.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = config.r_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.r_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rs1.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2, "Expected 2 AssertLt diff limbs for RS1");
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // ReadRS2
    let rs2_id = config.r_insn.rs2.id.id as u32;
    let rs2_prev_ts = config.r_insn.rs2.prev_ts.id as u32;
    let rs2_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rs2.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2, "Expected 2 AssertLt diff limbs for RS2");
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // WriteRD
    let rd_id = config.r_insn.rd.id.id as u32;
    let rd_prev_ts = config.r_insn.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let limbs = config
            .r_insn
            .rd
            .prev_value
            .wits_in()
            .expect("WriteRD prev_value should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 prev_value limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rd.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2, "Expected 2 AssertLt diff limbs for RD");
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // Arithmetic: rs1/rs2 u16 limbs
    let rs1_limbs: [u32; 2] = {
        let limbs = config
            .rs1_read
            .wits_in()
            .expect("rs1_read should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 rs1_read limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rs2_limbs: [u32; 2] = {
        let limbs = config
            .rs2_read
            .wits_in()
            .expect("rs2_read should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 rs2_read limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };

    // rd carries
    let rd_carries: [u32; 2] = {
        let carries = config
            .rd_written
            .carries
            .as_ref()
            .expect("rd_written should have carries");
        assert_eq!(carries.len(), 2, "Expected 2 rd_written carries");
        [carries[0].id as u32, carries[1].id as u32]
    };

    AddColumnMap {
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
        rd_carries,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::arith::AddInstruction},
        structs::ProgramParams,
    };
    use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    fn make_test_steps(n: usize) -> Vec<StepRecord> {
        const EDGE_CASES: &[(u32, u32)] = &[
            (0, 0),
            (0, 1),
            (1, 0),
            (u32::MAX, 1),          // overflow
            (u32::MAX, u32::MAX),   // double overflow
            (0x80000000, 0x80000000), // INT_MIN + INT_MIN
            (0x7FFFFFFF, 1),        // INT_MAX + 1
            (0xFFFF0000, 0x0000FFFF), // limb carry
        ];

        let pc_start = 0x1000u32;
        (0..n)
            .map(|i| {
                let (rs1, rs2) = if i < EDGE_CASES.len() {
                    EDGE_CASES[i]
                } else {
                    ((i as u32) % 1000 + 1, (i as u32) % 500 + 3)
                };
                let rd_before = (i as u32) % 200;
                let rd_after = rs1.wrapping_add(rs2);
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(pc_start + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::ADD, 2, 3, 4, 0);
                StepRecord::new_r_instruction(
                    cycle,
                    pc,
                    insn_code,
                    rs1,
                    rs2,
                    Change::new(rd_before, rd_after),
                    0,
                )
            })
            .collect()
    }

    #[test]
    fn test_extract_add_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AddInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_add_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // All column IDs should be unique and within range
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
        // Check uniqueness
        let mut seen = std::collections::HashSet::new();
        for &col in &flat {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_add_correctness() {
        use crate::e2e::ShardContext;
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        // Construct circuit
        let mut cs = ConstraintSystem::<E>::new(|| "test_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AddInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        // Generate test data
        let n = 1024;
        let steps = make_test_steps(n);
        let indices: Vec<usize> = (0..n).collect();

        // CPU path
        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, AddInstruction<E>>(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        // GPU path (AOS with indirect indexing)
        let col_map = extract_add_column_map(&config, num_witin);
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
            .witgen_add(&col_map, &gpu_records, &indices_u32, shard_offset, None)
            .unwrap();

        // D2H copy (GPU output is column-major)
        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();

        // Compare element by element (GPU is column-major, CPU is row-major)
        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "Size mismatch");

        let mut mismatches = 0;
        for row in 0..n {
            for col in 0..num_witin {
                let gpu_val = gpu_data[col * n + row]; // column-major
                let cpu_val = cpu_data[row * num_witin + col]; // row-major
                if gpu_val != cpu_val {
                    if mismatches < 10 {
                        eprintln!(
                            "Mismatch at row={}, col={}: GPU={:?}, CPU={:?}",
                            row, col, gpu_val, cpu_val
                        );
                    }
                    mismatches += 1;
                }
            }
        }
        assert_eq!(mismatches, 0, "Found {} mismatches", mismatches);
    }
}
