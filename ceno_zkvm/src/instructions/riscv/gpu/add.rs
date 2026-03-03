use ceno_emul::StepIndex;
use ceno_gpu::common::witgen_types::{AddColumnMap, AddStepRecordSOA};
use ff_ext::ExtensionField;

use crate::{e2e::ShardContext, instructions::riscv::arith::ArithConfig};
use ceno_emul::StepRecord;

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

/// Pack step records into SOA format for GPU transfer.
///
/// Pre-computes shard-adjusted timing values on CPU so the GPU kernel
/// only needs to do witness filling.
pub fn pack_add_soa(
    shard_ctx: &ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> AddStepRecordSOA {
    let n = step_indices.len();
    let mut soa = AddStepRecordSOA::with_capacity(n);

    let offset = shard_ctx.current_shard_offset_cycle();

    for &idx in step_indices {
        let step = &shard_steps[idx];
        let rs1 = step.rs1().expect("ADD requires rs1");
        let rs2 = step.rs2().expect("ADD requires rs2");
        let rd = step.rd().expect("ADD requires rd");

        soa.pc_before.push(step.pc().before.0);
        soa.cycle.push(step.cycle() - offset);
        soa.rs1_reg.push(rs1.register_index() as u32);
        soa.rs1_val.push(rs1.value);
        soa.rs1_prev_cycle
            .push(aligned_prev_ts(rs1.previous_cycle, offset));
        soa.rs2_reg.push(rs2.register_index() as u32);
        soa.rs2_val.push(rs2.value);
        soa.rs2_prev_cycle
            .push(aligned_prev_ts(rs2.previous_cycle, offset));
        soa.rd_reg.push(rd.register_index() as u32);
        soa.rd_val_before.push(rd.value.before);
        soa.rd_prev_cycle
            .push(aligned_prev_ts(rd.previous_cycle, offset));
    }

    soa
}

/// Inline version of ShardContext::aligned_prev_ts for SOA packing.
fn aligned_prev_ts(prev_cycle: u64, shard_offset: u64) -> u64 {
    let mut ts = prev_cycle.saturating_sub(shard_offset);
    if ts < ceno_emul::FullTracer::SUBCYCLES_PER_INSN {
        ts = 0;
    }
    ts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{Instruction, riscv::arith::AddInstruction},
        structs::ProgramParams,
    };
    use ceno_emul::{ByteAddr, Change, InsnKind, encode_rv32};
    use ceno_gpu::{Buffer, bb31::CudaHalBB31};
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    fn make_test_steps(n: usize) -> Vec<StepRecord> {
        // Use small PC values that fit within BabyBear field (P ≈ 2×10^9)
        let pc_start = 0x1000u32;
        (0..n)
            .map(|i| {
                let rs1 = (i as u32) % 1000 + 1;
                let rs2 = (i as u32) % 500 + 3;
                let rd_before = (i as u32) % 200;
                let rd_after = rs1.wrapping_add(rs2);
                let cycle = 4 + (i as u64) * 4; // cycles start at 4 (SUBCYCLES_PER_INSN)
                let pc = ByteAddr(pc_start + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::ADD, 2, 3, 4, 0);
                StepRecord::new_r_instruction(
                    cycle,
                    pc,
                    insn_code,
                    rs1,
                    rs2,
                    Change::new(rd_before, rd_after),
                    0, // prev_cycle
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
    fn test_pack_add_soa() {
        let steps = make_test_steps(4);
        let indices: Vec<usize> = (0..steps.len()).collect();
        let shard_ctx = ShardContext::default();
        let soa = pack_add_soa(&shard_ctx, &steps, &indices);

        assert_eq!(soa.len(), 4);
        // Check first step
        assert_eq!(soa.rs1_val[0], 1); // 0 * 7 + 1
        assert_eq!(soa.rs2_val[0], 3); // 0 * 13 + 3
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_add_correctness() {
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

        // CPU path — use cpu_assign_instances directly to avoid going through
        // the GPU override in assign_instances (which would make this GPU vs GPU).
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
        let cpu_witness = &cpu_rmms[0]; // witness matrix (not structural)

        // GPU path
        let col_map = extract_add_column_map(&config, num_witin);
        let shard_ctx_gpu = ShardContext::default();
        let soa = pack_add_soa(&shard_ctx_gpu, &steps, &indices);
        let gpu_result = hal.witgen_add(&col_map, &soa, None).unwrap();

        // D2H copy
        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();

        // Compare element by element
        let cpu_data = cpu_witness.values();
        assert_eq!(
            gpu_data.len(),
            cpu_data.len(),
            "Size mismatch: GPU {} vs CPU {}",
            gpu_data.len(),
            cpu_data.len()
        );

        let mut mismatches = 0;
        for row in 0..n {
            for col in 0..num_witin {
                let gpu_val = gpu_data[row * num_witin + col];
                let cpu_val = cpu_data[row * num_witin + col];
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
        assert_eq!(
            mismatches,
            0,
            "Found {} mismatches out of {} elements",
            mismatches,
            n * num_witin
        );
    }
}
