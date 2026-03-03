use ceno_emul::StepIndex;
use ceno_gpu::common::witgen_types::{LwColumnMap, LwStepRecordSOA};
use ff_ext::ExtensionField;

use crate::e2e::ShardContext;
#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::memory::load::LoadConfig;
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::memory::load_v2::LoadConfig;
use crate::tables::InsnRecord;
use ceno_emul::{ByteAddr, StepRecord};

/// Extract column map from a constructed LoadConfig (LW variant).
pub fn extract_lw_column_map<E: ExtensionField>(
    config: &LoadConfig<E>,
    num_witin: usize,
) -> LwColumnMap {
    let im = &config.im_insn;

    // StateInOut
    let pc = im.vm_state.pc.id as u32;
    let ts = im.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = im.rs1.id.id as u32;
    let rs1_prev_ts = im.rs1.prev_ts.id as u32;
    let rs1_lt_diff = {
        let d = &im.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // WriteRD
    let rd_id = im.rd.id.id as u32;
    let rd_prev_ts = im.rd.prev_ts.id as u32;
    let rd_prev_val = {
        let l = im.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rd_lt_diff = {
        let d = &im.rd.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // ReadMEM
    let mem_prev_ts = im.mem_read.prev_ts.id as u32;
    let mem_lt_diff = {
        let d = &im.mem_read.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // Load-specific
    let rs1_limbs = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let imm = config.imm.id as u32;
    #[cfg(feature = "u16limb_circuit")]
    let imm_sign = Some(config.imm_sign.id as u32);
    #[cfg(not(feature = "u16limb_circuit"))]
    let imm_sign = None;
    let mem_addr_limbs = {
        let l = config.memory_addr.addr.wits_in().expect("memory_addr WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let mem_read_limbs = {
        let l = config.memory_read.wits_in().expect("memory_read WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    LwColumnMap {
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
        mem_addr_limbs,
        mem_read_limbs,
        num_cols: num_witin as u32,
    }
}

/// Pack step records into SOA format for LW GPU transfer.
pub fn pack_lw_soa<E: ExtensionField>(
    shard_ctx: &ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> LwStepRecordSOA {
    use p3::field::PrimeField32;
    type B = <ff_ext::BabyBearExt4 as ff_ext::ExtensionField>::BaseField;

    let n = step_indices.len();
    let mut soa = LwStepRecordSOA::with_capacity(n);
    let offset = shard_ctx.current_shard_offset_cycle();

    for &idx in step_indices {
        let step = &shard_steps[idx];
        let rs1_op = step.rs1().expect("LW requires rs1");
        let rd_op = step.rd().expect("LW requires rd");
        let mem_op = step.memory_op().expect("LW requires memory_op");

        // Compute imm field value (signed immediate as BabyBear)
        let imm_pair = InsnRecord::<B>::imm_internal(&step.insn());
        let imm_field_val: B = imm_pair.1;

        // Compute unaligned address
        let unaligned_addr =
            ByteAddr::from(rs1_op.value.wrapping_add_signed(imm_pair.0 as i32));

        soa.pc_before.push(step.pc().before.0);
        soa.cycle.push(step.cycle() - offset);
        soa.rs1_reg.push(rs1_op.register_index() as u32);
        soa.rs1_val.push(rs1_op.value);
        soa.rs1_prev_cycle
            .push(aligned_prev_ts(rs1_op.previous_cycle, offset));
        soa.rd_reg.push(rd_op.register_index() as u32);
        soa.rd_val_before.push(rd_op.value.before);
        soa.rd_prev_cycle
            .push(aligned_prev_ts(rd_op.previous_cycle, offset));
        soa.mem_prev_cycle
            .push(aligned_prev_ts(mem_op.previous_cycle, offset));
        soa.mem_val.push(mem_op.value.before);
        soa.imm_field.push(imm_field_val.as_canonical_u32());
        soa.unaligned_addr.push(unaligned_addr.0);

        // imm_sign for v2 variant
        #[cfg(feature = "u16limb_circuit")]
        {
            let imm_sign_extend =
                crate::utils::imm_sign_extend(true, step.insn().imm as i16);
            let is_neg = if imm_sign_extend[1] > 0 { 1u32 } else { 0u32 };
            if soa.imm_sign_field.is_none() {
                soa.imm_sign_field = Some(Vec::with_capacity(n));
            }
            soa.imm_sign_field.as_mut().unwrap().push(is_neg);
        }
    }

    soa
}

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
        instructions::Instruction,
        structs::ProgramParams,
    };
    use ceno_emul::{
        ByteAddr, Change, InsnKind, ReadOp, StepRecord, WordAddr, encode_rv32,
    };
    use ceno_gpu::{Buffer, bb31::CudaHalBB31};
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;
    type LwInstruction = crate::instructions::riscv::LwInstruction<E>;

    fn make_lw_test_steps(n: usize) -> Vec<StepRecord> {
        let pc_start = 0x1000u32;
        (0..n)
            .map(|i| {
                let rs1_val = 0x100u32 + (i as u32) * 4; // base address, 4-byte aligned
                let imm: i32 = 0; // zero offset for simplicity
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                let mem_val = (i as u32) * 111 % 1000000; // some value < P
                let rd_before = (i as u32) % 200;
                let cycle = 4 + (i as u64) * 4;
                let pc = ByteAddr(pc_start + (i as u32) * 4);
                let insn_code = encode_rv32(InsnKind::LW, 2, 0, 4, imm);

                let mem_read_op = ReadOp {
                    addr: WordAddr::from(ByteAddr(mem_addr)),
                    value: mem_val,
                    previous_cycle: 0,
                };

                StepRecord::new_im_instruction(
                    cycle,
                    pc,
                    insn_code,
                    rs1_val,
                    Change::new(rd_before, mem_val),
                    mem_read_op,
                    0, // prev_cycle
                )
            })
            .collect()
    }

    #[test]
    fn test_extract_lw_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_lw");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            LwInstruction::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_lw_column_map(&config, cb.cs.num_witin as usize);
        let (n_entries, flat) = col_map.to_flat();

        // All column IDs should be within range
        for (i, &col) in flat[..n_entries].iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i, col, col, col_map.num_cols
            );
        }
        // Check uniqueness
        let mut seen = std::collections::HashSet::new();
        for &col in &flat[..n_entries] {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }

    #[test]
    fn test_gpu_witgen_lw_correctness() {
        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_lw_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            LwInstruction::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let steps = make_lw_test_steps(n);
        let indices: Vec<usize> = (0..n).collect();

        // CPU path
        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = LwInstruction::assign_instances(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &indices,
        )
        .unwrap();
        let cpu_witness = &cpu_rmms[0];

        // GPU path
        let col_map = extract_lw_column_map(&config, num_witin);
        let shard_ctx_gpu = ShardContext::default();
        let soa = pack_lw_soa::<E>(&shard_ctx_gpu, &steps, &indices);
        let gpu_result = hal.witgen_lw(&col_map, &soa, None).unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();

        let cpu_data = cpu_witness.values();
        assert_eq!(
            gpu_data.len(),
            cpu_data.len(),
            "Size mismatch: GPU {} vs CPU {}",
            gpu_data.len(),
            cpu_data.len()
        );

        // Only compare columns that the GPU fills (the col_map columns)
        let (n_entries, flat) = col_map.to_flat();
        let mut mismatches = 0;
        for row in 0..n {
            for &col in &flat[..n_entries] {
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
        assert_eq!(
            mismatches, 0,
            "Found {} mismatches in GPU-filled columns",
            mismatches
        );
    }
}
