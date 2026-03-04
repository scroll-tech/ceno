use ceno_gpu::common::witgen_types::LwColumnMap;
use ff_ext::ExtensionField;

#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::memory::load::LoadConfig;
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::memory::load_v2::LoadConfig;

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
        let l = config
            .memory_addr
            .addr
            .wits_in()
            .expect("memory_addr WitIns");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        structs::ProgramParams,
    };
    use ceno_emul::{ByteAddr, Change, InsnKind, ReadOp, StepRecord, WordAddr, encode_rv32};
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;
    type LwInstruction = crate::instructions::riscv::LwInstruction<E>;

    fn make_lw_test_steps(n: usize) -> Vec<StepRecord> {
        let pc_start = 0x1000u32;
        // Use varying immediates including negative values to test imm_field encoding
        let imm_values: [i32; 4] = [0, 4, -4, -8];
        (0..n)
            .map(|i| {
                let rs1_val = 0x1000u32 + (i as u32) * 16; // 16-byte aligned base
                let imm: i32 = imm_values[i % imm_values.len()];
                let mem_addr = rs1_val.wrapping_add_signed(imm);
                let mem_val = (i as u32) * 111 % 1000000;
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
                    0,
                )
            })
            .collect()
    }

    #[test]
    fn test_extract_lw_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_lw");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = LwInstruction::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_lw_column_map(&config, cb.cs.num_witin as usize);
        let (n_entries, flat) = col_map.to_flat();

        for (i, &col) in flat[..n_entries].iter().enumerate() {
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
        for &col in &flat[..n_entries] {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_lw_correctness() {
        use crate::e2e::ShardContext;
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_lw_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = LwInstruction::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let steps = make_lw_test_steps(n);
        let indices: Vec<usize> = (0..n).collect();

        // CPU path
        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) = crate::instructions::cpu_assign_instances::<E, LwInstruction>(
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
        let col_map = extract_lw_column_map(&config, num_witin);
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
            .witgen_lw(&col_map, &gpu_records, &indices_u32, shard_offset, None)
            .unwrap();

        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.device_buffer.to_vec().unwrap();

        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "Size mismatch");

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
        assert_eq!(mismatches, 0, "Found {} mismatches", mismatches);
    }
}
