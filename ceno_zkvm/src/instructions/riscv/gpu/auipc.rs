use ceno_gpu::common::witgen_types::AuipcColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::auipc::AuipcConfig;

/// Extract column map from a constructed AuipcConfig.
pub fn extract_auipc_column_map<E: ExtensionField>(
    config: &AuipcConfig<E>,
    num_witin: usize,
) -> AuipcColumnMap {
    let im = &config.i_insn;

    // StateInOut
    let pc = im.vm_state.pc.id as u32;
    let ts = im.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = im.rs1.id.id as u32;
    let rs1_prev_ts = im.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let d = &im.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // WriteRD
    let rd_id = im.rd.id.id as u32;
    let rd_prev_ts = im.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let l = im.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let d = &im.rd.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // AUIPC-specific
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written UInt8 WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };
    let pc_limbs: [u32; 2] = [
        config.pc_limbs[0].id as u32,
        config.pc_limbs[1].id as u32,
    ];
    let imm_limbs: [u32; 3] = [
        config.imm_limbs[0].id as u32,
        config.imm_limbs[1].id as u32,
        config.imm_limbs[2].id as u32,
    ];

    AuipcColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rd_bytes,
        pc_limbs,
        imm_limbs,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::auipc::AuipcInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_auipc_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_auipc");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AuipcInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_auipc_column_map(&config, cb.cs.num_witin as usize);
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
    fn test_gpu_witgen_auipc_correctness() {
        use crate::e2e::ShardContext;
        use ceno_emul::{ByteAddr, Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
        use ceno_gpu::{Buffer, bb31::CudaHalBB31};

        let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");

        let mut cs = ConstraintSystem::<E>::new(|| "test_auipc_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AuipcInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        let n = 1024;
        let steps: Vec<StepRecord> = (0..n)
            .map(|i| {
                let imm_20bit = (i as i32) % 0x100000; // 0..0xfffff (20-bit)
                let imm = imm_20bit << 12; // AUIPC immediate is upper 20 bits
                let pc = ByteAddr(0x1000 + (i as u32) * 4);
                let rd_after = pc.0.wrapping_add(imm as u32);
                let cycle = 4 + (i as u64) * 4;
                let insn_code = encode_rv32(InsnKind::AUIPC, 0, 0, 4, imm);
                StepRecord::new_i_instruction(
                    cycle,
                    Change::new(pc, pc + PC_STEP_SIZE),
                    insn_code,
                    0,
                    Change::new((i as u32) % 200, rd_after),
                    0,
                )
            })
            .collect();
        let indices: Vec<usize> = (0..n).collect();

        let mut shard_ctx = ShardContext::default();
        let (cpu_rmms, _lkm) =
            crate::instructions::cpu_assign_instances::<E, AuipcInstruction<E>>(
                &config, &mut shard_ctx, num_witin, num_structural_witin, &steps, &indices,
            )
            .unwrap();
        let cpu_witness = &cpu_rmms[0];

        let col_map = extract_auipc_column_map(&config, num_witin);
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
            .witgen_auipc(&col_map, &gpu_records, &indices_u32, shard_offset, None)
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
