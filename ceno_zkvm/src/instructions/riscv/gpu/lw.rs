use ceno_gpu::common::witgen_types::LwColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{extract_rd, extract_read_mem, extract_rs1, extract_state, extract_uint_limbs};

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

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);
    let (mem_prev_ts, mem_lt_diff) = extract_read_mem(&im.mem_read);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    #[cfg(feature = "u16limb_circuit")]
    let imm_sign = Some(config.imm_sign.id as u32);
    #[cfg(not(feature = "u16limb_circuit"))]
    let imm_sign = None;
    let mem_addr_limbs = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");
    let mem_read_limbs = extract_uint_limbs::<E, 2, _, _>(&config.memory_read, "memory_read");

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

    fn flatten_records(
        records: &[std::collections::BTreeMap<ceno_emul::WordAddr, crate::e2e::RAMRecord>],
    ) -> Vec<(ceno_emul::WordAddr, u64, u64, usize)> {
        records
            .iter()
            .flat_map(|table| {
                table
                    .iter()
                    .map(|(addr, record)| (*addr, record.prev_cycle, record.cycle, record.shard_id))
            })
            .collect()
    }

    fn flatten_lk(
        multiplicity: &gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
    ) -> Vec<Vec<(u64, usize)>> {
        multiplicity
            .iter()
            .map(|table| {
                let mut entries = table
                    .iter()
                    .map(|(key, count)| (*key, *count))
                    .collect::<Vec<_>>();
                entries.sort_unstable();
                entries
            })
            .collect()
    }

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
        let (cpu_rmms, cpu_lkm) = crate::instructions::cpu_assign_instances::<E, LwInstruction>(
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
            .witgen_lw(&col_map, &gpu_records, &indices_u32, shard_offset, 0, 0, 0, None, None)
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

        let mut shard_ctx_full_gpu = ShardContext::default();
        let (gpu_rmms, gpu_lkm) =
            crate::instructions::riscv::gpu::witgen_gpu::try_gpu_assign_instances::<
                E,
                LwInstruction,
            >(
                &config,
                &mut shard_ctx_full_gpu,
                num_witin,
                num_structural_witin,
                &steps,
                &indices,
                crate::instructions::riscv::gpu::witgen_gpu::GpuWitgenKind::Lw,
            )
            .unwrap()
            .expect("GPU path should be available");

        assert_eq!(gpu_rmms[0].values(), cpu_rmms[0].values());
        assert_eq!(flatten_lk(&gpu_lkm), flatten_lk(&cpu_lkm));
        assert_eq!(
            shard_ctx_full_gpu.get_addr_accessed(),
            shard_ctx.get_addr_accessed()
        );
        assert_eq!(
            flatten_records(shard_ctx_full_gpu.read_records()),
            flatten_records(shard_ctx.read_records())
        );
        assert_eq!(
            flatten_records(shard_ctx_full_gpu.write_records()),
            flatten_records(shard_ctx.write_records())
        );
    }
}
