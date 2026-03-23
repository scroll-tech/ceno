use ceno_gpu::common::witgen_types::AddColumnMap;
use ff_ext::ExtensionField;

use super::colmap_base::{extract_carries, extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs};
use crate::instructions::riscv::arith::ArithConfig;

/// Extract column map from a constructed ArithConfig (ADD variant).
///
/// This reads all WitIn.id values from the config tree and packs them
/// into an AddColumnMap suitable for GPU kernel dispatch.
pub fn extract_add_column_map<E: ExtensionField>(
    config: &ArithConfig<E>,
    num_witin: usize,
) -> AddColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let rd_carries = extract_carries::<E, 2, _, _>(&config.rd_written, "rd_written");

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

    fn make_test_steps(n: usize) -> Vec<StepRecord> {
        const EDGE_CASES: &[(u32, u32)] = &[
            (0, 0),
            (0, 1),
            (1, 0),
            (u32::MAX, 1),            // overflow
            (u32::MAX, u32::MAX),     // double overflow
            (0x80000000, 0x80000000), // INT_MIN + INT_MIN
            (0x7FFFFFFF, 1),          // INT_MAX + 1
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

        crate::instructions::riscv::gpu::colmap_base::validate_column_map(&flat, col_map.num_cols);
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
        let (cpu_rmms, cpu_lkm) =
            crate::instructions::cpu_assign_instances::<E, AddInstruction<E>>(
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
            .witgen_add(&col_map, &gpu_records, &indices_u32, shard_offset, 0, 0, None, None)
            .unwrap();

        // D2H copy (GPU output is column-major)
        let gpu_data: Vec<<E as ff_ext::ExtensionField>::BaseField> =
            gpu_result.witness.device_buffer.to_vec().unwrap();

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

        let mut shard_ctx_full_gpu = ShardContext::default();
        let (gpu_rmms, gpu_lkm) =
            crate::instructions::riscv::gpu::witgen_gpu::try_gpu_assign_instances::<
                E,
                AddInstruction<E>,
            >(
                &config,
                &mut shard_ctx_full_gpu,
                num_witin,
                num_structural_witin,
                &steps,
                &indices,
                crate::instructions::riscv::gpu::witgen_gpu::GpuWitgenKind::Add,
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
