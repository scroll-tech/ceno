use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::common::witgen::types::{GpuKeccakInstance, GpuKeccakWriteOp, KeccakColumnMap};
use ff_ext::ExtensionField;
use std::sync::Arc;

use crate::instructions::riscv::ecall::keccak::EcallKeccakConfig;

use ceno_emul::SyscallWitness;

/// Extract column map from a constructed EcallKeccakConfig.
///
/// VM state columns are listed individually. Keccak math columns use
/// a single base offset since they're allocated contiguously via transmute.
pub fn extract_keccak_column_map<E: ExtensionField>(
    config: &EcallKeccakConfig<E>,
    num_witin: usize,
) -> KeccakColumnMap {
    // StateInOut
    let pc = config.vm_state.pc.id as u32;
    let ts = config.vm_state.ts.id as u32;

    // OpFixedRS<reg_ecall, read> - ecall_id
    let ecall_prev_ts = config.ecall_id.prev_ts.id as u32;
    let ecall_lt_diff = {
        let diffs = &config.ecall_id.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2, "Expected 2 AssertLt diff limbs for ecall_id");
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // MemAddr - state_ptr address limbs
    let addr_limbs = {
        let limbs = config
            .state_ptr
            .1
            .addr
            .wits_in()
            .expect("MemAddr should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 addr limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };

    // OpFixedRS<reg_arg0, write> - state_ptr register write
    let sptr_prev_ts = config.state_ptr.0.prev_ts.id as u32;
    let sptr_prev_val = {
        let limbs = config
            .state_ptr
            .0
            .prev_value
            .as_ref()
            .expect("state_ptr should have prev_value")
            .wits_in()
            .expect("prev_value should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 prev_value limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let sptr_lt_diff = {
        let diffs = &config.state_ptr.0.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2, "Expected 2 AssertLt diff limbs for state_ptr");
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // WriteMEM x50: prev_ts + lt_diff[2] each
    let mut mem_prev_ts = [0u32; 50];
    let mut mem_lt_diff_0 = [0u32; 50];
    let mut mem_lt_diff_1 = [0u32; 50];
    for (i, writer) in config.mem_rw.iter().enumerate() {
        mem_prev_ts[i] = writer.prev_ts.id as u32;
        let diffs = &writer.lt_cfg.0.diff;
        assert_eq!(
            diffs.len(),
            2,
            "Expected 2 AssertLt diff limbs for mem_rw[{}]",
            i
        );
        mem_lt_diff_0[i] = diffs[0].id as u32;
        mem_lt_diff_1[i] = diffs[1].id as u32;
    }

    // Keccak math columns base offset (contiguous block)
    let keccak_base_col = config.layout.layer_exprs.wits.input8[0].id as u32;

    // Verify contiguity of keccak math columns
    #[cfg(debug_assertions)]
    {
        let base = keccak_base_col as usize;
        let expected_size = std::mem::size_of::<crate::precompiles::lookup_keccakf::KeccakWitCols<u8>>();
        // Check that the last keccak column is at base + expected_size - 1
        let last_rc = config.layout.layer_exprs.wits.rc.last().unwrap();
        assert_eq!(
            last_rc.id as usize,
            base + expected_size - 1,
            "Keccak math columns not contiguous: last rc id {} != expected {}",
            last_rc.id,
            base + expected_size - 1
        );
    }

    KeccakColumnMap {
        pc,
        ts,
        ecall_prev_ts,
        ecall_lt_diff,
        addr_limbs,
        sptr_prev_ts,
        sptr_prev_val,
        sptr_lt_diff,
        mem_prev_ts,
        mem_lt_diff_0,
        mem_lt_diff_1,
        keccak_base_col,
        num_cols: num_witin as u32,
    }
}

/// Pack step records + syscall witnesses into flat GPU-transferable instances.
pub fn pack_keccak_instances(
    steps: &[StepRecord],
    step_indices: &[StepIndex],
    syscall_witnesses: &Arc<Vec<SyscallWitness>>,
) -> Vec<GpuKeccakInstance> {
    step_indices
        .iter()
        .map(|&idx| {
            let step = &steps[idx];
            let sw = step
                .syscall(syscall_witnesses)
                .expect("keccak step must have syscall witness");

            // Register op (state_ptr)
            let reg_op = &sw.reg_ops[0];
            let gpu_reg_op = GpuKeccakWriteOp {
                addr: reg_op.addr.0,
                value_before: reg_op.value.before,
                value_after: reg_op.value.after,
                _pad: 0,
                previous_cycle: reg_op.previous_cycle,
            };

            // Memory ops (50 read-writes)
            let mut mem_ops = [GpuKeccakWriteOp::default(); 50];
            for (i, op) in sw.mem_ops.iter().enumerate() {
                mem_ops[i] = GpuKeccakWriteOp {
                    addr: op.addr.0,
                    value_before: op.value.before,
                    value_after: op.value.after,
                    _pad: 0,
                    previous_cycle: op.previous_cycle,
                };
            }

            GpuKeccakInstance {
                pc: step.pc().before.0,
                _pad0: 0,
                cycle: step.cycle(),
                ecall_prev_cycle: step.rs1().unwrap().previous_cycle,
                reg_op: gpu_reg_op,
                mem_ops,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::ecall::keccak::KeccakInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_keccak_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            KeccakInstruction::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();

        let col_map = extract_keccak_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // All column IDs should be within range
        // Note: keccak_base_col and num_cols are metadata, not column indices
        let metadata_indices = [flat.len() - 1, flat.len() - 2]; // num_cols, keccak_base_col
        for (i, &col) in flat.iter().enumerate() {
            if metadata_indices.contains(&i) {
                continue;
            }
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i,
                col,
                col,
                col_map.num_cols
            );
        }
    }

    #[test]
    fn test_gpu_witgen_keccak_correctness() {
        use crate::e2e::ShardContext;

        let mut cs = ConstraintSystem::<E>::new(|| "test_keccak_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            KeccakInstruction::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        // Get test data from emulator
        let (step, _program, syscall_witnesses) = ceno_emul::test_utils::keccak_step();
        let steps = vec![step];
        let step_indices: Vec<usize> = vec![0];

        // --- CPU path (force CPU via thread-local flag) ---
        use crate::instructions::gpu::dispatch::set_force_cpu_path;
        set_force_cpu_path(true);
        let mut shard_ctx = ShardContext::default();
        shard_ctx.syscall_witnesses = std::sync::Arc::new(syscall_witnesses.clone());
        let (cpu_rmms, _cpu_lkm) = KeccakInstruction::<E>::assign_instances(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &step_indices,
        )
        .unwrap();
        set_force_cpu_path(false);
        let cpu_witness = &cpu_rmms[0];
        let cpu_structural = &cpu_rmms[1];

        // --- GPU path (full pipeline via gpu_assign_keccak_instances) ---
        use crate::instructions::gpu::dispatch::gpu_assign_keccak_instances;
        let mut shard_ctx_gpu = ShardContext::default();
        shard_ctx_gpu.syscall_witnesses = std::sync::Arc::new(syscall_witnesses);
        let (gpu_rmms, gpu_lk) = gpu_assign_keccak_instances::<E>(
            &config,
            &mut shard_ctx_gpu,
            num_witin,
            num_structural_witin,
            &steps,
            &step_indices,
        )
        .unwrap()
        .expect("GPU path should not return None");
        let gpu_witness = &gpu_rmms[0];
        let gpu_structural = &gpu_rmms[1];

        // --- Compare witness (raw_witin) ---
        let gpu_data = gpu_witness.values();
        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "witness size mismatch");

        let mut mismatches = 0;
        for (i, (g, c)) in gpu_data.iter().zip(cpu_data.iter()).enumerate() {
            if g != c {
                if mismatches < 20 {
                    let row = i / num_witin;
                    let col = i % num_witin;
                    eprintln!(
                        "Witness mismatch row={}, col={}: GPU={:?}, CPU={:?}",
                        row, col, g, c
                    );
                }
                mismatches += 1;
            }
        }
        eprintln!(
            "Keccak witness: {} mismatches out of {} cells",
            mismatches,
            gpu_data.len()
        );

        // --- Compare structural witness ---
        let gpu_struct_data = gpu_structural.values();
        let cpu_struct_data = cpu_structural.values();
        assert_eq!(
            gpu_struct_data.len(),
            cpu_struct_data.len(),
            "structural witness size mismatch"
        );

        let mut struct_mismatches = 0;
        for (i, (g, c)) in gpu_struct_data.iter().zip(cpu_struct_data.iter()).enumerate() {
            if g != c {
                if struct_mismatches < 20 {
                    let row = i / num_structural_witin;
                    let col = i % num_structural_witin;
                    eprintln!(
                        "Structural mismatch row={}, col={}: GPU={:?}, CPU={:?}",
                        row, col, g, c
                    );
                }
                struct_mismatches += 1;
            }
        }
        eprintln!(
            "Keccak structural: {} mismatches out of {} cells",
            struct_mismatches,
            gpu_struct_data.len()
        );

        // --- Compare LK multiplicity ---
        let mut lk_mismatches = 0;
        for (table_idx, (gpu_map, cpu_map)) in gpu_lk.0.iter().zip(_cpu_lkm.0.iter()).enumerate() {
            for (&k, &gpu_v) in gpu_map.iter() {
                let cpu_v = cpu_map.get(&k).copied().unwrap_or(0);
                if gpu_v != cpu_v {
                    if lk_mismatches < 30 {
                        eprintln!(
                            "LK mismatch table={}, key={:#x}: GPU={}, CPU={}",
                            table_idx, k, gpu_v, cpu_v,
                        );
                    }
                    lk_mismatches += 1;
                }
            }
            for (&k, &cpu_v) in cpu_map.iter() {
                if !gpu_map.contains_key(&k) {
                    if lk_mismatches < 30 {
                        eprintln!(
                            "LK mismatch table={}, key={:#x}: GPU=missing, CPU={}",
                            table_idx, k, cpu_v,
                        );
                    }
                    lk_mismatches += 1;
                }
            }
        }
        eprintln!("Keccak LK: {} mismatches", lk_mismatches);

        assert_eq!(mismatches, 0, "GPU vs CPU witness mismatch");
        assert_eq!(struct_mismatches, 0, "GPU vs CPU structural witness mismatch");
        assert_eq!(lk_mismatches, 0, "GPU vs CPU LK multiplicity mismatch");
    }
}
