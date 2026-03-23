use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::common::witgen_types::{GpuKeccakInstance, GpuKeccakWriteOp, KeccakColumnMap};
use ff_ext::ExtensionField;
use std::sync::Arc;

use crate::{
    instructions::riscv::ecall::keccak::EcallKeccakConfig,
    precompiles::lookup_keccakf::KECCAK_INPUT32_SIZE,
};

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
}
