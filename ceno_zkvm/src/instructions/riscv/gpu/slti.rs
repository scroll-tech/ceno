use ceno_gpu::common::witgen_types::SltiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig;

/// Extract column map from a constructed SetLessThanImmConfig (SLTI/SLTIU).
pub fn extract_slti_column_map<E: ExtensionField>(
    config: &SetLessThanImmConfig<E>,
    num_witin: usize,
) -> SltiColumnMap {
    // rs1_read: UInt (2 u16 limbs)
    let rs1_limbs: [u32; 2] = {
        let limbs = config
            .rs1_read
            .wits_in()
            .expect("rs1_read should have WitIn limbs");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };

    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;

    // UIntLimbsLT comparison gadget
    let cmp_lt = config.uint_lt_config.cmp_lt.id as u32;
    let a_msb_f = config.uint_lt_config.a_msb_f.id as u32;
    let b_msb_f = config.uint_lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        config.uint_lt_config.diff_marker[0].id as u32,
        config.uint_lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = config.uint_lt_config.diff_val.id as u32;

    // I-type base: StateInOut + ReadRS1 + WriteRD
    let pc = config.i_insn.vm_state.pc.id as u32;
    let ts = config.i_insn.vm_state.ts.id as u32;

    let rs1_id = config.i_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.i_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rs1.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    let rd_id = config.i_insn.rd.id.id as u32;
    let rd_prev_ts = config.i_insn.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let limbs = config
            .i_insn
            .rd
            .prev_value
            .wits_in()
            .expect("WriteRD prev_value should have WitIn limbs");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let diffs = &config.i_insn.rd.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    SltiColumnMap {
        rs1_limbs,
        imm,
        imm_sign,
        cmp_lt,
        a_msb_f,
        b_msb_f,
        diff_marker,
        diff_val,
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::slti::SltiInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_slti_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SltiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_slti_column_map(&config, cb.cs.num_witin as usize);
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
}
