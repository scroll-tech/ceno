use ceno_gpu::common::witgen_types::ShiftRColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::shift::shift_circuit_v2::ShiftRTypeConfig;

/// Extract column map from a constructed ShiftRTypeConfig (R-type: SLL/SRL/SRA).
pub fn extract_shift_r_column_map<E: ExtensionField>(
    config: &ShiftRTypeConfig<E>,
    num_witin: usize,
) -> ShiftRColumnMap {
    // StateInOut
    let pc = config.r_insn.vm_state.pc.id as u32;
    let ts = config.r_insn.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = config.r_insn.rs1.id.id as u32;
    let rs1_prev_ts = config.r_insn.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rs1.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // ReadRS2
    let rs2_id = config.r_insn.rs2.id.id as u32;
    let rs2_prev_ts = config.r_insn.rs2.prev_ts.id as u32;
    let rs2_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rs2.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // WriteRD
    let rd_id = config.r_insn.rd.id.id as u32;
    let rd_prev_ts = config.r_insn.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let limbs = config.r_insn.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(limbs.len(), 2);
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let diffs = &config.r_insn.rd.lt_cfg.0.diff;
        assert_eq!(diffs.len(), 2);
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // UInt8 byte limbs
    let rs1_bytes: [u32; 4] = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };
    let rs2_bytes: [u32; 4] = {
        let l = config.rs2_read.wits_in().expect("rs2_read WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };

    // ShiftBase
    let bit_shift_marker: [u32; 8] = std::array::from_fn(|i| {
        config.shift_base_config.bit_shift_marker[i].id as u32
    });
    let limb_shift_marker: [u32; 4] = std::array::from_fn(|i| {
        config.shift_base_config.limb_shift_marker[i].id as u32
    });
    let bit_multiplier_left = config.shift_base_config.bit_multiplier_left.id as u32;
    let bit_multiplier_right = config.shift_base_config.bit_multiplier_right.id as u32;
    let b_sign = config.shift_base_config.b_sign.id as u32;
    let bit_shift_carry: [u32; 4] = std::array::from_fn(|i| {
        config.shift_base_config.bit_shift_carry[i].id as u32
    });

    ShiftRColumnMap {
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
        rs1_bytes,
        rs2_bytes,
        rd_bytes,
        bit_shift_marker,
        limb_shift_marker,
        bit_multiplier_left,
        bit_multiplier_right,
        b_sign,
        bit_shift_carry,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::shift::SllInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_shift_r_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_shift_r");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            SllInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_shift_r_column_map(&config, cb.cs.num_witin as usize);
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
