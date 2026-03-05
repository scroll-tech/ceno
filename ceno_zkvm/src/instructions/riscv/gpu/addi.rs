use ceno_gpu::common::witgen_types::AddiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig;

/// Extract column map from a constructed InstructionConfig (ADDI v2).
pub fn extract_addi_column_map<E: ExtensionField>(
    config: &InstructionConfig<E>,
    num_witin: usize,
) -> AddiColumnMap {
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

    // rs1 u16 limbs
    let rs1_limbs: [u32; 2] = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    // imm and imm_sign
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;

    // rd carries (from the add operation: rs1 + sign_extend(imm))
    let rd_carries: [u32; 2] = {
        let carries = config
            .rd_written
            .carries
            .as_ref()
            .expect("rd_written should have carries for ADDI");
        assert_eq!(carries.len(), 2);
        [carries[0].id as u32, carries[1].id as u32]
    };

    AddiColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_limbs,
        imm,
        imm_sign,
        rd_carries,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::arith_imm::AddiInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_addi_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_addi");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AddiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_addi_column_map(&config, cb.cs.num_witin as usize);
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
