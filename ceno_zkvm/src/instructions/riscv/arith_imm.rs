#[cfg(not(feature = "u16limb_circuit"))]
mod arith_imm_circuit;
#[cfg(feature = "u16limb_circuit")]
mod arith_imm_circuit_v2;

#[cfg(feature = "u16limb_circuit")]
pub use crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::AddiInstruction;

#[cfg(not(feature = "u16limb_circuit"))]
pub use crate::instructions::riscv::arith_imm::arith_imm_circuit::AddiInstruction;

use super::RIVInstruction;

impl<E> RIVInstruction for AddiInstruction<E> {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::ADDI;
}

#[cfg(test)]
mod test {
    use super::AddiInstruction;
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{Instruction, riscv::constants::UInt},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
    #[cfg(feature = "u16limb_circuit")]
    use ff_ext::BabyBearExt4;
    use ff_ext::{ExtensionField, GoldilocksExt2};
    use gkr_iop::circuit_builder::DebugIndex;

    #[test]
    fn test_opcode_addi() {
        let cases = vec![
            (1000, 1003, 3), // positive immediate
            (1000, 997, -3), // negative immediate
        ];

        for &(rs1, expected, imm) in &cases {
            test_opcode_addi_internal::<GoldilocksExt2>(rs1, expected, imm);
            #[cfg(feature = "u16limb_circuit")]
            test_opcode_addi_internal::<BabyBearExt4>(rs1, expected, imm);
        }
    }

    fn test_opcode_addi_internal<E: ExtensionField>(rs1: u32, rd: u32, imm: i32) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config =
                        AddiInstruction::<E>::construct_circuit(cb, &ProgramParams::default());
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, imm);
        let (raw_witin, lkm) = AddiInstruction::<E>::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &[StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1,
                Change::new(0, rd),
                0,
            )],
        )
        .unwrap();

        // verify rd_written
        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            expected_rd_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
