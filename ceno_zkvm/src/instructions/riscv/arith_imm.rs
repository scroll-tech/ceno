#[cfg(not(feature = "u16limb_circuit"))]
mod arith_imm_circuit;
#[cfg(feature = "u16limb_circuit")]
mod arith_imm_circuit_v2;

#[cfg(feature = "u16limb_circuit")]
pub use crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::AddiInstruction;

#[cfg(not(feature = "u16limb_circuit"))]
pub use crate::instructions::riscv::arith_imm::arith_imm_circuit::AddiInstruction;

use std::marker::PhantomData;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use crate::{
    Value, circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction,
    structs::ProgramParams, tables::InsnRecord, witness::LkMultiplicity,
};

use super::{RIVInstruction, constants::UInt, i_insn::IInstructionConfig};

impl<E> RIVInstruction for AddiInstruction<E> {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::ADDI;
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
    use ff_ext::GoldilocksExt2;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };

    use super::AddiInstruction;

    #[test]
    fn test_opcode_addi() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, 3);
        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                1000,
                Change::new(0, 1003),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_opcode_addi_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, -3);

        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                1000,
                Change::new(0, 997),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
