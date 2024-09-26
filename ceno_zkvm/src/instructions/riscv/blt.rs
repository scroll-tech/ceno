use ceno_emul::InsnKind;

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, gadgets::IsLtConfig,
    instructions::Instruction, witness::LkMultiplicity, Value,
};

use super::{
    b_insn::BInstructionConfig,
    constants::{UInt, UINT_LIMBS},
    RIVInstruction,
};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,
    pub is_lt: IsLtConfig<UINT_LIMBS>,
}

impl RIVInstruction for BltInstruction {
    const INST_KIND: InsnKind = InsnKind::BLT;
}

impl<E: ExtensionField> Instruction<E> for BltInstruction {
    // const NAME: &'static str = "BLT";
    fn name() -> String {
        "BLT".into()
    }
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;
        // TODO this is for unsigned lt, FIXME to use signed version
        let is_lt = IsLtConfig::construct_circuit(
            circuit_builder,
            || "rs1<rs2",
            read_rs1.value(),
            read_rs2.value(),
            None,
        )?;
        // let is_lt = UIntLtSignedConfig::construct_circuit(
        //     circuit_builder,
        //     || "rs1<rs2",
        //     &read_rs1,
        //     &read_rs2,
        //     None,
        // )?;

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            is_lt.expr(),
        )?;

        Ok(InstructionConfig {
            b_insn,
            read_rs1,
            read_rs2,
            is_lt,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [std::mem::MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        config.read_rs1.assign_limbs(instance, rs1.u16_fields());
        config.read_rs2.assign_limbs(instance, rs2.u16_fields());
        config.is_lt.assign_instance(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().value as u64,
            step.rs2().unwrap().value as u64,
        )?;

        config
            .b_insn
            .assign_instance::<E>(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ceno_emul::StepRecord;
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_BLT, MOCK_PROGRAM},
    };

    #[test]
    fn test_blt_circuit() -> Result<(), ZKVMError> {
        let mut cs = ConstraintSystem::new(|| "riscv");
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
        let config = BltInstruction::construct_circuit(&mut circuit_builder)?;

        let num_wits = circuit_builder.cs.num_witin as usize;
        // generate mock witness
        let (raw_witin, _) = BltInstruction::assign_instances(
            &config,
            num_wits,
            vec![StepRecord::new_b_instruction(
                12,
                MOCK_PC_BLT,
                MOCK_PROGRAM[8],
                0,
                7,
                10,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut circuit_builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
        Ok(())
    }
}
