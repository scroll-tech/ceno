use ceno_emul::InsnKind;

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::{
        riscv::config::{UIntLtConfig, UIntLtInput},
        Instruction,
    },
    utils::{i64_to_base, split_to_u8},
    witness::LkMultiplicity,
};

use super::{b_insn::BInstructionConfig, constants::UInt8, RIVInstruction};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig,
    pub read_rs1: UInt8<E>,
    pub read_rs2: UInt8<E>,
    pub is_lt: UIntLtConfig,
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
        let read_rs1 = UInt8::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt8::new_unchecked(|| "rs2_limbs", circuit_builder)?;
        let is_lt = read_rs1.lt_limb8(circuit_builder, &read_rs2)?;

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            is_lt.is_lt.expr(),
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
        let rs1_limbs = split_to_u8(step.rs1().unwrap().value);
        let rs2_limbs = split_to_u8(step.rs2().unwrap().value);
        config.read_rs1.assign_limbs(instance, {
            rs1_limbs
                .iter()
                .map(|&limb| i64_to_base::<E::BaseField>(limb as i64))
                .collect()
        });
        config.read_rs2.assign_limbs(instance, {
            rs2_limbs
                .iter()
                .map(|&limb| i64_to_base::<E::BaseField>(limb as i64))
                .collect()
        });
        let lt_input = UIntLtInput {
            lhs_limbs: &rs1_limbs,
            rhs_limbs: &rs2_limbs,
        };
        lt_input.assign(instance, &config.is_lt, lk_multiplicity);

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
                3,
                MOCK_PC_BLT,
                MOCK_PROGRAM[8],
                0x20,
                0x21,
                0,
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
