use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    instructions::{
        riscv::{
            b_insn::BInstructionConfig, config::UIntLtSignedConfig, constants::UInt, RIVInstruction,
        },
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::InsnKind;

pub struct BltCircuit<I>(PhantomData<I>);

pub struct InstructionConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,
    pub is_lt: UIntLtSignedConfig,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BltCircuit<I> {
    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    type InstructionConfig = InstructionConfig<E>;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        // TODO: reduce degree.
        let is_lt = UIntLtSignedConfig::construct_circuit(
            circuit_builder,
            || "rs1<rs2",
            &read_rs1,
            &read_rs2,
            None,
        )?;

        let branch_taken_bit = match I::INST_KIND {
            InsnKind::BLT => is_lt.expr(),
            InsnKind::BGE => Expression::ONE - is_lt.expr(),

            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            branch_taken_bit,
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
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        config.read_rs1.assign_limbs(instance, rs1.as_u16_limbs());
        config.read_rs2.assign_limbs(instance, rs2.as_u16_limbs());
        config.is_lt.assign_instance::<E>(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().value as u64,
            step.rs2().unwrap().value as u64,
        )?;

        config
            .b_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
