use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    gadgets::IsEqualConfig,
    instructions::{
        riscv::{b_insn::BInstructionConfig, constants::UInt, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};

pub struct BeqConfig<E: ExtensionField> {
    b_insn: BInstructionConfig,

    // TODO: Limb decomposition is not necessary. Replace with a single witness.
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,

    equal: IsEqualConfig,
}

pub struct BeqCircuit<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BeqCircuit<E, I> {
    type InstructionConfig = BeqConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;

        let equal = IsEqualConfig::construct_circuit(
            circuit_builder,
            || "rs1==rs2",
            rs2_read.value(),
            rs1_read.value(),
        )?;

        let branch_taken_bit = match I::INST_KIND {
            InsnKind::BEQ => equal.expr(),
            InsnKind::BNE => Expression::ONE - equal.expr(),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            branch_taken_bit,
        )?;

        Ok(BeqConfig {
            b_insn,
            rs1_read,
            rs2_read,
            equal,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .b_insn
            .assign_instance::<E>(instance, lk_multiplicity, step)?;

        let rs1_read = step.rs1().unwrap().value;
        config
            .rs1_read
            .assign_limbs(instance, Value::new_unchecked(rs1_read).as_u16_limbs());

        let rs2_read = step.rs2().unwrap().value;
        config
            .rs2_read
            .assign_limbs(instance, Value::new_unchecked(rs2_read).as_u16_limbs());

        config.equal.assign_instance(
            instance,
            E::BaseField::from(rs2_read as u64),
            E::BaseField::from(rs1_read as u64),
        )?;

        Ok(())
    }
}
