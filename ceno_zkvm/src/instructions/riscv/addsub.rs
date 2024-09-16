use std::{marker::PhantomData, ops::Deref};

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    constants::RegUInt,
    gadgets::{RTypeGadget, RTypeInstructionConfig},
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction, uint::UIntValue,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

pub struct AddInstruction<E>(PhantomData<E>);
pub struct SubInstruction<E>(PhantomData<E>);

#[derive(Debug)]
pub struct InstructionConfig<E: ExtensionField>(RTypeInstructionConfig<E>);

impl<E: ExtensionField> Deref for InstructionConfig<E> {
    type Target = RTypeInstructionConfig<E>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E: ExtensionField> RIVInstruction<E> for AddInstruction<E> {
    const INST_KIND: InsnKind = InsnKind::ADD;
}

impl<E: ExtensionField> RIVInstruction<E> for SubInstruction<E> {
    const INST_KIND: InsnKind = InsnKind::SUB;
}

fn add_sub_gadget<IC: RIVInstruction<E>, E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    Ok(InstructionConfig(RTypeGadget::construct_circuit::<IC>(
        circuit_builder,
        |cb| {
            Ok(match IC::INST_KIND {
                InsnKind::ADD => {
                    // outcome = addend_0 + addend_1
                    let addend_0 = RegUInt::new_unchecked(|| "addend_0", cb)?;
                    let addend_1 = RegUInt::new_unchecked(|| "addend_1", cb)?;
                    (
                        addend_0.clone(),
                        addend_1.clone(),
                        addend_0.add(|| "outcome", cb, &addend_1, true)?,
                    )
                }
                InsnKind::SUB => {
                    // outcome + addend_1 = addend_0
                    // outcome is the new value to be updated in register so we need to constrain its range
                    let outcome = RegUInt::new(|| "outcome", cb)?;
                    let addend_1 = RegUInt::new_unchecked(|| "addend_1", cb)?;
                    (
                        addend_1
                            .clone()
                            .add(|| "addend_0", cb, &outcome.clone(), true)?,
                        addend_1,
                        outcome,
                    )
                }
                _ => unreachable!(),
            })
        },
    )?))
}

fn add_sub_assignment<IC: RIVInstruction<E>, E: ExtensionField>(
    config: &RTypeInstructionConfig<E>,
    instance: &mut [MaybeUninit<E::BaseField>],
    lk_multiplicity: &mut LkMultiplicity,
    step: &StepRecord,
) -> Result<(), ZKVMError> {
    RTypeGadget::assign(
        config,
        instance,
        lk_multiplicity,
        step,
        |config, instance, lk_multiplicity, step, addend_1| {
            match IC::INST_KIND {
                InsnKind::ADD => {
                    // addend_0 + addend_1 = outcome
                    let addend_0 = UIntValue::new_unchecked(step.rs1().unwrap().value);
                    config
                        .addend_0
                        .assign_limbs(instance, addend_0.u16_fields());
                    let (_, outcome_carries) = addend_0.add(addend_1, lk_multiplicity, true);
                    config.outcome.assign_carries(
                        instance,
                        outcome_carries
                            .into_iter()
                            .map(|carry| E::BaseField::from(carry as u64))
                            .collect_vec(),
                    );
                }
                InsnKind::SUB => {
                    // addend_0 = outcome + addend_1
                    let outcome = UIntValue::new(step.rd().unwrap().value.after, lk_multiplicity);
                    config.outcome.assign_limbs(instance, outcome.u16_fields());
                    let (_, addend_0_carries) = addend_1.add(&outcome, lk_multiplicity, true);
                    config.addend_0.assign_carries(
                        instance,
                        addend_0_carries
                            .into_iter()
                            .map(|carry| E::BaseField::from(carry as u64))
                            .collect_vec(),
                    );
                }
                _ => unreachable!(),
            };
            Ok(())
        },
    )
}

impl<E: ExtensionField> Instruction<E> for AddInstruction<E> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<Self, _>(circuit_builder)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<Self, _>(config, instance, lk_multiplicity, step)
    }
}

impl<E: ExtensionField> Instruction<E> for SubInstruction<E> {
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<Self, _>(circuit_builder)
    }

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<Self, _>(config, instance, lk_multiplicity, step)
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_ADD, MOCK_PC_SUB, MOCK_PROGRAM},
    };

    use super::{AddInstruction, SubInstruction};

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_add() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                11,
                0xfffffffe,
                Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_add_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                u32::MAX - 1,
                u32::MAX - 1,
                Change::new(0, (u32::MAX - 1).wrapping_add(u32::MAX - 1)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                11,
                2,
                Change::new(0, 11_u32.wrapping_sub(2)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    #[allow(clippy::option_map_unit_fn)]
    fn test_opcode_sub_underflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                3,
                11,
                Change::new(0, 3_u32.wrapping_sub(11)),
            )],
        )
        .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }
}
