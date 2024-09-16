use std::marker::PhantomData;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{
    constants::{OPType, OpcodeType, RegUInt, FUNCT3_ADD_SUB, FUNCT7_ADD, FUNCT7_SUB, OPCODE_OP},
    r_insn::RInstructionConfig,
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{riscv::config::ExprLtInput, Instruction},
    set_val,
    uint::UIntValue,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

#[derive(Debug)]
pub struct AddSubConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    addend_0: RegUInt<E>,
    addend_1: RegUInt<E>,
    outcome: RegUInt<E>,
}

pub struct AddInstruction<E>(PhantomData<E>);
pub struct SubInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> RIVInstruction<E> for AddInstruction<E> {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0000000);
}

impl<E: ExtensionField> RIVInstruction<E> for SubInstruction<E> {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::Op, 0x000, 0x0100000);
}

fn add_sub_gadget<E: ExtensionField, const IS_ADD: bool>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<AddSubConfig<E>, ZKVMError> {
    // Execution result = addend0 + addend1, with carry.
    let (addend_0, addend_1, outcome) = if IS_ADD {
        // outcome = addend_0 + addend_1
        let addend_0 = RegUInt::new_unchecked(|| "addend_0", circuit_builder)?;
        let addend_1 = RegUInt::new_unchecked(|| "addend_1", circuit_builder)?;
        (
            addend_0.clone(),
            addend_1.clone(),
            addend_0.add(|| "outcome", circuit_builder, &addend_1, true)?,
        )
    } else {
        // outcome + addend_1 = addend_0
        // outcome is the new value to be updated in register so we need to constrain its range
        let outcome = RegUInt::new(|| "outcome", circuit_builder)?;
        let addend_1 = RegUInt::new_unchecked(|| "addend_1", circuit_builder)?;
        (
            addend_1
                .clone()
                .add(|| "addend_0", circuit_builder, &outcome.clone(), true)?,
            addend_1,
            outcome,
        )
    };

    let funct7 = if IS_ADD { FUNCT7_ADD } else { FUNCT7_SUB };

    let r_insn = RInstructionConfig::<E>::construct_circuit(
        circuit_builder,
        (OPCODE_OP, FUNCT3_ADD_SUB, funct7),
        &addend_0,
        &addend_1,
        &outcome,
    )?;

    Ok(AddSubConfig {
        r_insn,
        addend_0,
        addend_1,
        outcome,
    })
}

fn add_sub_assignment<E: ExtensionField, const IS_ADD: bool>(
    config: &AddSubConfig<E>,
    instance: &mut [MaybeUninit<E::BaseField>],
    lk_multiplicity: &mut LkMultiplicity,
    step: &StepRecord,
) -> Result<(), ZKVMError> {
    config
        .r_insn
        .assign_instance(instance, lk_multiplicity, step)?;

    let addend_1 = UIntValue::new_unchecked(step.rs2().unwrap().value);
    config
        .addend_1
        .assign_limbs(instance, addend_1.u16_fields());

    if IS_ADD {
        // addend_0 + addend_1 = outcome
        let addend_0 = UIntValue::new_unchecked(step.rs1().unwrap().value);
        config
            .addend_0
            .assign_limbs(instance, addend_0.u16_fields());
        let (_, outcome_carries) = addend_0.add(&addend_1, lk_multiplicity, true);
        config.outcome.assign_carries(
            instance,
            outcome_carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );
    } else {
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

    Ok(())
}

impl<E: ExtensionField> Instruction<E> for AddInstruction<E> {
    // const NAME: &'static str = "ADD";
    fn name() -> String {
        "ADD".into()
    }
    type InstructionConfig = AddSubConfig<E>;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        add_sub_gadget::<E, true>(circuit_builder)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<_, true>(config, instance, lk_multiplicity, step)
    }
}

impl<E: ExtensionField> Instruction<E> for SubInstruction<E> {
    // const NAME: &'static str = "ADD";
    fn name() -> String {
        "SUB".into()
    }
    type InstructionConfig = AddSubConfig<E>;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        add_sub_gadget::<E, false>(circuit_builder)
    }

    #[allow(clippy::option_map_unit_fn)]
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        add_sub_assignment::<_, false>(config, instance, lk_multiplicity, step)
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
