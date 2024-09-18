use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{constants::UInt, r_insn::RInstructionConfig, RIVInstruction};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction, uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    multiplier_1: UInt<E>,
    multiplier_2: UInt<E>,
    outcome: UInt<E>,
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct MulOp;
impl RIVInstruction for MulOp {
    const INST_KIND: InsnKind = InsnKind::MUL;
}
pub type MulInstruction<E> = ArithInstruction<E, MulOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = ArithConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let mut multiplier_1 = UInt::new_unchecked(|| "multiplier_1", circuit_builder)?;
        let mut multiplier_2 = UInt::new_unchecked(|| "multiplier_2", circuit_builder)?;
        let outcome = multiplier_1.mul(|| "outcome", circuit_builder, &mut multiplier_2, true)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &multiplier_1,
            &multiplier_2,
            &outcome,
        )?;

        Ok(ArithConfig {
            r_insn,
            multiplier_1,
            multiplier_2,
            outcome,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.r_insn.assign_instance(instance, lkm, step)?;

        let multiplier_1 = Value::new_unchecked(step.rs1().unwrap().value);
        let multiplier_2 = Value::new_unchecked(step.rs2().unwrap().value);
        let outcome = Value::new_unchecked(step.rd().unwrap().value.after);

        config
            .multiplier_1
            .assign_limbs(instance, multiplier_1.u16_fields());
        config
            .multiplier_2
            .assign_limbs(instance, multiplier_2.u16_fields());
        let (_, carries) = multiplier_1.mul(&multiplier_2, lkm, true);

        config.outcome.assign_limbs(instance, outcome.u16_fields());
        config.outcome.assign_carries(
            instance,
            carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );

        Ok(())
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
        scheme::mock_prover::{MockProver, MOCK_PC_MUL, MOCK_PROGRAM},
    };

    use super::MulInstruction;

    #[test]
    fn test_opcode_mul() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                11,
                2,
                Change::new(0, 22),
                0,
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
    fn test_opcode_mul_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                u32::MAX / 2 + 1,
                2,
                Change::new(0, 0),
                0,
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
    fn test_opcode_mul_overflow2() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                4294901760,
                4294901760,
                Change::new(0, 0),
                0,
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
