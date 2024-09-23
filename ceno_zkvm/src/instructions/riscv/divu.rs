use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{config::IsZeroConfig, constants::UInt, r_insn::RInstructionConfig, RIVInstruction};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    instructions::Instruction,
    uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    dividend: UInt<E>,
    divisor: UInt<E>,
    outcome: UInt<E>,

    remainder: UInt<E>,
    inter_mul_value: UInt<E>,
    is_zero: IsZeroConfig,
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct DivUOp;
impl RIVInstruction for DivUOp {
    const INST_KIND: InsnKind = InsnKind::DIVU;
}
pub type DivUInstruction<E> = ArithInstruction<E, DivUOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = ArithConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // outcome = dividend / divisor + remainder => dividend = divisor * outcome + r
        let mut divisor = UInt::new_unchecked(|| "divisor", circuit_builder)?;
        let mut outcome = UInt::new_unchecked(|| "outcome", circuit_builder)?;
        let mut r = UInt::new_unchecked(|| "remainder", circuit_builder)?;

        let (inter_mul_value, dividend) =
            divisor.mul_add(|| "dividend", circuit_builder, &mut outcome, &mut r, true)?;

        // div by zero check
        let is_zero = divisor.is_zero(circuit_builder)?;
        outcome.limbs.iter().for_each(|&limb| {
            // conditional_outcome is -1 if divisor is zero
            // => is_zero * (-1) + (1 - is_zero) * outcome = outcome - is_zero*outcome - is_zero*(-1)
            let conditional_outcome = limb.expr()
                + is_zero.is_zero.expr() * Expression::from(u16::MAX as usize)
                - is_zero.is_zero.expr() * limb.expr();

            circuit_builder
                .require_equal(|| "outcome_check", limb.expr(), conditional_outcome)
                .unwrap();
        });

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            dividend.register_expr(),
            divisor.register_expr(),
            outcome.register_expr(),
        )?;

        Ok(ArithConfig {
            r_insn,
            dividend,
            divisor,
            outcome,
            remainder: r,
            inter_mul_value,
            is_zero,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;
        let rd = step.rd().unwrap().value.after;

        // dividend = divisor * outcome + r
        let dividend = Value::new_unchecked(rs1);
        let divisor = Value::new_unchecked(rs2);
        let outcome = Value::new_unchecked(rd);

        // divisor * outcome
        let inter_mul_value = Value::new_unchecked(rs2 * rd);
        let r = if rs2 == 0 {
            Value::new_unchecked(0)
        } else {
            Value::new_unchecked(rs1 % rs2)
        };

        // assignment
        config.r_insn.assign_instance(instance, lkm, step)?;
        config.divisor.assign_limbs(instance, divisor.u16_fields());
        config.outcome.assign_limbs(instance, outcome.u16_fields());

        let (_, inter_carries) = divisor.mul(&outcome, lkm, true);
        config
            .inter_mul_value
            .assign_limbs(instance, inter_mul_value.u16_fields());
        config.inter_mul_value.assign_carries(
            instance,
            inter_carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );
        config.remainder.assign_limbs(instance, r.u16_fields());

        let (_, carries) = divisor.mul_add(&outcome, &r, lkm, true);
        config
            .dividend
            .assign_limbs(instance, dividend.u16_fields());
        config.dividend.assign_carries(
            instance,
            carries
                .into_iter()
                .map(|carry| E::BaseField::from(carry as u64))
                .collect_vec(),
        );

        config.is_zero.assign::<E>(instance, divisor.u16_fields());

        Ok(())
    }
}

#[cfg(test)]
mod test {

    mod divu {
        use ceno_emul::{Change, StepRecord};
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;
        use multilinear_extensions::mle::IntoMLEs;

        use crate::{
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            instructions::{riscv::divu::DivUInstruction, Instruction},
            scheme::mock_prover::{MockProver, MOCK_PC_DIVU, MOCK_PROGRAM},
        };

        #[test]
        fn test_opcode_divu() {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(|| "divu", |cb| Ok(DivUInstruction::construct_circuit(cb)))
                .unwrap()
                .unwrap();

            // values assignment
            let (raw_witin, _) = DivUInstruction::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_DIVU,
                    MOCK_PROGRAM[3],
                    10,
                    2,
                    Change::new(0, 5),
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
        fn test_opcode_divu_remainder() {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(|| "divu", |cb| Ok(DivUInstruction::construct_circuit(cb)))
                .unwrap()
                .unwrap();

            // values assignment
            let (raw_witin, _) = DivUInstruction::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_DIVU,
                    MOCK_PROGRAM[3],
                    11,
                    2,
                    Change::new(0, 5),
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
        fn test_opcode_divu_by_zero() {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(|| "divu", |cb| Ok(DivUInstruction::construct_circuit(cb)))
                .unwrap()
                .unwrap();

            // values assignment
            let (raw_witin, _) = DivUInstruction::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_DIVU,
                    MOCK_PROGRAM[3],
                    11,
                    0,
                    Change::new(0, u32::MAX),
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
}
