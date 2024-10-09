use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{r_insn::RInstructionConfig, RIVInstruction};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, gadgets::DivConfig,
    instructions::Instruction, uint::Value, witness::LkMultiplicity,
};
use core::mem::MaybeUninit;
use std::marker::PhantomData;

pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,
    div_config: DivConfig<E, true>,
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
        let div_config = DivConfig::construct_circuit(circuit_builder, || "divu")?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            div_config.dividend.register_expr(),
            div_config.divisor.register_expr(),
            div_config.quotient.register_expr(),
        )?;

        Ok(ArithConfig { r_insn, div_config })
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
        let divisor = Value::new_unchecked(rs2);
        let outcome = Value::new(rd, lkm);

        let r = if rs2 == 0 {
            Value::new_unchecked(0)
        } else {
            Value::new(rs1 % rs2, lkm)
        };

        // assignment
        config.r_insn.assign_instance(instance, lkm, step)?;

        config
            .div_config
            .assign_instance(instance, lkm, &divisor, &outcome, &r)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    mod divu {

        use ceno_emul::{Change, StepRecord, Word};
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;
        use multilinear_extensions::mle::IntoMLEs;
        use rand::Rng;

        use crate::{
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            instructions::{
                riscv::{constants::UInt, divu::DivUInstruction},
                Instruction,
            },
            scheme::mock_prover::{MockProver, MOCK_PC_DIVU, MOCK_PROGRAM},
            Value,
        };

        fn verify(name: &'static str, dividend: Word, divisor: Word, exp_outcome: Word) {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(
                    || format!("divu_({name})"),
                    |cb| Ok(DivUInstruction::construct_circuit(cb)),
                )
                .unwrap()
                .unwrap();

            let outcome = if divisor == 0 {
                u32::MAX
            } else {
                dividend / divisor
            };
            // values assignment
            let (raw_witin, _) = DivUInstruction::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_DIVU,
                    MOCK_PROGRAM[9],
                    dividend,
                    divisor,
                    Change::new(0, outcome),
                    0,
                )],
            )
            .unwrap();

            let expected_rd_written = UInt::from_const_unchecked(
                Value::new_unchecked(exp_outcome).as_u16_limbs().to_vec(),
            );

            config
                .div_config
                .quotient
                .require_equal(|| "assert_outcome", &mut cb, &expected_rd_written)
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
        fn test_opcode_divu() {
            verify("basic", 10, 2, 5);
            verify("dividend > divisor", 10, 11, 0);
            verify("remainder", 11, 2, 5);
            verify("u32::MAX", u32::MAX, u32::MAX, 1);
            verify("div u32::MAX", 3, u32::MAX, 0);
            verify("u32::MAX div by 2", u32::MAX, 2, u32::MAX / 2);
            verify("mul with carries", 1202729773, 171818539, 7);
            verify("div by zero", 10, 0, u32::MAX);
        }

        #[test]
        fn test_opcode_divu_random() {
            let mut rng = rand::thread_rng();
            let a: u32 = rng.gen();
            let b: u32 = rng.gen_range(1..u32::MAX);
            println!("random: {} / {} = {}", a, b, a / b);
            verify("random", a, b, a / b);
        }
    }
}
