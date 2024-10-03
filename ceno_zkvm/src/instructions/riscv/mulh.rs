use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{
    constants::{UInt, UIntMul, VALUE_BIT_WIDTH},
    r_insn::RInstructionConfig,
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::Instruction,
    uint::{UIntLimbs, Value},
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles R-Instructions that represent registers values as 2 * u16.
#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UIntMul<E>,
}

pub struct MulhInstruction<E, I>(PhantomData<(E, I)>);

pub struct MulhuOp;
impl RIVInstruction for MulhuOp {
    const INST_KIND: InsnKind = InsnKind::MULHU;
}
pub type MulhuInstruction<E> = MulhInstruction<E, MulhuOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstruction<E, I> {
    type InstructionConfig = ArithConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let (rs1_read, rs2_read, rd_written, rd_written_reg_expr) = match I::INST_KIND {
            InsnKind::MULHU => {
                // rs1_read * rs2_read = rd_written
                let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let mut rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rd_written: UIntMul<E> =
                    rs1_read.mul(|| "rd_written", circuit_builder, &mut rs2_read, true)?;
                let rd_written_exprs = rd_written.expr();
                let rd_hi = UInt::from_exprs_unchecked(
                    rd_written_exprs[(rd_written_exprs.len() / 2)..].to_vec(),
                )?;
                (rs1_read, rs2_read, rd_written, rd_hi.register_expr())
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written_reg_expr,
        )?;

        Ok(ArithConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());

        match I::INST_KIND {
            InsnKind::MULHU => {
                // rs1_read * rs2_read = rd_written
                let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
                let rd_written = Value::new_unchecked(step.rd().unwrap().value.after);

                config
                    .rs1_read
                    .assign_limbs(instance, rs1_read.as_u16_limbs());

                let (limbs, carries, max_carry_value) =
                    rs1_read.mul_hi(&rs2_read, lk_multiplicity, true);
                println!("limbs {:?}", limbs);

                config
                    .rd_written
                    .assign_limbs(instance, rd_written.as_u16_limbs());
                config.rd_written.assign_carries(instance, &carries);
                config.rd_written.assign_carries_auxiliary(
                    instance,
                    lk_multiplicity,
                    &carries,
                    max_carry_value,
                )?;
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{
            MockProver, MOCK_PC_ADD, MOCK_PC_MUL, MOCK_PC_MULHU, MOCK_PC_SUB, MOCK_PROGRAM,
        },
    };

    #[test]
    fn test_opcode_mulhu() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mulhu", |cb| Ok(MulhuInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulhuInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MULHU,
                MOCK_PROGRAM[18],
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
}
