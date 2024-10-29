use std::{marker::PhantomData, ops::Neg};

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use super::{
    RIVInstruction,
    constants::{UInt, UIntMul},
    r_insn::RInstructionConfig,
};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::{Expression, ToExpr, WitIn}, gadgets::IsLtConfig, instructions::Instruction, set_val, uint::Value, witness::LkMultiplicity
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

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulhuOp;
impl RIVInstruction for MulhuOp {
    const INST_KIND: InsnKind = InsnKind::MULHU;
}
pub type MulhuInstruction<E> = MulhInstructionBase<E, MulhuOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
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
                let (_, rd_written_hi) = rd_written.as_lo_hi()?;
                (
                    rs1_read,
                    rs2_read,
                    rd_written,
                    rd_written_hi.register_expr(),
                )
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

                config
                    .rs1_read
                    .assign_limbs(instance, rs1_read.as_u16_limbs());

                let rd_written = rs1_read.mul_hi(&rs2_read, lk_multiplicity, true);

                config
                    .rd_written
                    .assign_mul_outcome(instance, lk_multiplicity, &rd_written)?;
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        Ok(())
    }
}

pub struct MulhInstruction<E>(PhantomData<E>);

pub struct MulhConfig<E: ExtensionField> {
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,
    rs1_signed: Signed,
    rs2_signed: Signed,
    rd_signed: Signed,
    unsigned_prod_low: UInt<E>,
    r_insn: RInstructionConfig<E>,
}

impl<E: ExtensionField> Instruction<E> for MulhInstruction<E> {
    type InstructionConfig = MulhConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::MULH)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let rs1_signed = Signed::construct_circuit(circuit_builder, &rs1_read)?;
        let rs2_signed = Signed::construct_circuit(circuit_builder, &rs2_read)?;
        let rd_signed = Signed::construct_circuit(circuit_builder, &rd_written)?;

        let unsigned_prod_low = UInt::new(|| "prod_low", circuit_builder)?;

        circuit_builder.require_equal(
            || "unsigned_prod_equal",
            rs1_signed.abs_value.expr() * rs2_signed.abs_value.expr(),
            unsigned_prod_low.value() + Expression::<E>::from(1u64 << 32) * rd_signed.abs_value.expr()
        )?;

        circuit_builder.require_equal(
            || "check_signs",
            rs1_signed.is_negative.expr::<E>() * (Expression::<E>::ONE - rs2_signed.is_negative.expr())
            + (Expression::<E>::ONE - rs1_signed.is_negative.expr::<E>()) * rs2_signed.is_negative.expr(),
            rd_signed.is_negative.expr())?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            InsnKind::MULH,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(MulhConfig {
            rs1_read,
            rs2_read,
            rd_written,
            rs1_signed,
            rs2_signed,
            rd_signed,
            unsigned_prod_low,
            r_insn,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!();

        // Ok(())
    }
}


struct Signed {
    pub is_negative: IsLtConfig,
    pub abs_value: WitIn,
}

impl Signed {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        val: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        // is_lt is set if top limb of val is negative
        let sign_cmp = IsLtConfig::construct_circuit(
            cb,
            || "signed",
            (1u64 << 15).into(),
            val.expr().last().unwrap().clone(),
            1)?;
        let abs_value = cb.create_witin(|| "abs_value witin")?;
        cb.require_equal(|| "abs_value", abs_value.expr(),
            (1 - 2*sign_cmp.expr())*(val.value() - (1 << 32)*sign_cmp.expr()))?;

        Ok(Self { is_negative: sign_cmp, abs_value })
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        lkm: &mut LkMultiplicity,
        val: &Value<u32>,
    ) -> Result<(), ZKVMError> {
        self.is_negative.assign_instance(instance, lkm, 1u64 << 15, *val.limbs.last().unwrap() as u64)?;
        let unsigned = val.as_u64();
        set_val!(instance, self.abs_value, if unsigned >= (1u64 << 31) {
            (unsigned as i64 - (1i64 << 32)).neg() as u64
        } else {
            unsigned
        });
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use super::*;
    use crate::{
        chip_handler::test::DebugIndex,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_opcode_mulhu() {
        verify(2, 11);
        verify(u32::MAX, u32::MAX);
        verify(u16::MAX as u32, u16::MAX as u32);
    }

    fn verify(rs1: u32, rs2: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mulhu", |cb| Ok(MulhuInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        let a = Value::<'_, u32>::new_unchecked(rs1);
        let b = Value::<'_, u32>::new_unchecked(rs2);
        let value_mul = a.mul_hi(&b, &mut LkMultiplicity::default(), true);

        // values assignment
        let insn_code = encode_rv32(InsnKind::MULHU, 2, 3, 4, 0);
        let (raw_witin, lkm) =
            MulhuInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_START,
                    insn_code,
                    a.as_u64() as u32,
                    b.as_u64() as u32,
                    Change::new(0, value_mul.as_hi_value::<u32>().as_u32()),
                    0,
                ),
            ])
            .unwrap();

        // verify value write to register, which is only hi
        let expected_rd_written = UInt::from_const_unchecked(value_mul.as_hi_limb_slice().to_vec());
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            expected_rd_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
