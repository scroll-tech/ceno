use std::{fmt::Display, marker::PhantomData};

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    gadgets::IsLtConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{BIT_WIDTH, LIMB_BITS, UInt, UIntMul},
            r_insn::RInstructionConfig,
        },
    },
    uint::Value,
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
    rs1_signed: Signed<E>,
    rs2_signed: Signed<E>,
    rd_signed: Signed<E>,
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

        // 1. Compute the signed values associated with `rs1`, `rs2`, and `rd`

        let rs1_signed = Signed::construct_circuit(circuit_builder, || "rs1", &rs1_read)?;
        let rs2_signed = Signed::construct_circuit(circuit_builder, || "rs2", &rs2_read)?;
        let rd_signed = Signed::construct_circuit(circuit_builder, || "rd", &rd_written)?;

        // 2. Verify that the product of signed inputs `rs1` and `rs2` is equal to
        //    the result of interpreting `rd` as the high limb of a 2s complement
        //    value with some 32-bit low limb

        let unsigned_prod_low = UInt::new(|| "unsigned_prod_low", circuit_builder)?;
        circuit_builder.require_equal(
            || "validate_prod_high_limb",
            rs1_signed.expr() * rs2_signed.expr(),
            rd_signed.expr() * (1u64 << 32) + unsigned_prod_low.value(),
        )?;

        // The soundness here is a bit subtle.  The signed values of 32-bit
        // inputs `rs1` and `rs2` have values between `-2^31` and `2^31 - 1`, so
        // their product is constrained to lie between `-2^62 + 2^31` and
        // `2^62`.  In a prime field of size smaller than `2^64`, the range of
        // values represented by a 64-bit 2s complement value, integers between
        // `-2^63` and `2^63 - 1`, have some ambiguity.  If `p = 2^64 - k`, then
        // the values between `-2^63` and `-2^63 + k - 1` correspond with the
        // values between `2^63 - k` and `2^63 - 1`.
        //
        // However, as long as the values required by signed products don't overlap
        // with this ambiguous range, an arbitrary 64-bit 2s complement value can
        // represent a signed 32-bit product in only one way, so there is no
        // ambiguity in the representation.  This is the case for the Goldilocks
        // field with order `p = 2^64 - 2^32 + 1`.

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
        // Read registers from step
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        config
            .rs1_read
            .assign_limbs(instance, rs1_read.as_u16_limbs());

        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());

        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        config
            .rd_written
            .assign_limbs(instance, rd_written.as_u16_limbs());

        // Signed register values
        let rs1_signed = config
            .rs1_signed
            .assign_instance(instance, lk_multiplicity, &rs1_read)?;

        let rs2_signed = config
            .rs2_signed
            .assign_instance(instance, lk_multiplicity, &rs2_read)?;

        config
            .rd_signed
            .assign_instance(instance, lk_multiplicity, &rd_written)?;

        // Low limb of product in 2s complement form
        let prod = ((rs1_signed as i64) * (rs2_signed as i64)) as u64;
        let unsigned_prod_low = (prod % (1u64 << BIT_WIDTH)) as u32;
        let unsigned_prod_low_val = Value::new(unsigned_prod_low, lk_multiplicity);
        config
            .unsigned_prod_low
            .assign_limbs(instance, unsigned_prod_low_val.as_u16_limbs());

        // R-type instruction
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

/// Transform a value represented as a `UInt` into a `WitIn` containing its
/// corresponding signed value, interpreting the bits as a 2s-complement
/// encoding.  Gadget allocates 2 `WitIn` values in total.
struct Signed<E: ExtensionField> {
    pub is_negative: IsLtConfig,
    val: Expression<E>,
}

impl<E: ExtensionField> Signed<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        unsigned_val: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(
            || "signed",
            |cb| {
                let name = name_fn();
                // is_lt is set if top limb of val is negative
                let is_negative = IsLtConfig::construct_circuit(
                    cb,
                    || name.clone(),
                    ((1u64 << (LIMB_BITS - 1)) - 1).into(),
                    unsigned_val.expr().last().unwrap().clone(),
                    1,
                )?;
                let val = unsigned_val.value() - (1u64 << BIT_WIDTH) * is_negative.expr();

                Ok(Self { is_negative, val })
            },
        )
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        val: &Value<u32>,
    ) -> Result<i32, ZKVMError> {
        let high_limb = *val.limbs.last().unwrap() as u64;
        let sign_cutoff = (1u64 << (LIMB_BITS - 1)) - 1;
        self.is_negative
            .assign_instance(instance, lkm, sign_cutoff, high_limb)?;

        let signed_val = val.as_u32() as i32;

        Ok(signed_val)
    }

    pub fn expr(&self) -> Expression<E> {
        self.val.clone()
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
        verify_mulhu(2, 11);
        verify_mulhu(u32::MAX, u32::MAX);
        verify_mulhu(u16::MAX as u32, u16::MAX as u32);
    }

    fn verify_mulhu(rs1: u32, rs2: u32) {
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

    #[test]
    fn test_opcode_mulh() {
        let test_cases = vec![
            (2, 11),
            (7, 0),
            (0, 5),
            (0, -3),
            (-19, 0),
            (0, 0),
            (-12, -31),
            (2, -1),
            (1, i32::MIN),
            (i32::MAX, -1),
            (i32::MAX, i32::MIN),
            (i32::MAX, i32::MAX),
            (i32::MIN, i32::MIN),
        ];
        test_cases
            .into_iter()
            .for_each(|(rs1, rs2)| verify_mulh(rs1, rs2));
    }

    fn verify_mulh(rs1: i32, rs2: i32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mulh", |cb| Ok(MulhInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        let signed_prod_high = ((rs1 as i64).wrapping_mul(rs2 as i64) >> 32) as u32;

        // values assignment
        let insn_code = encode_rv32(InsnKind::MULH, 2, 3, 4, 0);
        let (raw_witin, lkm) =
            MulhInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_START,
                    insn_code,
                    rs1 as u32,
                    rs2 as u32,
                    Change::new(0, signed_prod_high),
                    0,
                ),
            ])
            .unwrap();

        // verify value written to register
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            Expression::from(signed_prod_high),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
