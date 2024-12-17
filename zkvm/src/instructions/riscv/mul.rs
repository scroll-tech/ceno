//! Circuit implementations for MULH, MULHU, and MULHSU RISC-V opcodes
//!
//! Approach for computing the upper limb of a product of two 32-bit values
//! which are signed/signed, unsigned/unsigned, or signed/unsigned is the
//! following:
//!
//! - Compute the signed or unsigned value associated with input and output
//!   registers of the instruction
//! - Verify that the product of input values is equal to the value obtained
//!   by interpreting the output register `rd` as the high limb of a signed or
//!   unsigned 64-bit value with some additional 32-bit low limb
//!
//! Soundness of this approach is almost straightforward except for a
//! complication, which is that the 64-bit values represented by `rd` as a
//! high limb have a small number of values that are ambiguously represented
//! as field elements over the Goldilocks field.  The numbers for which the
//! projections into Goldilocks are unique are:
//!
//! - Signed 64-bits: `-2^63 + 2^32 - 1` to `2^63 - 2^32`
//! - Unsigned 64-bits: `2^32 - 1` to `2^64 - 2^32`
//!
//! The intervals of values corresponding to products of signed and/or unsigned
//! 32-bit integers are given by
//!
//! - Signed/signed: `-2^62 + 2^31` to `2^62`, length `2^63 - 2^31 + 1`
//! - Unsigned/unsigned: `0` to `2^64 - 2^33 + 1`, length `2^64 - 2^33 + 2`
//! - Signed/unsigned: `-2^63 + 2^31` to `2^63 - 2^32 - 2^31 + 1`, length
//!   `2^64 - 2^33 + 2`
//!
//! In particular, all of these intervals have length smaller than the
//! Goldilocks prime `p = 2^64 - 2^32 + 1`, and so these values are uniquely
//! represented as Goldilocks elements.  To ensure that the equality of the
//! product of input register values with the full 64-bit value with high limb
//! represented by `rd` is fully unambiguous, it is sufficient to ensure that
//! the domain of product values does not overlap with the intervals of
//! ambiguous 64-bit number representations.
//!
//! This is immediately the case for the signed/signed products because of the
//! smaller length of the interval of product values.  Since all signed/signed
//! products lie in the unambiguous range `-2^63 + 2^32 - 1` to `2^63 - 2^32` of
//! 64-bit 2s complement signed values, each such value associated with a
//! product value is uniquely determined.
//!
//! For unsigned/unsigned and signed/unsigned products, the situation is
//! different.  For unsigned/unsigned products, the interval of product values
//! between `0` and `2^32 - 2` is represented ambiguously by two unsigned 64-bit
//! values each, as Goldilocks field elements, but only the smaller of these
//! two representations is the correct product value.  Similarly for signed/
//! unsigned products, the product values between `-2^63 + 2^31` and
//! `-2^63 + 2^32 - 2` are ambiguously represented by two signed 64-bit values
//! each, as Goldilocks field elements, but only the smaller (more negative) of
//! these gives the correct product.
//!
//! Examples of these ambiguous representations:
//! - Unsigned/unsigned: for `rs1 = rs2 = 0`, the product should be represented
//!   by `hi = low = 0`, but can also be represented by `hi = 2^32 - 1` and
//!   `low = 1`, so that `hi * 2^32 + low = 2^64 - 2^32 + 1` which is congruent
//!   to 0 mod the Goldilocks prime.
//! - Signed/unsigned: for `rs1 = -2^31` and `rs2 = 2^32 - 1`, the product
//!   `-2^63 + 2^31` should be represented by `rd = -2^31` and `low = 2^31`,
//!   but can also be represented by `rd = 2^31 - 1` and `low = 2^31 + 1`,
//!   such that `rd*2^32 + low = 2^63 - 2^32 + 2^31 + 1`, which can be written
//!   as `(-2^63 + 2^31) + (2^64 - 2^32 + 1)`.
//!
//! As it happens, this issue can be remedied in each case by the following
//! mitigation: constrain the high limb `rd` to not be equal to its maximal
//! value, which is `2^32 - 1` in the unsigned case, and `2^31 - 1` in the
//! signed case.  Removing this possibility eliminates the entire high
//! interval of ambiguous values represented in 64-bits, but still allows
//! representing the entire range of product values in each case.
//! Specifically, with this added restriction, the numbers represented by
//! (restricted) 64-bit values unambiguously over Goldilocks are
//!
//! - Signed (restricted) 64-bits: `-2^63` to `2^63 - 2^32 - 1`
//! - Unsigned (restricted) 64-bits: `0` to `2^64 - 2^32 - 1`
//!
//! With this added check in place, the 64-bit values represented with `rd` as
//! the high limb uniquely represent the product values for unsigned/unsigned
//! and signed/unsigned products.

use std::{fmt::Display, marker::PhantomData};

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    gadgets::{IsEqualConfig, SignedExtendConfig},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{BIT_WIDTH, UInt},
            r_insn::RInstructionConfig,
        },
    },
    uint::Value,
    utils::i64_to_base,
    witness::LkMultiplicity,
};

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulOp;
impl RIVInstruction for MulOp {
    const INST_KIND: InsnKind = InsnKind::MUL;
}
pub type MulInstruction<E> = MulhInstructionBase<E, MulOp>;

pub struct MulhOp;
impl RIVInstruction for MulhOp {
    const INST_KIND: InsnKind = InsnKind::MULH;
}
pub type MulhInstruction<E> = MulhInstructionBase<E, MulhOp>;

pub struct MulhuOp;
impl RIVInstruction for MulhuOp {
    const INST_KIND: InsnKind = InsnKind::MULHU;
}
pub type MulhuInstruction<E> = MulhInstructionBase<E, MulhuOp>;

pub struct MulhsuOp;
impl RIVInstruction for MulhsuOp {
    const INST_KIND: InsnKind = InsnKind::MULHSU;
}
pub type MulhsuInstruction<E> = MulhInstructionBase<E, MulhsuOp>;

pub struct MulhConfig<E: ExtensionField> {
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,
    sign_deps: MulhSignDependencies<E>,
    r_insn: RInstructionConfig<E>,
    /// The low/high part of the result of multiplying two Uint32.
    ///
    /// Whether it's low or high depends on the operation.
    prod_lo_hi: UInt<E>,
}

enum MulhSignDependencies<E: ExtensionField> {
    LL {
        constrain_rd: IsEqualConfig,
    },
    UU {
        constrain_rd: IsEqualConfig,
    },
    SU {
        rs1_signed: Signed<E>,
        rd_signed: Signed<E>,
        constrain_rd: IsEqualConfig,
    },
    SS {
        rs1_signed: Signed<E>,
        rs2_signed: Signed<E>,
        rd_signed: Signed<E>,
    },
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        // The soundness analysis for these constraints is only valid for
        // 32-bit registers represented over the Goldilocks field, so verify
        // these parameters
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(E::BaseField::MODULUS_U64, goldilocks::MODULUS);

        // 0. Registers and instruction lookup
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        // 1. Compute the signed values associated with `rs1`, `rs2`, `rd` and 2nd half of the prod
        let (rs1_val, rs2_val, rd_val, sign_deps, prod_lo_hi) = match I::INST_KIND {
            InsnKind::MULH => {
                let rs1_signed = Signed::construct_circuit(circuit_builder, || "rs1", &rs1_read)?;
                let rs2_signed = Signed::construct_circuit(circuit_builder, || "rs2", &rs2_read)?;
                let rd_signed = Signed::construct_circuit(circuit_builder, || "rd", &rd_written)?;
                let prod_low = UInt::new(|| "prod_low", circuit_builder)?;

                (
                    rs1_signed.expr(),
                    rs2_signed.expr(),
                    rd_signed.expr(),
                    MulhSignDependencies::SS {
                        rs1_signed,
                        rs2_signed,
                        rd_signed,
                    },
                    prod_low,
                )
            }

            InsnKind::MULHU => {
                let prod_low = UInt::new(|| "prod_low", circuit_builder)?;
                // constrain that rd does not represent 2^32 - 1
                let rd_avoid = Expression::<E>::from(u32::MAX);
                let constrain_rd = IsEqualConfig::construct_non_equal(
                    circuit_builder,
                    || "constrain_rd",
                    rd_written.value(),
                    rd_avoid,
                )?;

                (
                    rs1_read.value(),
                    rs2_read.value(),
                    rd_written.value(),
                    MulhSignDependencies::UU { constrain_rd },
                    prod_low,
                )
            }
            InsnKind::MUL => {
                // constrain that prod_hi does not represent 2^32 - 1
                let prod_hi_avoid = Expression::<E>::from(u32::MAX);
                let prod_hi = UInt::new(|| "prod_hi", circuit_builder)?;
                let constrain_rd = IsEqualConfig::construct_non_equal(
                    circuit_builder,
                    || "constrain_prod_hi",
                    prod_hi.value(),
                    prod_hi_avoid,
                )?;

                (
                    rs1_read.value(),
                    rs2_read.value(),
                    rd_written.value(),
                    MulhSignDependencies::LL { constrain_rd },
                    prod_hi,
                )
            }

            InsnKind::MULHSU => {
                let rs1_signed = Signed::construct_circuit(circuit_builder, || "rs1", &rs1_read)?;
                let rd_signed = Signed::construct_circuit(circuit_builder, || "rd", &rd_written)?;
                let prod_low = UInt::new(|| "prod_low", circuit_builder)?;

                // constrain that (signed) rd does not represent 2^31 - 1
                let rd_avoid = Expression::<E>::from(i32::MAX);
                let constrain_rd = IsEqualConfig::construct_non_equal(
                    circuit_builder,
                    || "constrain_rd",
                    rd_signed.expr(),
                    rd_avoid,
                )?;

                (
                    rs1_signed.expr(),
                    rs2_read.value(),
                    rd_signed.expr(),
                    MulhSignDependencies::SU {
                        rs1_signed,
                        rd_signed,
                        constrain_rd,
                    },
                    prod_low,
                )
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        // 2. Verify that the product of signed inputs `rs1` and `rs2` is equal to
        //    the result of interpreting `rd` as the high limb of a 2s complement
        //    value
        match I::INST_KIND {
            InsnKind::MUL => circuit_builder.require_equal(
                || "validate_prod_low_limb",
                rs1_val * rs2_val,
                (prod_lo_hi.value() << 32) + rd_val,
            )?,
            // MULH families
            InsnKind::MULHU | InsnKind::MULHSU | InsnKind::MULH => circuit_builder.require_equal(
                || "validate_prod_high_limb",
                rs1_val * rs2_val,
                (rd_val << 32) + prod_lo_hi.value(),
            )?,
            _ => unreachable!("Unsupported instruction kind"),
        }

        Ok(MulhConfig {
            rs1_read,
            rs2_read,
            rd_written,
            sign_deps,
            prod_lo_hi,
            r_insn,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // Read registers from step
        let rs1 = step.rs1().unwrap().value;
        let rs1_val = Value::new_unchecked(rs1);
        config
            .rs1_read
            .assign_limbs(instance, rs1_val.as_u16_limbs());

        let rs2 = step.rs2().unwrap().value;
        let rs2_val = Value::new_unchecked(rs2);
        config
            .rs2_read
            .assign_limbs(instance, rs2_val.as_u16_limbs());

        let rd = step.rd().unwrap().value.after;
        let rd_val = Value::new(rd, lk_multiplicity);
        config
            .rd_written
            .assign_limbs(instance, rd_val.as_u16_limbs());

        // R-type instruction
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        // Assign signed values, if any, and compute low 32-bit limb of product
        let prod_lo_hi = match &config.sign_deps {
            MulhSignDependencies::SS {
                rs1_signed,
                rs2_signed,
                rd_signed,
            } => {
                // Signed register values
                let rs1_s = rs1_signed.assign_instance(instance, lk_multiplicity, &rs1_val)?;
                let rs2_s = rs2_signed.assign_instance(instance, lk_multiplicity, &rs2_val)?;
                rd_signed.assign_instance(instance, lk_multiplicity, &rd_val)?;

                // only take the low part of the product
                rs1_s.wrapping_mul(rs2_s) as u32
            }
            MulhSignDependencies::UU { constrain_rd } => {
                // assign nonzero value (u32::MAX - rd)
                let rd_f = E::BaseField::from(rd as u64);
                let avoid_f = E::BaseField::from(u32::MAX.into());
                constrain_rd.assign_instance(instance, rd_f, avoid_f)?;

                // only take the low part of the product
                rs1.wrapping_mul(rs2)
            }
            MulhSignDependencies::LL { constrain_rd } => {
                let prod = rs1_val.as_u64() * rs2_val.as_u64();
                let prod_lo = prod as u32;
                assert_eq!(prod_lo, rd);

                let prod_hi = prod >> BIT_WIDTH;
                let avoid_f = E::BaseField::from(u32::MAX.into());
                constrain_rd.assign_instance(instance, E::BaseField::from(prod_hi), avoid_f)?;
                prod_hi as u32
            }
            MulhSignDependencies::SU {
                rs1_signed,
                rd_signed,
                constrain_rd,
            } => {
                // Signed register values
                let rs1_s = rs1_signed.assign_instance(instance, lk_multiplicity, &rs1_val)?;
                let rd_s = rd_signed.assign_instance(instance, lk_multiplicity, &rd_val)?;

                // assign nonzero value (i32::MAX - rd)
                let rd_f = i64_to_base(rd_s as i64);
                let avoid_f = i64_to_base(i32::MAX.into());
                constrain_rd.assign_instance(instance, rd_f, avoid_f)?;

                // only take the low part of the product
                (rs2).wrapping_mul(rs1_s as u32)
            }
        };

        let prod_lo_hi_val = Value::new(prod_lo_hi, lk_multiplicity);
        config
            .prod_lo_hi
            .assign_limbs(instance, prod_lo_hi_val.as_u16_limbs());

        Ok(())
    }
}

/// Transform a value represented as a `UInt` into a `WitIn` containing its
/// corresponding signed value, interpreting the bits as a 2s-complement
/// encoding.  Gadget allocates 2 `WitIn` values in total.
struct Signed<E: ExtensionField> {
    pub is_negative: SignedExtendConfig<E>,
    val: Expression<E>,
}

impl<E: ExtensionField> Signed<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        unsigned_val: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(name_fn, |cb| {
            let is_negative = unsigned_val.is_negative(cb)?;
            let val = unsigned_val.value() - (1u64 << BIT_WIDTH) * is_negative.expr();

            Ok(Self { is_negative, val })
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        val: &Value<u32>,
    ) -> Result<i32, ZKVMError> {
        self.is_negative.assign_instance(
            instance,
            lkm,
            *val.as_u16_limbs().last().unwrap() as u64,
        )?;
        Ok(i32::from(val))
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
    fn test_opcode_mul() {
        verify_mulu::<MulOp>("basic", 2, 11);
        verify_mulu::<MulOp>("2 * 0", 2, 0);
        verify_mulu::<MulOp>("0 * 0", 0, 0);
        verify_mulu::<MulOp>("0 * 2", 0, 2);
        verify_mulu::<MulOp>("0 * u32::MAX", 0, u32::MAX);
        verify_mulu::<MulOp>("u32::MAX", u32::MAX, u32::MAX);
        verify_mulu::<MulOp>("u16::MAX", u16::MAX as u32, u16::MAX as u32);
    }

    #[test]
    fn test_opcode_mulhu() {
        verify_mulu::<MulhuOp>("basic", 2, 11);
        verify_mulu::<MulhuOp>("2 * 0", 2, 0);
        verify_mulu::<MulhuOp>("0 * 0", 0, 0);
        verify_mulu::<MulhuOp>("0 * 2", 0, 2);
        verify_mulu::<MulhuOp>("0 * u32::MAX", 0, u32::MAX);
        verify_mulu::<MulhuOp>("u32::MAX", u32::MAX, u32::MAX);
        verify_mulu::<MulhuOp>("u16::MAX", u16::MAX as u32, u16::MAX as u32);
    }

    fn verify_mulu<I: RIVInstruction>(name: &'static str, rs1: u32, rs2: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                |cb| {
                    Ok(MulhInstructionBase::<GoldilocksExt2, I>::construct_circuit(
                        cb,
                    ))
                },
            )
            .unwrap()
            .unwrap();

        let outcome = match I::INST_KIND {
            InsnKind::MUL => rs1.wrapping_mul(rs2),
            InsnKind::MULHU => {
                let a = Value::<'_, u32>::new_unchecked(rs1);
                let b = Value::<'_, u32>::new_unchecked(rs2);
                let value_mul = a.mul_hi(&b, &mut LkMultiplicity::default(), true);
                value_mul.as_hi_value::<u32>().as_u32()
            }
            _ => unreachable!("Unsupported instruction kind"),
        };

        // values assignment
        let insn_code = encode_rv32(I::INST_KIND, 2, 3, 4, 0);
        let (raw_witin, lkm) = MulhInstructionBase::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1,
                rs2,
                Change::new(0, outcome),
                0,
            )],
        )
        .unwrap();

        // verify value write to register, which is only hi
        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(outcome).as_u16_limbs().to_vec());
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

    #[test]
    fn test_opcode_mulhsu() {
        let test_cases = vec![
            (0, 0),
            (0, 5),
            (0, u32::MAX),
            (7, 0),
            (2, 11),
            (91, u32::MAX),
            (i32::MAX, 0),
            (i32::MAX, 2),
            (i32::MAX, u32::MAX),
            (-4, 0),
            (-1, 3),
            (-1000, u32::MAX),
            (i32::MIN, 0),
            (i32::MIN, 21),
            (i32::MIN, u32::MAX),
        ];
        test_cases
            .into_iter()
            .for_each(|(rs1, rs2)| verify_mulhsu(rs1, rs2));
    }

    fn verify_mulhsu(rs1: i32, rs2: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "mulhsu",
                |cb| Ok(MulhsuInstruction::construct_circuit(cb)),
            )
            .unwrap()
            .unwrap();

        let signed_unsigned_prod_high = ((rs1 as i64).wrapping_mul(rs2 as i64) >> 32) as u32;

        // values assignment
        let insn_code = encode_rv32(InsnKind::MULHSU, 2, 3, 4, 0);
        let (raw_witin, lkm) =
            MulhsuInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_START,
                    insn_code,
                    rs1 as u32,
                    rs2,
                    Change::new(0, signed_unsigned_prod_high),
                    0,
                ),
            ])
            .unwrap();

        // verify value written to register
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            Expression::from(signed_unsigned_prod_high),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
