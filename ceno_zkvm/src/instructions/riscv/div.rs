//! Circuit implementations for DIVU, REMU, DIV, and REM RISC-V opcodes
//!
//! The signed and unsigned division and remainder opcodes are handled by
//! simulating the division algorithm expression:
//!
//! `dividend = divisor * quotient + remainder` (1)
//!
//! where `remainder` is constrained to be between 0 and the divisor in a way
//! that suitably respects signed values, except for the case of division by 0.
//! Of particular note for this implememntation is the fact that in the
//! Goldilocks field, the right hand side of (1) does not wrap around under
//! modular arithmetic for either unsigned or signed 32-bit range-checked
//! values of `divisor`, `quotient`, and `remainder`, taking values between `0`
//! and `2^64 - 2^32` in the unsigned case, and between `-2^62` and `2^62 +
//! 2^31 - 1` in the signed case.
//!
//! This means that in either the unsigned or the signed setting, equation
//! (1) can be checked directly using native field expressions without
//! ambiguity due to modular field arithmetic.
//!
//! The remainder of the complexity of this circuit comes about because of two
//! edge cases in the opcodes: division by zero, and signed division overflow.
//! For division by zero, equation (1) still holds, but an extra constraint is
//! imposed on the value of `quotient` to be `u32::MAX` in the unsigned case,
//! or `-1` in the unsigned case (the 32-bit vector with all 1s for both).
//!
//! Signed division overflow occurs when `dividend` is set to `i32::MIN
//! = -2^31`, and `divisor` is set to `-1`.  In this case, the natural value of
//! `quotient` is `2^31`, but this value cannot be properly represented as a
//! signed 32-bit integer, so an error output must be enforced with `quotient =
//! i32::MIN`, and `remainder = 0`.  In this one case, the proper RISC-V values
//! for `dividend`, `divisor`, `quotient`, and `remainder` do not satisfy the
//! division algorithm expression (1), so the proper values of `quotient` and
//! `remainder` can be enforced by instead imposing the variant constraint
//!
//! `2^31 = divisor * quotient + remainder` (2)
//!
//! Once (1) or (2) is appropriately satisfied, an inequality condition is
//! imposed on remainder, which varies depending on signs of the inputs.  In
//! the case of unsigned inputs, this is just
//!
//! `0 <= remainder < divisor` (3)
//!
//! for signed inputs, the inequality is a little more complicated: for
//! `dividend` and `divisor` with the same sign, quotient and remainder are
//! non-negative, and we require
//!
//! `0 <= remainder < |divisor|` (4)
//!
//! When `dividend` and `divisor` have different signs, `quotient` and
//! `remainder` are non-positive values, and we instead require
//!
//! `-|divisor| < remainder <= 0` (5)
//!
//! To handle these variations of the remainder inequalities in a uniform
//! manner, we derive expressions representing the "positively oriented" values
//! with signs set so that the inequalities are always of the form (3).  Note
//! that it is not enough to just take absolute values, as this would allow
//! values with an incorrect sign, e.g. for 10 divided by -6, one could witness
//! `10 = -6 * 2 + 2` instead of the correct expression `10 = -6 * 1 - 4`.
//!
//! The inequality condition (5) is properly satisfied by `divisor` and the
//! appropriate value of `remainder` in the case of signed division overflow,
//! so no special treatment is needed in this case.  On the other hand, these
//! inequalities cannot be satisfied when `divisor` is `0`, so we require that
//! exactly one of `remainder < divisor` and `divisor = 0` holds.
//! Specifically, since these conditions are expressed as 0/1-valued booleans,
//! we require just that the sum of these booleans is equal to 1.

use ceno_emul::{InsnKind, StepRecord};
use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::{Goldilocks, SmallField};

use super::{
    RIVInstruction,
    constants::{UINT_LIMBS, UInt},
    r_insn::RInstructionConfig,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::{AssertLTConfig, IsEqualConfig, IsLtConfig, IsZeroConfig, Signed},
    instructions::Instruction,
    set_val,
    uint::Value,
    utils::i64_to_base,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;
use std::marker::PhantomData;

pub struct DivRemConfig<E: ExtensionField> {
    dividend: UInt<E>, // rs1_read
    divisor: UInt<E>,  // rs2_read
    quotient: UInt<E>,
    remainder: UInt<E>,

    internal_config: InternalDivRem<E>,

    is_divisor_zero: IsZeroConfig,
    is_remainder_lt_divisor: IsLtConfig,

    r_insn: RInstructionConfig<E>,
}

enum InternalDivRem<E: ExtensionField> {
    Unsigned,
    Signed {
        dividend_signed: Signed<E>,
        divisor_signed: Signed<E>,
        quotient_signed: Signed<E>,
        remainder_signed: Signed<E>,
        negative_division: WitIn,
        is_dividend_max_negative: IsEqualConfig,
        is_divisor_minus_one: IsEqualConfig,
        is_signed_overflow: WitIn,
        remainder_nonnegative: AssertLTConfig,
    },
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct DivuOp;
impl RIVInstruction for DivuOp {
    const INST_KIND: InsnKind = InsnKind::DIVU;
}
pub type DivuInstruction<E> = ArithInstruction<E, DivuOp>;

pub struct RemuOp;
impl RIVInstruction for RemuOp {
    const INST_KIND: InsnKind = InsnKind::REMU;
}
pub type RemuInstruction<E> = ArithInstruction<E, RemuOp>;

pub struct RemOp;
impl RIVInstruction for RemOp {
    const INST_KIND: InsnKind = InsnKind::REM;
}
pub type RemInstruction<E> = ArithInstruction<E, RemOp>;

pub struct DivOp;
impl RIVInstruction for DivOp {
    const INST_KIND: InsnKind = InsnKind::DIV;
}
pub type DivInstruction<E> = ArithInstruction<E, DivOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = DivRemConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // The soundness analysis for these constraints is only valid for
        // 32-bit registers represented over the Goldilocks field, so verify
        // these parameters
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(E::BaseField::MODULUS_U64, goldilocks::MODULUS);

        // 32-bit value from rs1
        let dividend = UInt::new_unchecked(|| "dividend", cb)?;
        // 32-bit value from rs2
        let divisor = UInt::new_unchecked(|| "divisor", cb)?;
        let quotient = UInt::new(|| "quotient", cb)?;
        let remainder = UInt::new(|| "remainder", cb)?;

        // `rem_e` and `div_e` are expressions representing the remainder and
        // divisor from the signed or unsigned division operation, with signs
        // normalized to be nonnegative, so that correct values must satisfy
        // either `0 <= rem_e < div_e` or `div_e == 0`.  The `rem_e` value
        // should be constrained to be nonnegative before being returned from
        // this block, while the checks `rem_e < div_e` or `div_e == 0` are
        // done later.
        let (internal_config, rem_e, div_e) = match I::INST_KIND {
            InsnKind::DIVU | InsnKind::REMU => {
                cb.require_equal(
                    || "unsigned_division_relation",
                    dividend.value(),
                    divisor.value() * quotient.value() + remainder.value(),
                )?;

                (InternalDivRem::Unsigned, remainder.value(), divisor.value())
            }

            InsnKind::DIV | InsnKind::REM => {
                let dividend_signed =
                    Signed::construct_circuit(cb, || "dividend_signed", &dividend)?;
                let divisor_signed = Signed::construct_circuit(cb, || "divisor_signed", &divisor)?;
                let quotient_signed =
                    Signed::construct_circuit(cb, || "quotient_signed", &quotient)?;
                let remainder_signed =
                    Signed::construct_circuit(cb, || "remainder_signed", &remainder)?;

                // The quotient and remainder can be interpreted as non-positive
                // values when exactly one of dividend and divisor is negative
                let neg_div_expr = {
                    let a_neg = dividend_signed.is_negative.expr();
                    let b_neg = divisor_signed.is_negative.expr();
                    &a_neg * (1 - &b_neg) + (1 - &a_neg) * &b_neg
                };
                let negative_division = cb.flatten_expr(|| "neg_division", neg_div_expr)?;

                // Check for signed division overflow: i32::MIN / -1
                let is_dividend_max_negative = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_dividend_max_negative",
                    dividend.value(),
                    (i32::MIN as u32).into(),
                )?;
                let is_divisor_minus_one = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_divisor_minus_one",
                    divisor.value(),
                    (-1i32 as u32).into(),
                )?;
                let is_signed_overflow = cb.flatten_expr(
                    || "signed_division_overflow",
                    is_dividend_max_negative.expr() * is_divisor_minus_one.expr(),
                )?;

                // For signed division overflow, dividend = -2^31 and divisor
                // = -1, so that quotient = 2^31 would be required for proper
                // arithmetic, which is too large for signed 32-bit values.  In
                // this case, quotient and remainder are required to be set to
                // -2^31 and 0 respectively.  These values are assured by the
                // constraints
                //
                //   2^31 = divisor * quotient + remainder
                //   0 <= |remainder| < |divisor|
                //
                // The second condition is the same inequality as required when
                // there is no overflow, so no special handling is needed.  The
                // first condition is only different from the proper value in
                // the left side of the equality, which can be controlled by a
                // conditional equality constraint using fixed dividend value
                // +2^31 in the signed overflow case.
                let div_rel_expr =
                    quotient_signed.expr() * divisor_signed.expr() + remainder_signed.expr();
                cb.condition_require_equal(
                    || "signed_division_relation",
                    is_signed_overflow.expr(),
                    div_rel_expr,
                    // overflow replacement dividend value, +2^31
                    (1u64 << 31).into(),
                    dividend_signed.expr(),
                )?;

                // Check required inequalities for remainder value; change sign
                // for remainder and divisor so that checked inequality is the
                // usual unsigned one, 0 <= remainder < divisor
                let remainder_pos_orientation: Expression<E> =
                    (1 - 2 * negative_division.expr()) * remainder_signed.expr();
                let divisor_pos_orientation =
                    (1 - 2 * divisor_signed.is_negative.expr()) * divisor_signed.expr();

                let remainder_nonnegative = AssertLTConfig::construct_circuit(
                    cb,
                    || "oriented_remainder_nonnegative",
                    (-1).into(),
                    remainder_pos_orientation.clone(),
                    UINT_LIMBS,
                )?;

                (
                    InternalDivRem::Signed {
                        dividend_signed,
                        divisor_signed,
                        quotient_signed,
                        remainder_signed,
                        negative_division,
                        is_dividend_max_negative,
                        is_divisor_minus_one,
                        is_signed_overflow,
                        remainder_nonnegative,
                    },
                    remainder_pos_orientation,
                    divisor_pos_orientation,
                )
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let is_divisor_zero =
            IsZeroConfig::construct_circuit(cb, || "is_divisor_zero", divisor.value())?;

        // For zero division, quotient must be the "all ones" register for both
        // unsigned and signed cases, representing 2^32-1 and -1 respectively.
        cb.condition_require_equal(
            || "quotient_zero_division",
            is_divisor_zero.expr(),
            quotient.value(),
            u32::MAX.into(),
            quotient.value(),
        )?;

        // Check whether the (suitably oriented) remainder is less than the
        // (suitably oriented) divisor, where "suitably oriented" is subtle for
        // the signed case, involving both signs and the constraints used for
        // signed division overflow.
        let is_remainder_lt_divisor = IsLtConfig::construct_circuit(
            cb,
            || "is_remainder_lt_divisor",
            rem_e,
            div_e,
            UINT_LIMBS,
        )?;

        // When divisor is nonzero, (nonnegative) remainder must be less than
        // divisor, but when divisor is zero, remainder can't be less than
        // divisor; so require that exactly one of these is true, i.e. sum of
        // bit expressions is equal to 1.
        cb.require_equal(
            || "remainder < divisor iff divisor nonzero",
            is_divisor_zero.expr() + is_remainder_lt_divisor.expr(),
            1.into(),
        )?;

        // TODO determine whether any optimizations are possible for getting
        // just one of quotient or remainder
        let rd_written_e = match I::INST_KIND {
            InsnKind::DIVU | InsnKind::DIV => quotient.register_expr(),
            InsnKind::REMU | InsnKind::REM => remainder.register_expr(),
            _ => unreachable!("Unsupported instruction kind"),
        };
        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            dividend.register_expr(),
            divisor.register_expr(),
            rd_written_e,
        )?;

        Ok(DivRemConfig {
            dividend,
            divisor,
            quotient,
            remainder,
            internal_config,
            is_divisor_zero,
            is_remainder_lt_divisor,
            r_insn,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // dividend = quotient * divisor + remainder
        let dividend = step.rs1().unwrap().value;
        let divisor = step.rs2().unwrap().value;

        let dividend_v = Value::new_unchecked(dividend);
        let divisor_v = Value::new_unchecked(divisor);

        let (quotient, remainder) = match &config.internal_config {
            InternalDivRem::Unsigned => (
                dividend.checked_div(divisor).unwrap_or(u32::MAX),
                dividend.checked_rem(divisor).unwrap_or(dividend),
            ),
            InternalDivRem::Signed { .. } => {
                let dividend = dividend as i32;
                let divisor = divisor as i32;

                let (quotient, remainder) = if divisor == 0 {
                    (-1i32, dividend)
                } else {
                    // these correctly handle signed division overflow
                    (
                        dividend.wrapping_div(divisor),
                        dividend.wrapping_rem(divisor),
                    )
                };

                (quotient as u32, remainder as u32)
            }
        };

        let quotient_v = Value::new(quotient, lkm);
        let remainder_v = Value::new(remainder, lkm);

        let (rem_pos, div_pos) = match &config.internal_config {
            InternalDivRem::Unsigned => (remainder, divisor),
            InternalDivRem::Signed {
                dividend_signed,
                divisor_signed,
                negative_division,
                is_dividend_max_negative,
                is_divisor_minus_one,
                is_signed_overflow,
                quotient_signed,
                remainder_signed,
                remainder_nonnegative,
            } => {
                let dividend = dividend as i32;
                let divisor = divisor as i32;
                let remainder = remainder as i32;

                dividend_signed.assign_instance(instance, lkm, &dividend_v)?;
                divisor_signed.assign_instance(instance, lkm, &divisor_v)?;

                let negative_division_b = (dividend < 0) ^ (divisor < 0);
                set_val!(instance, negative_division, negative_division_b as u64);

                is_dividend_max_negative.assign_instance(
                    instance,
                    (dividend as u32 as u64).into(),
                    (i32::MIN as u32 as u64).into(),
                )?;
                is_divisor_minus_one.assign_instance(
                    instance,
                    (divisor as u32 as u64).into(),
                    (-1i32 as u32 as u64).into(),
                )?;

                let signed_div_overflow_b = dividend == i32::MIN && divisor == -1i32;
                set_val!(instance, is_signed_overflow, signed_div_overflow_b as u64);

                quotient_signed.assign_instance(instance, lkm, &quotient_v)?;
                remainder_signed.assign_instance(instance, lkm, &remainder_v)?;

                let negate_if = |b: bool, x: i32| if b { -(x as i64) } else { x as i64 };
                // TODO check overflow
                let negate_if_32 = |b: bool, x: i32| if b { -x } else { x };

                let remainder_pos_orientation = negate_if_32(negative_division_b, remainder);
                let divisor_pos_orientation = negate_if(divisor < 0, divisor);

                remainder_nonnegative.assign_instance_signed(
                    instance,
                    lkm,
                    -1i32,
                    remainder_pos_orientation,
                )?;

                (
                    remainder_pos_orientation as u32,
                    divisor_pos_orientation as u32,
                )
            }
        };

        config.dividend.assign_value(instance, dividend_v);
        config.divisor.assign_value(instance, divisor_v);
        config.quotient.assign_value(instance, quotient_v);
        config.remainder.assign_value(instance, remainder_v);

        config
            .is_divisor_zero
            .assign_instance(instance, (divisor as u64).into())?;

        config.is_remainder_lt_divisor.assign_instance(
            instance,
            lkm,
            rem_pos as u64,
            div_pos as u64,
        )?;

        config.r_insn.assign_instance(instance, lkm, step)?;

        Ok(())
    }
}

// TODO Tests

#[cfg(test)]
mod test {

    mod divu {

        use ceno_emul::{Change, InsnKind, StepRecord, Word, encode_rv32};
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;
        use multilinear_extensions::mle::IntoMLEs;
        use rand::Rng;

        use crate::{
            Value,
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            instructions::{
                Instruction,
                riscv::{constants::UInt, div::DivuInstruction},
            },
            scheme::mock_prover::{MOCK_PC_START, MockProver},
        };

        fn verify(
            name: &'static str,
            dividend: Word,
            divisor: Word,
            exp_outcome: Word,
            is_ok: bool,
        ) {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(
                    || format!("divu_({name})"),
                    |cb| Ok(DivuInstruction::construct_circuit(cb)),
                )
                .unwrap()
                .unwrap();

            let outcome = if divisor == 0 {
                u32::MAX
            } else {
                dividend / divisor
            };

            let insn_code = encode_rv32(InsnKind::DIVU, 2, 3, 4, 0);
            // values assignment
            let (raw_witin, lkm) =
                DivuInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                    StepRecord::new_r_instruction(
                        3,
                        MOCK_PC_START,
                        insn_code,
                        dividend,
                        divisor,
                        Change::new(0, outcome),
                        0,
                    ),
                ])
                .unwrap();

            let expected_rd_written = UInt::from_const_unchecked(
                Value::new_unchecked(exp_outcome).as_u16_limbs().to_vec(),
            );

            config
                .quotient
                .require_equal(|| "assert_outcome", &mut cb, &expected_rd_written)
                .unwrap();

            let expected_errors: &[_] = if is_ok { &[] } else { &[name] };
            MockProver::assert_with_expected_errors(
                &cb,
                &raw_witin
                    .de_interleaving()
                    .into_mles()
                    .into_iter()
                    .map(|v| v.into())
                    .collect_vec(),
                &[insn_code],
                expected_errors,
                None,
                Some(lkm),
            );
        }
        #[test]
        fn test_opcode_divu() {
            verify("basic", 10, 2, 5, true);
            verify("dividend > divisor", 10, 11, 0, true);
            verify("remainder", 11, 2, 5, true);
            verify("u32::MAX", u32::MAX, u32::MAX, 1, true);
            verify("div u32::MAX", 3, u32::MAX, 0, true);
            verify("u32::MAX div by 2", u32::MAX, 2, u32::MAX / 2, true);
            verify("mul with carries", 1202729773, 171818539, 7, true);
            verify("div by zero", 10, 0, u32::MAX, true);
        }

        #[test]
        fn test_opcode_divu_unsatisfied() {
            verify("assert_outcome", 10, 2, 3, false);
        }

        #[test]
        fn test_opcode_divu_random() {
            let mut rng = rand::thread_rng();
            let a: u32 = rng.gen();
            let b: u32 = rng.gen_range(1..u32::MAX);
            verify("random", a, b, a / b, true);
        }
    }

    mod div {
        use crate::{
            Value,
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            instructions::{
                Instruction,
                riscv::{
                    constants::UInt,
                    div::{DivInstruction, DivuInstruction},
                },
            },
            scheme::mock_prover::{MOCK_PC_START, MockProver},
        };
        use ceno_emul::{Change, InsnKind, StepRecord, Word, encode_rv32};
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;
        use multilinear_extensions::mle::IntoMLEs;
        use rand::Rng;
        fn verify(name: &'static str, dividend: i32, divisor: i32, exp_outcome: i32, is_ok: bool) {
            let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = cb
                .namespace(
                    || format!("div_({name})"),
                    |cb| Ok(DivInstruction::construct_circuit(cb)),
                )
                .unwrap()
                .unwrap();
            let outcome = if divisor == 0 {
                -1i32
            } else if dividend == i32::MIN && divisor == -1 {
                i32::MAX
            } else {
                dividend / divisor
            };
            let insn_code = encode_rv32(InsnKind::DIV, 2, 3, 4, 0);
            // values assignment
            let (raw_witin, lkm) =
                DivInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                    StepRecord::new_r_instruction(
                        3,
                        MOCK_PC_START,
                        insn_code,
                        dividend as u32,
                        divisor as u32,
                        Change::new(0, outcome as u32),
                        0,
                    ),
                ])
                .unwrap();
            let expected_rd_written = UInt::from_const_unchecked(
                Value::new_unchecked(exp_outcome as u32)
                    .as_u16_limbs()
                    .to_vec(),
            );
            config
                .quotient
                .require_equal(|| "assert_outcome", &mut cb, &expected_rd_written)
                .unwrap();
            let expected_errors: &[_] = if is_ok { &[] } else { &[name] };
            MockProver::assert_with_expected_errors(
                &cb,
                &raw_witin
                    .de_interleaving()
                    .into_mles()
                    .into_iter()
                    .map(|v| v.into())
                    .collect_vec(),
                &[insn_code],
                expected_errors,
                None,
                Some(lkm),
            );
        }
        #[test]
        fn test_opcode_div() {
            verify("basic", 10, 2, 5, true);
            // verify("dividend < divisor", 10, 11, 0, true);
            // verify("remainder", 11, 2, 5, true);
            // verify("i32::MAX", i32::MAX, i32::MAX, 1, true);
            // verify("div u32::MAX", 3, i32::MAX, 0, true);
            // verify("i32::MAX div by 2", i32::MAX, 2, i32::MAX / 2, true);
            // verify("mul with carries", 1202729773, 171818539, 7, true);
            // verify("div by zero", 10, 0, -1, true);
        }
        #[test]
        fn test_opcode_div_unsatisfied() {
            verify("assert_outcome", 10, 2, 3, false);
        }
    }
}
