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
//! ambiguity due to modular field arithmetic -- more specifically, `dividend`
//! and `divisor` are taken from RISC-V registers, so are constrained to 32-bit
//! unsigned or signed values, and `quotient` and `remainder` values are
//! explicitly constrained to 32 bits by the checked UInt construction.
//!
//! The remainder of the complexity of this circuit comes about because of two
//! edge cases in the opcodes: division by zero, and signed division overflow.
//! For division by zero, equation (1) still holds, but an extra constraint is
//! imposed on the value of `quotient` to be `u32::MAX` in the unsigned case,
//! or `-1` in the signed case (the 32-bit vector with all 1s for both).
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
//! For signed inputs the situation is slightly more complicated, as `remainder`
//! and `divisor` may be either positive or negative.  To handle sign
//! variations for the remainder inequality in a uniform manner, we derive
//! expressions representing the "positively oriented" values with signs set so
//! that the inequalities are always of the form (3).  The correct sign
//! normalization is to take the absolute value of `divisor`, and to multiply
//! `remainder` by the sign of `dividend` since these two values are required
//! to have matching signs.
//!
//! For the special case of signed division overflow, the inequality condition
//! (3) still holds for the remainder and divisor after normalizing signs in
//! this way (specifically: `0 <= 0 < 1`), so no special treatment is needed.
//! In the division by 0 case, since `divisor` is `0`, the inequality cannot be
//! satisfied.  To address this case, we require that exactly one of `remainder
//! < divisor` and `divisor = 0` holds. Specifically, since these conditions
//! are expressed as 0/1-valued booleans, we require just that the sum of these
//! booleans is equal to 1.

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto, SmallField};
use p3::goldilocks::Goldilocks;

use super::{
    super::{
        constants::{UINT_LIMBS, UInt},
        r_insn::RInstructionConfig,
    },
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::{AssertLtConfig, IsEqualConfig, IsLtConfig, IsZeroConfig, Signed},
    instructions::{Instruction, riscv::constants::LIMB_BITS},
    structs::ProgramParams,
    uint::Value,
    witness::{LkMultiplicity, set_val},
};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use std::marker::PhantomData;

pub struct DivRemConfig<E: ExtensionField> {
    pub(crate) dividend: UInt<E>, // rs1_read
    pub(crate) divisor: UInt<E>,  // rs2_read
    pub(crate) quotient: UInt<E>,
    pub(crate) remainder: UInt<E>,

    internal_config: InternalDivRem<E>,

    pub(crate) is_divisor_zero: IsZeroConfig,
    pub(crate) is_remainder_lt_divisor: IsLtConfig,

    pub(crate) r_insn: RInstructionConfig<E>,
}

enum InternalDivRem<E: ExtensionField> {
    Unsigned,
    Signed {
        dividend_signed: Signed<E>,
        divisor_signed: Signed<E>,
        quotient_signed: Signed<E>,
        remainder_signed: Signed<E>,
        is_dividend_signed_min: IsEqualConfig,
        is_divisor_neg_one: IsEqualConfig,
        is_signed_overflow: WitIn,
        remainder_nonnegative: Box<AssertLtConfig>,
    },
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = DivRemConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // The soundness analysis for these constraints is only valid for
        // 32-bit registers represented over the Goldilocks field, so verify
        // these parameters
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(E::BaseField::MODULUS_U64, Goldilocks::MODULUS_U64);

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

                // Check for signed division overflow: i32::MIN / -1
                let is_dividend_signed_min = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_dividend_signed_min",
                    dividend.value(),
                    (i32::MIN as u32).into(),
                )?;
                let is_divisor_neg_one = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_divisor_neg_one",
                    divisor.value(),
                    (-1i32 as u32).into(),
                )?;
                let is_signed_overflow = cb.flatten_expr(
                    || "signed_division_overflow",
                    is_dividend_signed_min.expr() * is_divisor_neg_one.expr(),
                )?;

                // For signed division overflow, dividend = -2^31 and divisor
                // = -1, so that quotient = 2^31 would be required for proper
                // arithmetic, which is too large to represent in a 32-bit
                // register.  This case is therefore handled specially in the
                // spec, setting quotient and remainder to -2^31 and 0
                // respectively.  These values are assured by the constraints
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

                // Check the required inequalities for the signed remainder.
                // Change the signs of `remainder_signed` and `divisor_signed`
                // so that the inequality matches the usual unsigned one: `0 <=
                // remainder < divisor`
                let remainder_pos_orientation: Expression<E> =
                    (1 - 2 * dividend_signed.is_negative.expr()) * remainder_signed.expr();
                let divisor_pos_orientation =
                    (1 - 2 * divisor_signed.is_negative.expr()) * divisor_signed.expr();

                let remainder_nonnegative = AssertLtConfig::construct_circuit(
                    cb,
                    || "oriented_remainder_nonnegative",
                    (-1i32).into(),
                    remainder_pos_orientation.clone(),
                    UINT_LIMBS * LIMB_BITS,
                )?;

                (
                    InternalDivRem::Signed {
                        dividend_signed,
                        divisor_signed,
                        quotient_signed,
                        remainder_signed,
                        is_dividend_signed_min,
                        is_divisor_neg_one,
                        is_signed_overflow,
                        remainder_nonnegative: Box::new(remainder_nonnegative),
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

        // Check whether the remainder is less than the divisor, where both
        // values have sign normalized to be nonnegative (for correct values)
        // in the signed case
        let is_remainder_lt_divisor = IsLtConfig::construct_circuit(
            cb,
            || "is_remainder_lt_divisor",
            rem_e,
            div_e,
            UINT_LIMBS * LIMB_BITS,
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
        instance: &mut [E::BaseField],
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
                    // i32::MIN / 0 => remainder == i32::MIN
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
                is_dividend_signed_min,
                is_divisor_neg_one,
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

                is_dividend_signed_min.assign_instance(
                    instance,
                    (dividend as u32 as u64).into_f(),
                    (i32::MIN as u32 as u64).into_f(),
                )?;
                is_divisor_neg_one.assign_instance(
                    instance,
                    (divisor as u32 as u64).into_f(),
                    (-1i32 as u32 as u64).into_f(),
                )?;

                let signed_div_overflow_b = dividend == i32::MIN && divisor == -1i32;
                set_val!(instance, is_signed_overflow, signed_div_overflow_b as u64);

                quotient_signed.assign_instance(instance, lkm, &quotient_v)?;
                remainder_signed.assign_instance(instance, lkm, &remainder_v)?;

                let negate_if = |b: bool, x: i32| if b { -(x as i64) } else { x as i64 };

                let remainder_pos_orientation = negate_if(dividend < 0, remainder);
                let divisor_pos_orientation = negate_if(divisor < 0, divisor);

                remainder_nonnegative.assign_instance_signed(
                    instance,
                    lkm,
                    -1,
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
            .assign_instance(instance, (divisor as u64).into_f())?;

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
