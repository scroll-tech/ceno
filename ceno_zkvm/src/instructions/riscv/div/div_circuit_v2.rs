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
use p3::{field::Field, goldilocks::Goldilocks};

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
use p3::field::FieldAlgebra;
use std::{array, marker::PhantomData};

pub struct DivRemConfig<E: ExtensionField> {
    pub(crate) dividend: UInt<E>, // rs1_read
    pub(crate) divisor: UInt<E>,  // rs2_read
    pub(crate) quotient: UInt<E>,
    pub(crate) remainder: UInt<E>,
    pub(crate) r_insn: RInstructionConfig<E>,

    dividend_sign: WitIn,
    divisor_sign: WitIn,
    quotient_sign: WitIn,
    remainder_zero: WitIn,
    divisor_zero: WitIn,
    divisor_sum_inv: WitIn,
    remainder_sum_inv: WitIn,
    sign_xor: WitIn,
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

        let dividend_expr = dividend.expr();
        let divisor_expr = divisor.expr();
        let quotient_expr = quotient.expr();
        let remainder_expr = remainder.expr();

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

        let dividend_sign = cb.create_witin(|| "dividend_sign".to_string());
        let divisor_sign = cb.create_witin(|| "divisor_sign".to_string());
        let dividend_ext: Expression<E> =
            dividend_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let divisor_ext: Expression<E> =
            divisor_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let carry_divide = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();
        let carry: [_; UINT_LIMBS] = array::from_fn(|i| cb.create_witin(|| format!("carry_{i}")));
        let mut carry_expr: [Expression<E>; UINT_LIMBS] =
            array::from_fn(|_| E::BaseField::ZERO.expr());

        for i in 0..UINT_LIMBS {
            let expected_limb = if i == 0 {
                E::BaseField::ZERO.expr()
            } else {
                carry_expr[i - 1].clone()
            } + (0..=i).fold(remainder_expr[i].expr(), |ac, k| {
                ac + (divisor_expr[k].clone() * quotient_expr[i - k].clone())
            });
            carry_expr[i] = carry_divide.expr() * (expected_limb - dividend_expr[i].clone());
        }
        for (i, (carry_expr, carry_witin)) in carry_expr.iter().zip(carry.iter()).enumerate() {
            cb.require_equal(
                || format!("carry_check_witin_{i}"),
                carry_expr.clone(),
                carry_witin.expr(),
            )?;
        }

        for (i, (quotient, carry)) in quotient_expr.iter().zip(carry.iter()).enumerate() {
            cb.assert_ux::<_, _, 16>(|| format!("range_check_quotient_{i}"), quotient.clone())?;
            cb.assert_ux::<_, _, 16>(|| format!("range_check_carry_{i}"), carry.expr())?;
        }

        let quotient_sign = cb.create_witin(|| "quotient_sign".to_string());
        let quotient_ext: Expression<E> =
            quotient_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let mut carry_ext: [Expression<E>; UINT_LIMBS] =
            array::from_fn(|_| E::BaseField::ZERO.expr());

        let remainder_zero = cb.create_witin(|| "remainder_zero".to_string());
        for j in 0..UINT_LIMBS {
            let expected_limb =
                if j == 0 {
                    carry_expr[UINT_LIMBS - 1].clone()
                } else {
                    carry_ext[j - 1].clone()
                } + ((j + 1)..UINT_LIMBS).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (divisor_expr[k].clone() * quotient_expr[UINT_LIMBS + j - k].clone())
                }) + (E::BaseField::ONE.expr() - remainder_zero.expr()) * dividend_ext.clone();
            carry_ext[j] = carry_divide.expr() * (expected_limb - dividend_ext.clone());
        }

        for (i, (remainder, carry_ext)) in quotient_expr.iter().zip(carry_ext.iter()).enumerate() {
            cb.assert_ux::<_, _, 16>(|| format!("range_check_remainder_{i}"), remainder.clone())?;
            cb.assert_ux::<_, _, 16>(|| format!("range_check_carry_ext_{i}"), carry_ext.clone())?;
        }

        let divisor_zero = cb.create_witin(|| "divisor_zero".to_string());
        cb.assert_bit(
            || "divisor_remainder_not_both_zero",
            divisor_zero.expr() + remainder_zero.expr(),
        )?;
        cb.assert_bit(|| "divisor_zero_bool", divisor_zero.expr())?;

        for (i, (divisor_expr, quotient_expr)) in
            divisor_expr.iter().zip(quotient_expr.iter()).enumerate()
        {
            cb.condition_require_zero(
                || format!("check_divisor_zero_{}", i),
                divisor_zero.expr(),
                divisor_expr.clone(),
            )?;
            cb.condition_require_zero(
                || format!("check_quotient_on_divisor_zero"),
                divisor_zero.expr(),
                quotient_expr.clone()
                    - E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr(),
            )?;
        }
        // divisor_sum is guaranteed to be non-zero if divisor is non-zero since we assume
        // each limb of divisor to be within [0, 2^LIMB_BITS) already.
        // To constrain that if divisor = 0 then divisor_zero = 1, we check that if divisor_zero = 0 then divisor_sum is non-zero using divisor_sum_inv.
        let divisor_sum_inv = cb.create_witin(|| "divisor_sum_inv".to_string());
        let divisor_sum: Expression<E> = divisor_expr
            .iter()
            .fold(E::BaseField::ZERO.expr(), |acc, d| acc + d.clone());
        let divisor_not_zero: Expression<E> = E::BaseField::ONE.expr() - divisor_zero.expr();
        cb.condition_require_zero(
            || "check_divisor_sum_inv",
            divisor_not_zero.clone(),
            divisor_sum.clone() * divisor_sum_inv.expr() - E::BaseField::ONE.expr(),
        )?;

        cb.assert_bit(|| "remainder_zero_bool", remainder_zero.expr())?;
        for (i, remainder_expr) in remainder_expr.iter().enumerate() {
            cb.condition_require_zero(
                || format!("check_divisor_zero_{}", i),
                remainder_zero.expr(),
                remainder_expr.clone(),
            )?;
        }
        let remainder_sum_inv = cb.create_witin(|| "remainder_sum_inv".to_string());
        let remainder_sum: Expression<E> = remainder_expr
            .iter()
            .fold(E::BaseField::ZERO.expr(), |acc, r| acc + r.clone());
        let divisor_remainder_not_zero: Expression<E> =
            E::BaseField::ONE.expr() - divisor_zero.expr() - remainder_zero.expr();
        cb.condition_require_zero(
            || "check_remainder_sum_inv",
            divisor_remainder_not_zero,
            remainder_sum.clone() * remainder_sum_inv.expr() - E::BaseField::ONE.expr(),
        )?;

        cb.assert_bit(|| "check_dividend_sign_bool", dividend_sign.expr())?;
        cb.assert_bit(|| "check_divisor_sign_bool", divisor_sign.expr())?;

        match I::INST_KIND {
            InsnKind::DIVU | InsnKind::REMU => {
                cb.require_zero(
                    || "divu_remu_sign_equal_zero",
                    dividend_sign.expr() + divisor_sign.expr(),
                )?;
            }
            _ => {}
        }

        let sign_xor = cb.create_witin(|| "sign_xor".to_string());
        cb.require_equal(
            || "sign_xor_zero",
            dividend_sign.expr() + divisor_sign.expr()
                - E::BaseField::from_canonical_u32(2).expr()
                    * dividend_sign.expr()
                    * divisor_sign.expr(),
            sign_xor.expr(),
        )?;

        let quotient_sum: Expression<E> = quotient_expr
            .iter()
            .fold(E::BaseField::ZERO.expr(), |acc, q| acc + q.clone());
        cb.assert_bit(|| "quotient_sign_bool", quotient_sign.expr())?;
        cb.condition_require_zero(
            || "check_quotient_sign_eq_xor",
            quotient_sum * divisor_not_zero.clone(),
            quotient_sign.expr() - sign_xor.expr(),
        )?;
        cb.condition_require_zero(
            || "check_quotient_sign_zero_when_not_eq_xor",
            (quotient_sign.expr() - sign_xor.expr()) * divisor_not_zero.clone(),
            quotient_sign.expr(),
        )?;

        let sign_mask = E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1));

        match I::INST_KIND {
            InsnKind::DIV | InsnKind::REM => {
                cb.require_zero(
                    || "divu_remu_sign_equal_zero",
                    dividend_sign.expr() + divisor_sign.expr(),
                )?;
            }
            _ => {}
        }

        match I::INST_KIND {
            InsnKind::DIV => {}
            InsnKind::DIVU => {}
            InsnKind::REM => {}
            InsnKind::REMU => {}
            _ => unreachable!("Unsupported instruction kind"),
        }

        Ok(DivRemConfig {
            dividend,
            divisor,
            quotient,
            remainder,
            r_insn,
            dividend_sign,
            divisor_sign,
            quotient_sign,
            remainder_zero,
            divisor_zero,
            divisor_sum_inv,
            remainder_sum_inv,
            sign_xor,
        })
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [E::BaseField],
        _lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // dividend = quotient * divisor + remainder
        let dividend = step.rs1().unwrap().value;
        let divisor = step.rs2().unwrap().value;

        let _dividend_v = Value::new_unchecked(dividend);
        let _divisor_v = Value::new_unchecked(divisor);

        Ok(())
    }
}
