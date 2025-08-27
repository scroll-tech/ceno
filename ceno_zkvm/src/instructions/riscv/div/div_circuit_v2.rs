/// refer constraints implementation from https://github.com/openvm-org/openvm/blob/main/extensions/rv32im/circuit/src/divrem/core.rs
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use p3::field::Field;

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
    remainder_inv: [WitIn; UINT_LIMBS],
    sign_xor: WitIn,
    remainder_prime: UInt<E>, // r'
    lt_marker: [WitIn; UINT_LIMBS],
    lt_diff: WitIn,
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
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(UInt::<E>::LIMB_BITS, 16);
        assert_eq!(UInt::<E>::NUM_LIMBS, 2);

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

        let dividend_sign = cb.create_bit(|| "dividend_sign".to_string())?;
        let divisor_sign = cb.create_bit(|| "divisor_sign".to_string())?;
        let dividend_ext: Expression<E> =
            dividend_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let divisor_ext: Expression<E> =
            divisor_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let carry_divide = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();
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

        for (i, carry) in carry_expr.iter().enumerate() {
            cb.assert_const_range(
                || format!("range_check_carry_{i}"),
                carry.clone(),
                // carry up to 16 + 2 = 18 bits
                LIMB_BITS + 2,
            )?;
        }

        let quotient_sign = cb.create_bit(|| "quotient_sign".to_string())?;
        let quotient_ext: Expression<E> =
            quotient_sign.expr() * E::BaseField::from_canonical_u32((1 << LIMB_BITS) - 1).expr();
        let mut carry_ext: [Expression<E>; UINT_LIMBS] =
            array::from_fn(|_| E::BaseField::ZERO.expr());

        let remainder_zero = cb.create_bit(|| "remainder_zero".to_string())?;
        for j in 0..UINT_LIMBS {
            let expected_limb =
                if j == 0 {
                    carry_expr[UINT_LIMBS - 1].clone()
                } else {
                    carry_ext[j - 1].clone()
                } + ((j + 1)..UINT_LIMBS).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (divisor_expr[k].clone() * quotient_expr[UINT_LIMBS + j - k].clone())
                }) + (0..(j + 1)).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (divisor_expr[k].clone() * quotient_ext.expr())
                        + (quotient_expr[k].clone() * divisor_ext.expr())
                }) + (E::BaseField::ONE.expr() - remainder_zero.expr()) * dividend_ext.clone();
            carry_ext[j] = carry_divide.expr() * (expected_limb - dividend_ext.clone());
        }

        for (i, carry_ext) in carry_ext.iter().enumerate() {
            cb.assert_const_range(
                || format!("range_check_carry_ext_{i}"),
                carry_ext.clone(),
                // carry up to 16 + 2 = 18 bits
                LIMB_BITS + 2,
            )?;
        }

        let divisor_zero = cb.create_bit(|| "divisor_zero".to_string())?;
        cb.assert_bit(
            || "divisor_remainder_not_both_zero",
            divisor_zero.expr() + remainder_zero.expr(),
        )?;

        for (i, (divisor_expr, quotient_expr)) in
            divisor_expr.iter().zip(quotient_expr.iter()).enumerate()
        {
            cb.condition_require_zero(
                || format!("check_divisor_zero_{}", i),
                divisor_zero.expr(),
                divisor_expr.clone(),
            )?;
            cb.condition_require_zero(
                || "check_quotient_on_divisor_zero".to_string(),
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
        cb.condition_require_one(
            || "check_divisor_sum_inv",
            divisor_not_zero.clone(),
            divisor_sum.clone() * divisor_sum_inv.expr(),
        )?;

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
        cb.condition_require_one(
            || "check_remainder_sum_inv",
            divisor_remainder_not_zero,
            remainder_sum.clone() * remainder_sum_inv.expr(),
        )?;

        // TODO: can directly define sign_xor as expr?
        // Tried once, it will cause degree too high (although increases just one).
        // So the current degree is already at the brink of maximal supported.
        // The high degree mostly comes from the carry expressions.
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

        let remainder_prime = UInt::<E>::new_unchecked(|| "remainder_prime", cb)?;
        let remainder_prime_expr = remainder_prime.expr();
        let mut carry_lt: [Expression<E>; UINT_LIMBS] =
            array::from_fn(|_| E::BaseField::ZERO.expr());
        let remainder_inv: [_; UINT_LIMBS] =
            array::from_fn(|i| cb.create_witin(|| format!("remainder_inv_{i}")));

        for i in 0..UINT_LIMBS {
            // When the signs of remainer (i.e., dividend) and divisor are the same, r_prime = r.
            cb.condition_require_zero(
                || "r_rp_equal_when_xor_zero",
                E::BaseField::ONE.expr() - sign_xor.expr(),
                remainder_expr[i].clone() - remainder_prime_expr[i].clone(),
            )?;

            // When the signs of remainder and divisor are different, r_prime = -r. To constrain this, we
            // first ensure each r[i] + r_prime[i] + carry[i - 1] is in {0, 2^LIMB_BITS}, and
            // that when the sum is 0 then r_prime[i] = 0 as well. Passing both constraints
            // implies that 0 <= r_prime[i] <= 2^LIMB_BITS, and in order to ensure r_prime[i] !=
            // 2^LIMB_BITS we check that r_prime[i] - 2^LIMB_BITS has an inverse in F.
            let last_carry = if i > 0 {
                carry_lt[i - 1].clone()
            } else {
                E::BaseField::ZERO.expr()
            };
            carry_lt[i] =
                (last_carry.clone() + remainder_expr[i].clone() + remainder_prime_expr[i].clone())
                    * carry_divide.expr();
            cb.condition_require_zero(
                || "check_carry_lt",
                sign_xor.expr(),
                (carry_lt[i].clone() - last_carry.clone())
                    * (carry_lt[i].clone() - E::BaseField::ONE.expr()),
            )?;
            cb.condition_require_zero(
                || "check_remainder_prime_not_max",
                sign_xor.expr(),
                (remainder_prime_expr[i].clone()
                    - E::BaseField::from_canonical_u32(1 << LIMB_BITS).expr())
                    * remainder_inv[i].expr()
                    - E::BaseField::ONE.expr(),
            )?;
            cb.condition_require_zero(
                || "check_remainder_prime_zero",
                sign_xor.expr() * (E::BaseField::ONE.expr() - carry_lt[i].clone()),
                remainder_prime_expr[i].clone(),
            )?;
        }

        let lt_marker: [_; UINT_LIMBS] = array::from_fn(|i| {
            cb.create_bit(|| format!("lt_marker_{i}"))
                .expect("create bit error")
        });
        let mut prefix_sum: Expression<E> = divisor_zero.expr() + remainder_zero.expr();
        let lt_diff = cb.create_witin(|| "lt_diff");

        for i in (0..UINT_LIMBS).rev() {
            let diff = remainder_prime_expr[i].clone()
                * (E::BaseField::from_canonical_u8(2).expr() * divisor_sign.expr()
                    - E::BaseField::ONE.expr())
                + divisor_expr[i].clone()
                    * (E::BaseField::ONE.expr()
                        - E::BaseField::from_canonical_u8(2).expr() * divisor_sign.expr());
            prefix_sum += lt_marker[i].expr();
            cb.require_zero(
                || "prefix_sum_not_zero_or_diff_zero",
                (E::BaseField::ONE.expr() - prefix_sum.clone()) * diff.clone(),
            )?;
            cb.condition_require_zero(
                || "check_lt_diff_equal_diff".to_string(),
                lt_marker[i].expr(),
                lt_diff.expr() - diff.clone(),
            )?;
        }

        // - If r_prime != divisor, then prefix_sum = 1 so marker[i] must be 1 iff i is the first index
        //   where diff != 0. Constrains that diff == lt_diff where lt_diff is non-zero.
        // - If r_prime == divisor, then prefix_sum = 0. Here, prefix_sum cannot be 1 because all diff are
        //   zero, making diff == lt_diff fails.
        cb.require_one(|| "prefix_sum_one", prefix_sum.clone())?;

        // When not special case (divisor = 0 or remainder = 0), ensure lt_diff
        // is not zero by a range check
        cb.assert_dynamic_range(
            || "lt_diff_nonzero",
            (lt_diff.expr() - E::BaseField::ONE.expr())
                * (E::BaseField::ONE.expr() - divisor_zero.expr() - remainder_zero.expr()),
            E::BaseField::from_canonical_u32(16).expr(),
        )?;

        match I::INST_KIND {
            InsnKind::DIV | InsnKind::REM => {
                cb.assert_dynamic_range(
                    || "div_rem_range_check_dividend_last",
                    E::BaseField::from_canonical_u32(2).expr()
                        * (dividend_expr[UINT_LIMBS - 1].clone()
                            - dividend_sign.expr() * sign_mask.expr()),
                    E::BaseField::from_canonical_u32(16).expr(),
                )?;
                cb.assert_dynamic_range(
                    || "div_rem_range_check_divisor_last",
                    E::BaseField::from_canonical_u32(2).expr()
                        * (divisor_expr[UINT_LIMBS - 1].clone()
                            - divisor_sign.expr() * sign_mask.expr()),
                    E::BaseField::from_canonical_u32(16).expr(),
                )?;
            }
            InsnKind::DIVU | InsnKind::REMU => {
                cb.require_zero(
                    || "divu_remu_sign_equal_zero",
                    dividend_sign.expr() + divisor_sign.expr(),
                )?;
            }
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
            remainder_inv,
            sign_xor,
            remainder_prime,
            lt_marker,
            lt_diff,
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
        let dividend_value = Value::new_unchecked(dividend);
        let dividend_limbs = dividend_value.as_u16_limbs();
        config.dividend.assign_limbs(instance, dividend_limbs);

        let divisor = step.rs2().unwrap().value;
        let divisor_value = Value::new_unchecked(divisor);
        let divisor_limbs = divisor_value.as_u16_limbs();
        config.divisor.assign_limbs(instance, divisor_limbs);

        // R-type instruction
        config.r_insn.assign_instance(instance, lkm, step)?;

        let (signed, _div) = match I::INST_KIND {
            InsnKind::DIV => (true, true),
            InsnKind::REM => (true, false),
            InsnKind::DIVU => (false, true),
            InsnKind::REMU => (false, false),
            _ => unreachable!("Unsupported instruction kind"),
        };

        let (quotient, remainder, dividend_sign, divisor_sign, quotient_sign, case) =
            run_divrem(signed, &u32_to_limbs(&dividend), &u32_to_limbs(&divisor));

        let quotient_val = Value::new(limbs_to_u32(&quotient), lkm);
        let remainder_val = Value::new(limbs_to_u32(&remainder), lkm);

        config
            .quotient
            .assign_limbs(instance, quotient_val.as_u16_limbs());
        config
            .remainder
            .assign_limbs(instance, remainder_val.as_u16_limbs());

        set_val!(instance, config.dividend_sign, dividend_sign as u64);
        set_val!(instance, config.divisor_sign, divisor_sign as u64);
        set_val!(instance, config.quotient_sign, quotient_sign as u64);
        set_val!(
            instance,
            config.divisor_zero,
            (case == DivRemCoreSpecialCase::ZeroDivisor) as u64
        );

        let carries = run_mul_carries(
            signed,
            &u32_to_limbs(&divisor),
            &quotient,
            &remainder,
            quotient_sign,
        );

        for i in 0..UINT_LIMBS {
            lkm.assert_dynamic_range(carries[i] as u64, LIMB_BITS as u64 + 2);
            lkm.assert_dynamic_range(carries[i + UINT_LIMBS] as u64, LIMB_BITS as u64 + 2);
        }

        let sign_xor = dividend_sign ^ divisor_sign;
        let remainder_prime = if sign_xor {
            negate(&remainder)
        } else {
            remainder
        };
        let remainder_zero =
            remainder.iter().all(|&v| v == 0) && case != DivRemCoreSpecialCase::ZeroDivisor;
        set_val!(instance, config.remainder_zero, remainder_zero as u64);

        if signed {
            let dividend_sign_mask = if dividend_sign {
                1 << (LIMB_BITS - 1)
            } else {
                0
            };
            let divisor_sign_mask = if divisor_sign {
                1 << (LIMB_BITS - 1)
            } else {
                0
            };
            lkm.assert_dynamic_range(
                (dividend_limbs[UINT_LIMBS - 1] as u64 - dividend_sign_mask) << 1,
                16,
            );
            lkm.assert_dynamic_range(
                (divisor_limbs[UINT_LIMBS - 1] as u64 - divisor_sign_mask) << 1,
                16,
            );
        }

        let divisor_sum_f = divisor_limbs.iter().fold(E::BaseField::ZERO, |acc, c| {
            acc + E::BaseField::from_canonical_u16(*c)
        });
        let divisor_sum_inv_f = divisor_sum_f.try_inverse().unwrap_or(E::BaseField::ZERO);

        let remainder_sum_f = remainder.iter().fold(E::BaseField::ZERO, |acc, r| {
            acc + E::BaseField::from_canonical_u32(*r)
        });
        let remainder_sum_inv_f = remainder_sum_f.try_inverse().unwrap_or(E::BaseField::ZERO);

        let (lt_diff_idx, lt_diff_val) = if case == DivRemCoreSpecialCase::None && !remainder_zero {
            let idx = run_sltu_diff_idx(&u32_to_limbs(&divisor), &remainder_prime, divisor_sign);
            let val = if divisor_sign {
                remainder_prime[idx] - divisor_limbs[idx] as u32
            } else {
                divisor_limbs[idx] as u32 - remainder_prime[idx]
            };
            lkm.assert_dynamic_range(val as u64 - 1, 16);
            (idx, val)
        } else {
            lkm.assert_dynamic_range(0, 16);
            (UINT_LIMBS, 0)
        };

        let remainder_prime_f = remainder_prime.map(E::BaseField::from_canonical_u32);

        set_val!(instance, config.divisor_sum_inv, divisor_sum_inv_f);
        set_val!(instance, config.remainder_sum_inv, remainder_sum_inv_f);
        for i in 0..UINT_LIMBS {
            set_val!(
                instance,
                config.remainder_inv[i],
                (remainder_prime_f[i] - E::BaseField::from_canonical_u32(1 << LIMB_BITS)).inverse()
            );
            set_val!(instance, config.lt_marker[i], (i == lt_diff_idx) as u64);
        }
        set_val!(instance, config.sign_xor, sign_xor as u64);
        config.remainder_prime.assign_limbs(
            instance,
            remainder_prime
                .iter()
                .map(|x| *x as u16)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        set_val!(instance, config.lt_diff, lt_diff_val as u64);

        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum DivRemCoreSpecialCase {
    None,
    ZeroDivisor,
    SignedOverflow,
}

// Returns (quotient, remainder, x_sign, y_sign, q_sign, case) where case = 0 for normal, 1
// for zero divisor, and 2 for signed overflow
pub(super) fn run_divrem(
    signed: bool,
    x: &[u32; UINT_LIMBS],
    y: &[u32; UINT_LIMBS],
) -> (
    [u32; UINT_LIMBS],
    [u32; UINT_LIMBS],
    bool,
    bool,
    bool,
    DivRemCoreSpecialCase,
) {
    let x_sign = signed && (x[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1);
    let y_sign = signed && (y[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1);
    let max_limb = (1 << LIMB_BITS) - 1;

    let zero_divisor = y.iter().all(|val| *val == 0);
    let overflow = x[UINT_LIMBS - 1] == 1 << (LIMB_BITS - 1)
        && x[..(UINT_LIMBS - 1)].iter().all(|val| *val == 0)
        && y.iter().all(|val| *val == max_limb)
        && x_sign
        && y_sign;

    if zero_divisor {
        return (
            [max_limb; UINT_LIMBS],
            *x,
            x_sign,
            y_sign,
            signed,
            DivRemCoreSpecialCase::ZeroDivisor,
        );
    } else if overflow {
        return (
            *x,
            [0; UINT_LIMBS],
            x_sign,
            y_sign,
            false,
            DivRemCoreSpecialCase::SignedOverflow,
        );
    }

    let x_abs = if x_sign { negate(x) } else { *x };
    let y_abs = if y_sign { negate(y) } else { *y };

    let x_big = limbs_to_u32(&x_abs);
    let y_big = limbs_to_u32(&y_abs);
    let q_big = x_big / y_big;
    let r_big = x_big % y_big;

    let q = if x_sign ^ y_sign {
        negate(&u32_to_limbs(&q_big))
    } else {
        u32_to_limbs(&q_big)
    };
    let q_sign = signed && (q[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1);

    // In C |q * y| <= |x|, which means if x is negative then r <= 0 and vice versa.
    let r = if x_sign {
        negate(&u32_to_limbs(&r_big))
    } else {
        u32_to_limbs(&r_big)
    };

    (q, r, x_sign, y_sign, q_sign, DivRemCoreSpecialCase::None)
}

pub(super) fn run_sltu_diff_idx(x: &[u32; UINT_LIMBS], y: &[u32; UINT_LIMBS], cmp: bool) -> usize {
    for i in (0..UINT_LIMBS).rev() {
        if x[i] != y[i] {
            assert!((x[i] < y[i]) == cmp);
            return i;
        }
    }
    assert!(!cmp);
    UINT_LIMBS
}

// returns carries of d * q + r
pub(super) fn run_mul_carries(
    signed: bool,
    d: &[u32; UINT_LIMBS],
    q: &[u32; UINT_LIMBS],
    r: &[u32; UINT_LIMBS],
    q_sign: bool,
) -> Vec<u32> {
    let mut carry = vec![0u32; 2 * UINT_LIMBS];
    for i in 0..UINT_LIMBS {
        let mut val: u64 = r[i] as u64 + if i > 0 { carry[i - 1] } else { 0 } as u64;
        for j in 0..=i {
            val += d[j] as u64 * q[i - j] as u64;
        }
        carry[i] = (val >> LIMB_BITS) as u32;
    }

    let q_ext = if q_sign && signed {
        (1 << LIMB_BITS) - 1
    } else {
        0
    };
    let d_ext =
        (d[UINT_LIMBS - 1] >> (LIMB_BITS - 1)) * if signed { (1 << LIMB_BITS) - 1 } else { 0 };
    let r_ext =
        (r[UINT_LIMBS - 1] >> (LIMB_BITS - 1)) * if signed { (1 << LIMB_BITS) - 1 } else { 0 };
    let mut d_prefix = 0;
    let mut q_prefix = 0;

    for i in 0..UINT_LIMBS {
        d_prefix += d[i];
        q_prefix += q[i];
        let mut val: u64 = carry[UINT_LIMBS + i - 1] as u64
            + (d_prefix as u64 * q_ext as u64)
            + (q_prefix as u64 * d_ext as u64)
            + r_ext as u64;
        for j in (i + 1)..UINT_LIMBS {
            val += d[j] as u64 * q[UINT_LIMBS + i - j] as u64;
        }
        carry[UINT_LIMBS + i] = (val >> LIMB_BITS) as u32;
    }
    carry
}

fn limbs_to_u32(x: &[u32; UINT_LIMBS]) -> u32 {
    let base = 1 << LIMB_BITS;
    let mut res = 0;
    for val in x.iter().rev() {
        res *= base;
        res += *val;
    }
    res
}

fn u32_to_limbs(x: &u32) -> [u32; UINT_LIMBS] {
    let mut res = [0; UINT_LIMBS];
    let mut x = *x;
    let base = 1u32 << LIMB_BITS;
    for limb in res.iter_mut() {
        let (quot, rem) = (x / base, x % base);
        *limb = rem;
        x = quot;
    }
    debug_assert_eq!(x, 0u32);
    res
}

fn negate(x: &[u32; UINT_LIMBS]) -> [u32; UINT_LIMBS] {
    let mut carry = 1;
    array::from_fn(|i| {
        let val = (1 << LIMB_BITS) + carry - 1 - x[i];
        carry = val >> LIMB_BITS;
        val % (1 << LIMB_BITS)
    })
}
