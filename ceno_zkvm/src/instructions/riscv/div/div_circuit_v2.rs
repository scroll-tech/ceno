//! Byte-limb (u8) DIV / DIVU / REM / REMU circuit.
//!
//! The Euclidean identity `dividend = divisor * quotient + remainder` is
//! enforced over byte limbs with carries that are *genuine non-negative
//! magnitudes* (directly range-checked), exactly as in the byte multiply
//! circuit. This is sound over a small prime field (BabyBear, `p ~ 2^31`)
//! because every partial product `b[i]*c[j] <= 255^2` and column sum stays far
//! below `p`, so the field equation is a faithful integer equation.
//!
//! Operands are sign- or zero-extended to 64 bits; the product `divisor *
//! quotient` is computed to 64 bits and added to the (extended) remainder, and
//! the result is compared to the (extended) dividend. The remainder bound
//! `|remainder| < |divisor|` is enforced with a field-safe per-byte comparison
//! (not a single 32-bit field subtraction, which would be unsound on BabyBear).
//! Division-by-zero pins `remainder == dividend` (via the sound identity) and
//! `quotient == 0xFFFF_FFFF`; signed overflow (`i32::MIN / -1`) pins
//! `quotient == dividend`, `remainder == 0`.

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use p3::field::{Field, FieldAlgebra};

use super::{
    super::{
        constants::{UINT_BYTE_LIMBS, UInt8},
        r_insn::RInstructionConfig,
    },
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::SignedExtendConfig,
    impl_collect_lk_and_shardram, impl_collect_shardram, impl_gpu_assign,
    instructions::{
        Instruction,
        gpu::utils::{LkOp, LkShardramSink, emit_byte_decomposition_ops},
    },
    structs::ProgramParams,
    utils::split_to_u8,
    witness::{LkMultiplicity, set_val},
};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use std::{array, marker::PhantomData};

/// Number of bytes in the (sign/zero-extended) 64-bit operands and product.
const LONG_BYTES: usize = 2 * UINT_BYTE_LIMBS;
/// Bits used to range-check each product byte-column carry. Honest carry is at
/// most `~8 * 255^2 / 256 ~ 2040 < 2^16`, and the column sums stay far below the
/// field modulus, so a 16-bit bound admits the honest witness while preventing
/// any field wraparound that could create a second solution.
const CARRY_BITS: usize = 16;
const BYTE_MASK: u64 = 0xff;

pub struct DivRemConfig<E: ExtensionField> {
    pub(crate) dividend: UInt8<E>, // rs1_read
    pub(crate) divisor: UInt8<E>,  // rs2_read
    pub(crate) quotient: UInt8<E>,
    pub(crate) remainder: UInt8<E>,
    pub(crate) r_insn: RInstructionConfig<E>,

    // Sign bits (signed opcodes only).
    pub(crate) dividend_sign: Option<SignedExtendConfig<E>>,
    pub(crate) divisor_sign: Option<SignedExtendConfig<E>>,
    pub(crate) quotient_sign: Option<SignedExtendConfig<E>>,
    pub(crate) remainder_sign: Option<SignedExtendConfig<E>>,

    // `divisor * quotient` byte product and its column carries.
    pub(crate) prod: [WitIn; LONG_BYTES],
    pub(crate) prod_carry: [WitIn; LONG_BYTES],
    // Carries of `prod + remainder == dividend` (64-bit, byte add).
    pub(crate) add_carry: [WitIn; LONG_BYTES],

    // Division-by-zero detection.
    pub(crate) divisor_zero: WitIn,
    pub(crate) divisor_sum_inv: WitIn,
    // Whether remainder is non-zero (for the sign rule); signed opcodes only.
    pub(crate) remainder_sum_inv: WitIn,
    pub(crate) remainder_is_zero: Option<WitIn>,
    // Signed overflow (i32::MIN / -1); signed opcodes only.
    pub(crate) is_overflow: Option<WitIn>,

    // Absolute values |divisor|, |remainder| and their negation carries.
    pub(crate) abs_divisor: [WitIn; UINT_BYTE_LIMBS],
    pub(crate) abs_divisor_carry: [WitIn; UINT_BYTE_LIMBS],
    pub(crate) abs_remainder: [WitIn; UINT_BYTE_LIMBS],
    pub(crate) abs_remainder_carry: [WitIn; UINT_BYTE_LIMBS],

    // `|remainder| < |divisor|` per-byte comparison witnesses.
    pub(crate) lt_marker: [WitIn; UINT_BYTE_LIMBS],
    pub(crate) lt_diff: WitIn,

    phantom: PhantomData<E>,
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

/// `(signed, is_div)` for the opcode.
const fn op_kind(kind: InsnKind) -> (bool, bool) {
    match kind {
        InsnKind::DIV => (true, true),
        InsnKind::REM => (true, false),
        InsnKind::DIVU => (false, true),
        InsnKind::REMU => (false, false),
        _ => panic!("unsupported instruction kind"),
    }
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = DivRemConfig<E>;
    type InsnType = InsnKind;

    const GPU_LK_SHARDRAM: bool = true;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[I::INST_KIND]
    }

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let (signed, is_div) = op_kind(I::INST_KIND);

        let dividend = UInt8::new(|| "dividend", cb)?;
        let divisor = UInt8::new(|| "divisor", cb)?;
        let quotient = UInt8::new(|| "quotient", cb)?;
        let remainder = UInt8::new(|| "remainder", cb)?;

        let rd_written_e = if is_div {
            quotient.register_expr()
        } else {
            remainder.register_expr()
        };
        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            dividend.register_expr(),
            divisor.register_expr(),
            rd_written_e,
        )?;

        // Sign bits of the most-significant byte for signed opcodes.
        let (dividend_sign, divisor_sign, quotient_sign, remainder_sign) = if signed {
            (
                Some(SignedExtendConfig::construct_byte(
                    cb,
                    dividend.expr()[UINT_BYTE_LIMBS - 1].clone(),
                )?),
                Some(SignedExtendConfig::construct_byte(
                    cb,
                    divisor.expr()[UINT_BYTE_LIMBS - 1].clone(),
                )?),
                Some(SignedExtendConfig::construct_byte(
                    cb,
                    quotient.expr()[UINT_BYTE_LIMBS - 1].clone(),
                )?),
                Some(SignedExtendConfig::construct_byte(
                    cb,
                    remainder.expr()[UINT_BYTE_LIMBS - 1].clone(),
                )?),
            )
        } else {
            (None, None, None, None)
        };

        let sign_expr = |s: &Option<SignedExtendConfig<E>>| match s {
            Some(c) => c.expr(),
            None => Expression::ZERO,
        };
        let byte_mask: Expression<E> = BYTE_MASK.into();
        let extend =
            |reg: &[Expression<E>], sign: &Option<SignedExtendConfig<E>>| -> Vec<Expression<E>> {
                (0..LONG_BYTES)
                    .map(|i| {
                        if i < UINT_BYTE_LIMBS {
                            reg[i].clone()
                        } else {
                            sign_expr(sign) * byte_mask.clone()
                        }
                    })
                    .collect()
            };

        let c_ext = extend(&divisor.expr(), &divisor_sign);
        let q_ext = extend(&quotient.expr(), &quotient_sign);
        let r_ext = extend(&remainder.expr(), &remainder_sign);
        let b_ext = extend(&dividend.expr(), &dividend_sign);

        // ---- product P = divisor * quotient (low 64 bits) ----
        let prod: [WitIn; LONG_BYTES] = array::from_fn(|i| cb.create_witin(|| format!("prod_{i}")));
        for (i, pair) in prod.chunks(2).enumerate() {
            cb.assert_double_u8(|| format!("prod_{i}_u8"), pair[0].expr(), pair[1].expr())?;
        }
        let prod_carry: [WitIn; LONG_BYTES] =
            array::from_fn(|i| cb.create_witin(|| format!("prod_carry_{i}")));
        let base: Expression<E> = (1u64 << 8).into();
        for i in 0..LONG_BYTES {
            let mut m = Expression::ZERO;
            for j in 0..=i {
                if i - j < LONG_BYTES {
                    m += c_ext[j].clone() * q_ext[i - j].clone();
                }
            }
            let carry_in = if i > 0 {
                prod_carry[i - 1].expr()
            } else {
                Expression::ZERO
            };
            cb.require_zero(
                || format!("prod_byte_{i}"),
                m + carry_in - prod[i].expr() - prod_carry[i].expr() * base.clone(),
            )?;
            cb.assert_const_range(
                || format!("prod_carry_{i}_range"),
                prod_carry[i].expr(),
                CARRY_BITS,
            )?;
        }

        // ---- signed overflow detection (i32::MIN / -1) ----
        let is_overflow = if signed {
            let ov = cb.create_bit(|| "is_overflow")?;
            // When overflow: dividend == 0x8000_0000 and divisor == 0xFFFF_FFFF.
            let dividend_expr = dividend.expr();
            let divisor_expr = divisor.expr();
            let min_bytes = [0u64, 0, 0, 0x80];
            for i in 0..UINT_BYTE_LIMBS {
                cb.condition_require_zero(
                    || format!("overflow_dividend_{i}"),
                    ov.expr(),
                    dividend_expr[i].clone() - Expression::from(min_bytes[i]),
                )?;
                cb.condition_require_zero(
                    || format!("overflow_divisor_{i}"),
                    ov.expr(),
                    divisor_expr[i].clone() - byte_mask.clone(),
                )?;
            }
            Some(ov)
        } else {
            None
        };
        let not_overflow = match &is_overflow {
            Some(ov) => Expression::ONE - ov.expr(),
            None => Expression::ONE,
        };

        // ---- identity: prod + remainder == dividend (64-bit), unless overflow ----
        let add_carry: [WitIn; LONG_BYTES] =
            array::from_fn(|i| cb.create_witin(|| format!("add_carry_{i}")));
        for i in 0..LONG_BYTES {
            let carry_in = if i > 0 {
                add_carry[i - 1].expr()
            } else {
                Expression::ZERO
            };
            // prod[i] + r_ext[i] + carry_in - b_ext[i] - add_carry[i] * 2^8 == 0
            let add_expr = prod[i].expr() + r_ext[i].clone() + carry_in
                - b_ext[i].clone()
                - add_carry[i].expr() * base.clone();
            cb.condition_require_zero(|| format!("add_byte_{i}"), not_overflow.clone(), add_expr)?;
            // add carry is a single bit (sum of two bytes + carry < 2^9).
            cb.assert_bit(|| format!("add_carry_{i}_bit"), add_carry[i].expr())?;
        }

        // ---- division-by-zero: divisor == 0 ----
        let divisor_zero = cb.create_bit(|| "divisor_zero")?;
        let divisor_expr = divisor.expr();
        let divisor_sum: Expression<E> = divisor_expr
            .iter()
            .fold(Expression::ZERO, |acc, d| acc + d.clone());
        // if divisor_zero then every divisor byte is zero
        for (i, d) in divisor_expr.iter().enumerate() {
            cb.condition_require_zero(
                || format!("divisor_zero_byte_{i}"),
                divisor_zero.expr(),
                d.clone(),
            )?;
        }
        // if not divisor_zero then divisor_sum is invertible (non-zero)
        let divisor_sum_inv = cb.create_witin(|| "divisor_sum_inv");
        cb.condition_require_one(
            || "divisor_sum_inv",
            Expression::ONE - divisor_zero.expr(),
            divisor_sum.clone() * divisor_sum_inv.expr(),
        )?;
        // when divisor is zero, quotient must be all ones (0xFFFF_FFFF = -1 / 2^32-1)
        let quotient_expr = quotient.expr();
        for (i, q) in quotient_expr.iter().enumerate() {
            cb.condition_require_zero(
                || format!("quotient_zero_div_{i}"),
                divisor_zero.expr(),
                q.clone() - byte_mask.clone(),
            )?;
        }

        // ---- signed overflow result pins: quotient == dividend, remainder == 0 ----
        if let Some(ov) = &is_overflow {
            let dividend_expr = dividend.expr();
            let quotient_expr = quotient.expr();
            let remainder_expr = remainder.expr();
            for i in 0..UINT_BYTE_LIMBS {
                cb.condition_require_zero(
                    || format!("overflow_quotient_{i}"),
                    ov.expr(),
                    quotient_expr[i].clone() - dividend_expr[i].clone(),
                )?;
                cb.condition_require_zero(
                    || format!("overflow_remainder_{i}"),
                    ov.expr(),
                    remainder_expr[i].clone(),
                )?;
            }
        }

        // ---- remainder sign rule: sign(remainder) == sign(dividend) when r != 0 ----
        let remainder_expr = remainder.expr();
        let remainder_sum: Expression<E> = remainder_expr
            .iter()
            .fold(Expression::ZERO, |acc, r| acc + r.clone());
        let remainder_sum_inv = cb.create_witin(|| "remainder_sum_inv");
        let remainder_is_zero = if signed {
            // is_zero == 1 iff remainder == 0, via the standard inverse gadget:
            //   is_zero * sum == 0   and   is_zero + sum * inv == 1
            let is_zero = cb.create_witin(|| "remainder_is_zero");
            cb.require_zero(
                || "remainder_is_zero_mul",
                is_zero.expr() * remainder_sum.clone(),
            )?;
            cb.require_zero(
                || "remainder_is_zero_inv",
                is_zero.expr() + remainder_sum.clone() * remainder_sum_inv.expr() - Expression::ONE,
            )?;
            // when remainder != 0, sign(remainder) must equal sign(dividend)
            let r_sign = sign_expr(&remainder_sign);
            let b_sign = sign_expr(&dividend_sign);
            cb.require_zero(
                || "remainder_sign_matches_dividend",
                (Expression::ONE - is_zero.expr()) * (b_sign - r_sign),
            )?;
            Some(is_zero)
        } else {
            None
        };

        // ---- absolute values |divisor|, |remainder| ----
        let (abs_divisor, abs_divisor_carry) =
            constrain_abs(cb, "abs_divisor", &divisor.expr(), &divisor_sign, &base)?;
        let (abs_remainder, abs_remainder_carry) = constrain_abs(
            cb,
            "abs_remainder",
            &remainder.expr(),
            &remainder_sign,
            &base,
        )?;

        // ---- remainder bound: |remainder| < |divisor| (skipped when divisor == 0) ----
        let lt_marker: [WitIn; UINT_BYTE_LIMBS] =
            array::from_fn(|i| cb.create_bit(|| format!("lt_marker_{i}")).expect("bit"));
        let lt_diff = cb.create_witin(|| "lt_diff");
        let mut prefix_sum = divisor_zero.expr();
        for i in (0..UINT_BYTE_LIMBS).rev() {
            // diff = |divisor|[i] - |remainder|[i]; positive at the most-significant
            // differing byte means |remainder| < |divisor|.
            let diff = abs_divisor[i].expr() - abs_remainder[i].expr();
            prefix_sum += lt_marker[i].expr();
            cb.require_zero(
                || format!("lt_prefix_{i}"),
                (Expression::ONE - prefix_sum.clone()) * diff.clone(),
            )?;
            cb.condition_require_zero(
                || format!("lt_diff_eq_{i}"),
                lt_marker[i].expr(),
                lt_diff.expr() - diff,
            )?;
        }
        // exactly one marker set, unless divisor is zero
        cb.require_one(|| "lt_prefix_one", prefix_sum)?;
        // when divisor != 0, the selected diff must be in [1, 256): range-check diff-1 to 8 bits.
        cb.assert_dynamic_range(
            || "lt_diff_positive",
            (lt_diff.expr() - Expression::ONE) * (Expression::ONE - divisor_zero.expr()),
            E::BaseField::from_canonical_u32(8).expr(),
        )?;

        Ok(DivRemConfig {
            dividend,
            divisor,
            quotient,
            remainder,
            r_insn,
            dividend_sign,
            divisor_sign,
            quotient_sign,
            remainder_sign,
            prod,
            prod_carry,
            add_carry,
            divisor_zero,
            divisor_sum_inv,
            remainder_sum_inv,
            remainder_is_zero,
            is_overflow,
            abs_divisor,
            abs_divisor_carry,
            abs_remainder,
            abs_remainder_carry,
            lt_marker,
            lt_diff,
            phantom: PhantomData,
        })
    }

    impl_gpu_assign!(match I::INST_KIND {
        InsnKind::DIV => Some(dispatch::GpuWitgenKind::Div(0u32)),
        InsnKind::DIVU => Some(dispatch::GpuWitgenKind::Div(1u32)),
        InsnKind::REM => Some(dispatch::GpuWitgenKind::Div(2u32)),
        InsnKind::REMU => Some(dispatch::GpuWitgenKind::Div(3u32)),
        _ => None,
    });

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let (signed, _is_div) = op_kind(I::INST_KIND);
        let dividend = step.rs1().unwrap().value;
        let divisor = step.rs2().unwrap().value;

        let w = compute_divrem(signed, dividend, divisor);
        let quotient = w.quotient;
        let remainder = w.remainder;

        // operand byte assignment + u8 range lookups
        let dividend_bytes = split_to_u8::<u16>(dividend);
        let divisor_bytes = split_to_u8::<u16>(divisor);
        let quotient_bytes = split_to_u8::<u16>(quotient);
        let remainder_bytes = split_to_u8::<u16>(remainder);
        config.dividend.assign_limbs(instance, &dividend_bytes);
        config.divisor.assign_limbs(instance, &divisor_bytes);
        config.quotient.assign_limbs(instance, &quotient_bytes);
        config.remainder.assign_limbs(instance, &remainder_bytes);
        for bytes in [
            &dividend_bytes,
            &divisor_bytes,
            &quotient_bytes,
            &remainder_bytes,
        ] {
            for pair in bytes.chunks(2) {
                lkm.assert_double_u8(pair[0] as u64, pair[1] as u64);
            }
        }

        config
            .r_insn
            .assign_instance(instance, shard_ctx, lkm, step)?;

        // signs
        for (cfg, val) in [
            (&config.dividend_sign, dividend),
            (&config.divisor_sign, divisor),
            (&config.quotient_sign, quotient),
            (&config.remainder_sign, remainder),
        ] {
            if let Some(s) = cfg {
                s.assign_instance(instance, lkm, ((val >> 24) & 0xff) as u64)?;
            }
        }

        // product bytes + carries
        for (i, (p, c)) in config.prod.iter().zip(config.prod_carry.iter()).enumerate() {
            set_val!(instance, p, w.prod[i] as u64);
            set_val!(instance, c, w.prod_carry[i] as u64);
            lkm.assert_const_range(w.prod_carry[i] as u64, CARRY_BITS);
        }
        for pair in w.prod.chunks(2) {
            lkm.assert_double_u8(pair[0] as u64, pair[1] as u64);
        }

        // add carries
        for (i, ac) in config.add_carry.iter().enumerate() {
            set_val!(instance, ac, w.add_carry[i] as u64);
        }

        // divisor zero
        set_val!(instance, config.divisor_zero, w.divisor_zero as u64);
        let divisor_sum_f = divisor_bytes.iter().fold(E::BaseField::ZERO, |acc, b| {
            acc + E::BaseField::from_canonical_u16(*b)
        });
        set_val!(
            instance,
            config.divisor_sum_inv,
            divisor_sum_f.try_inverse().unwrap_or(E::BaseField::ZERO)
        );

        let remainder_sum_f = remainder_bytes.iter().fold(E::BaseField::ZERO, |acc, b| {
            acc + E::BaseField::from_canonical_u16(*b)
        });
        set_val!(
            instance,
            config.remainder_sum_inv,
            remainder_sum_f.try_inverse().unwrap_or(E::BaseField::ZERO)
        );
        if let Some(is_zero) = &config.remainder_is_zero {
            set_val!(instance, is_zero, (remainder == 0) as u64);
        }

        // overflow
        if let Some(ov) = &config.is_overflow {
            set_val!(instance, ov, w.is_overflow as u64);
        }

        // absolute values
        assign_abs(
            instance,
            lkm,
            &config.abs_divisor,
            &config.abs_divisor_carry,
            divisor,
            w.divisor_neg,
        );
        assign_abs(
            instance,
            lkm,
            &config.abs_remainder,
            &config.abs_remainder_carry,
            remainder,
            w.remainder_neg,
        );

        // comparison markers / diff
        let abs_divisor_bytes = split_to_u8::<u16>(w.abs_divisor);
        let abs_remainder_bytes = split_to_u8::<u16>(w.abs_remainder);
        let (lt_idx, lt_diff) = if w.divisor_zero {
            (UINT_BYTE_LIMBS, 0u32)
        } else {
            let mut idx = UINT_BYTE_LIMBS;
            let mut diff = 0u32;
            for i in (0..UINT_BYTE_LIMBS).rev() {
                if abs_divisor_bytes[i] != abs_remainder_bytes[i] {
                    idx = i;
                    diff = abs_divisor_bytes[i] as u32 - abs_remainder_bytes[i] as u32;
                    break;
                }
            }
            lkm.assert_const_range(diff as u64 - 1, 8);
            (idx, diff)
        };
        if w.divisor_zero {
            lkm.assert_const_range(0, 8);
        }
        for (i, m) in config.lt_marker.iter().enumerate() {
            set_val!(instance, m, (i == lt_idx) as u64);
        }
        set_val!(instance, config.lt_diff, lt_diff as u64);

        Ok(())
    }

    impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
        let (signed, _is_div) = op_kind(I::INST_KIND);
        let dividend = step.rs1().unwrap().value;
        let divisor = step.rs2().unwrap().value;
        let w = compute_divrem(signed, dividend, divisor);

        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(dividend));
        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(divisor));
        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(w.quotient));
        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(w.remainder));

        for (cfg_signed, val) in [
            (signed, dividend),
            (signed, divisor),
            (signed, w.quotient),
            (signed, w.remainder),
        ] {
            if cfg_signed {
                let byte = (val >> 24) & 0xff;
                let msb = byte >> 7;
                sink.emit_lk(LkOp::DynamicRange {
                    value: (2 * byte - (msb << 8)) as u64,
                    bits: 8,
                });
            }
        }

        emit_byte_decomposition_ops(sink, &w.prod);
        for c in &w.prod_carry {
            sink.emit_lk(LkOp::DynamicRange {
                value: *c as u64,
                bits: CARRY_BITS as u32,
            });
        }

        // abs negation byte range checks
        emit_abs_lk(sink, divisor, w.divisor_neg);
        emit_abs_lk(sink, w.remainder, w.remainder_neg);

        if w.divisor_zero {
            sink.emit_lk(LkOp::DynamicRange { value: 0, bits: 8 });
        } else {
            let abs_divisor_bytes = split_to_u8::<u8>(w.abs_divisor);
            let abs_remainder_bytes = split_to_u8::<u8>(w.abs_remainder);
            let mut diff = 0u32;
            for i in (0..UINT_BYTE_LIMBS).rev() {
                if abs_divisor_bytes[i] != abs_remainder_bytes[i] {
                    diff = abs_divisor_bytes[i] as u32 - abs_remainder_bytes[i] as u32;
                    break;
                }
            }
            sink.emit_lk(LkOp::DynamicRange {
                value: diff as u64 - 1,
                bits: 8,
            });
        }
    });

    impl_collect_shardram!(r_insn);
}

/// Constrain `abs[i]` to be the byte limbs of `|value|`, where `value` is
/// negative iff `sign == 1`. Returns the abs byte witnesses and the negation
/// carry bits. For unsigned operands (`sign == None`) this just copies `value`.
fn constrain_abs<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    value: &[Expression<E>],
    sign: &Option<SignedExtendConfig<E>>,
    base: &Expression<E>,
) -> Result<([WitIn; UINT_BYTE_LIMBS], [WitIn; UINT_BYTE_LIMBS]), ZKVMError> {
    let abs: [WitIn; UINT_BYTE_LIMBS] =
        array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")));
    for (i, pair) in abs.chunks(2).enumerate() {
        cb.assert_double_u8(|| format!("{name}_u8_{i}"), pair[0].expr(), pair[1].expr())?;
    }
    let carry: [WitIn; UINT_BYTE_LIMBS] =
        array::from_fn(|i| cb.create_witin(|| format!("{name}_carry_{i}")));

    let neg = match sign {
        Some(s) => s.expr(),
        None => Expression::ZERO,
    };
    for i in 0..UINT_BYTE_LIMBS {
        // when not negative: abs[i] == value[i]
        cb.condition_require_zero(
            || format!("{name}_copy_{i}"),
            Expression::ONE - neg.clone(),
            abs[i].expr() - value[i].clone(),
        )?;
        // when negative: value[i] + abs[i] + carry_in - carry[i]*2^8 == 0  (two's complement)
        let carry_in = if i > 0 {
            carry[i - 1].expr()
        } else {
            Expression::ZERO
        };
        cb.condition_require_zero(
            || format!("{name}_neg_{i}"),
            neg.clone(),
            value[i].clone() + abs[i].expr() + carry_in - carry[i].expr() * base.clone(),
        )?;
        cb.assert_bit(|| format!("{name}_carry_bit_{i}"), carry[i].expr())?;
    }
    // when negative, the final carry-out is 1 (value + abs == 2^32, value != 0)
    cb.condition_require_zero(
        || format!("{name}_neg_final_carry"),
        neg,
        carry[UINT_BYTE_LIMBS - 1].expr() - Expression::ONE,
    )?;
    Ok((abs, carry))
}

/// Assignment counterpart of [`constrain_abs`].
fn assign_abs<F: ff_ext::SmallField>(
    instance: &mut [F],
    lkm: &mut LkMultiplicity,
    abs_wit: &[WitIn; UINT_BYTE_LIMBS],
    carry_wit: &[WitIn; UINT_BYTE_LIMBS],
    value: u32,
    neg: bool,
) {
    let abs_val = if neg { value.wrapping_neg() } else { value };
    let abs_bytes = abs_val.to_le_bytes();
    let value_bytes = value.to_le_bytes();
    let mut carry_in = 0u32;
    for i in 0..UINT_BYTE_LIMBS {
        set_val!(instance, abs_wit[i], abs_bytes[i] as u64);
        let carry_out = if neg {
            let v = value_bytes[i] as u32 + abs_bytes[i] as u32 + carry_in;
            v >> 8
        } else {
            0
        };
        set_val!(instance, carry_wit[i], carry_out as u64);
        carry_in = carry_out;
    }
    // byte range-check lookups for the abs limbs (mirrors `assert_double_u8`)
    for pair in abs_bytes.chunks(2) {
        lkm.assert_double_u8(pair[0] as u64, pair[1] as u64);
    }
}

/// Emit the byte range-check lookups produced by [`constrain_abs`] /
/// [`assign_abs`] (only the abs byte u8 checks; carries are bits).
fn emit_abs_lk(sink: &mut impl LkShardramSink, value: u32, neg: bool) {
    let abs_val = if neg { value.wrapping_neg() } else { value };
    emit_byte_decomposition_ops(sink, &abs_val.to_le_bytes());
}

struct DivRemWitness {
    quotient: u32,
    remainder: u32,
    prod: [u8; LONG_BYTES],
    prod_carry: [u32; LONG_BYTES],
    add_carry: [u32; LONG_BYTES],
    divisor_zero: bool,
    is_overflow: bool,
    divisor_neg: bool,
    remainder_neg: bool,
    abs_divisor: u32,
    abs_remainder: u32,
}

fn compute_divrem(signed: bool, dividend: u32, divisor: u32) -> DivRemWitness {
    let (quotient, remainder) = if divisor == 0 {
        (u32::MAX, dividend)
    } else if signed {
        let d = dividend as i32;
        let v = divisor as i32;
        (d.wrapping_div(v) as u32, d.wrapping_rem(v) as u32)
    } else {
        (dividend / divisor, dividend % divisor)
    };

    let divisor_zero = divisor == 0;
    let is_overflow = signed && dividend == i32::MIN as u32 && divisor == u32::MAX;

    let divisor_neg = signed && (divisor >> 31) == 1;
    let dividend_neg = signed && (dividend >> 31) == 1;
    let quotient_neg = signed && (quotient >> 31) == 1;
    let remainder_neg = signed && (remainder >> 31) == 1;

    // sign-extend operands to 8 bytes (i64 two's complement / zero extension)
    let ext = |val: u32, neg: bool| -> [u8; LONG_BYTES] {
        let mut bytes = [if neg { 0xff } else { 0u8 }; LONG_BYTES];
        bytes[..UINT_BYTE_LIMBS].copy_from_slice(&val.to_le_bytes());
        bytes
    };
    let c = ext(divisor, divisor_neg);
    let q = ext(quotient, quotient_neg);
    let r = ext(remainder, remainder_neg);

    // product P = c * q (low 64 bits) with byte-column magnitude carries
    let mut acc = [0u64; LONG_BYTES];
    for (j, cj) in c.iter().enumerate() {
        for (k, qk) in q.iter().enumerate() {
            if j + k < LONG_BYTES {
                acc[j + k] += (*cj as u64) * (*qk as u64);
            }
        }
    }
    let mut prod = [0u8; LONG_BYTES];
    let mut prod_carry = [0u32; LONG_BYTES];
    let mut carry_in = 0u64;
    for i in 0..LONG_BYTES {
        let v = acc[i] + carry_in;
        prod[i] = (v & BYTE_MASK) as u8;
        carry_in = v >> 8;
        prod_carry[i] = carry_in as u32;
    }

    // add carries: prod + r_ext == b_ext (b = dividend sign-extended). The add
    // identity is disabled on the overflow path, so leave its carries at 0 there
    // (they only need to be valid bits).
    let b = ext(dividend, dividend_neg);
    let mut add_carry = [0u32; LONG_BYTES];
    if !is_overflow {
        let mut carry_in = 0u32;
        for i in 0..LONG_BYTES {
            let v = prod[i] as u32 + r[i] as u32 + carry_in;
            // v == b[i] + add_carry[i] * 256
            let co = (v.wrapping_sub(b[i] as u32)) >> 8;
            add_carry[i] = co;
            carry_in = co;
        }
    }

    let abs_divisor = if divisor_neg {
        divisor.wrapping_neg()
    } else {
        divisor
    };
    let abs_remainder = if remainder_neg {
        remainder.wrapping_neg()
    } else {
        remainder
    };

    DivRemWitness {
        quotient,
        remainder,
        prod,
        prod_carry,
        add_carry,
        divisor_zero,
        is_overflow,
        divisor_neg,
        remainder_neg,
        abs_divisor,
        abs_remainder,
    }
}
