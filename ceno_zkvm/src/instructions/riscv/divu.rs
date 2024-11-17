use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use super::{
    constants::{UInt, BIT_WIDTH, UINT_LIMBS}, dummy::DummyInstruction, r_insn::RInstructionConfig, RIVInstruction
};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::{Expression, ToExpr, WitIn}, gadgets::{AssertLTConfig, IsEqualConfig, IsLtConfig, IsZeroConfig, Signed}, instructions::Instruction, set_val, uint::Value, witness::LkMultiplicity
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
        negative_division: WitIn,
        is_dividend_max_negative: IsEqualConfig,
        is_divisor_minus_one: IsEqualConfig,
        is_signed_overflow: WitIn,
        quotient_signed: Signed<E>,
        remainder_signed: Signed<E>,
        remainder_nonnegative: AssertLTConfig,
    },
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct DivOp;
impl RIVInstruction for DivOp {
    const INST_KIND: InsnKind = InsnKind::DIV;
}
pub type DivDummy<E> = DummyInstruction<E, DivOp>; // TODO: implement DivInstruction.

pub struct DivUOp;
impl RIVInstruction for DivUOp {
    const INST_KIND: InsnKind = InsnKind::DIVU;
}
pub type DivUInstruction<E> = ArithInstruction<E, DivUOp>;

pub struct RemOp;
impl RIVInstruction for RemOp {
    const INST_KIND: InsnKind = InsnKind::REM;
}
pub type RemDummy<E> = DummyInstruction<E, RemOp>; // TODO: implement RemInstruction.

pub struct RemuOp;
impl RIVInstruction for RemuOp {
    const INST_KIND: InsnKind = InsnKind::REMU;
}
pub type RemuDummy<E> = DummyInstruction<E, RemuOp>; // TODO: implement RemuInstruction.

// dividend and divisor are always rs1 and rs2 respectively, this can be uniform
// unsigned values are as represented by UInts
// signed values should be interpreted as such (extra data in internal enum?)
// might be able to factor out all sign operations to the end

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = DivRemConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // quotient = dividend / divisor + remainder
        // => dividend = divisor * quotient + remainder
        let dividend = UInt::new_unchecked(|| "dividend", cb)?; // 32-bit value from rs1
        let divisor = UInt::new_unchecked(|| "divisor", cb)?; // 32-bit value from rs2
        let quotient = UInt::new(|| "quotient", cb)?;
        let remainder = UInt::new(|| "remainder", cb)?;

        // rem_e and div_e are expressions verified to be nonnegative, which
        // must be validated as either 0 <= rem_e < div_e, or div_e == 0 with
        // appropriate divide by zero outputs
        let (internal_config, rem_e, div_e) = match I::INST_KIND {
            InsnKind::DIVU | InsnKind::REMU => {
                (InternalDivRem::Unsigned, remainder.value(), divisor.value())
            },

            InsnKind::ADD | InsnKind::REM => {
                let dividend_signed: Signed<E> = Signed::construct_circuit(cb, || "dividend_signed", &dividend)?;
                let divisor_signed: Signed<E> = Signed::construct_circuit(cb, || "divisor_signed", &divisor)?;

                // quotient and remainder can be interpreted as non-positive
                // values when exactly one of dividend and divisor is negative
                let neg_div_expr: Expression<E> = {
                    let a_neg = dividend_signed.is_negative.expr();
                    let b_neg = divisor_signed.is_negative.expr();
                    // a_neg * (1 - b_neg) + (1 - a_neg) * b_neg
                    (a_neg.clone() + b_neg.clone()) - (Expression::<E>::from(2) * a_neg * b_neg)
                };
                let negative_division = cb.flatten_expr(|| "neg_division", neg_div_expr)?;

                // check for signed division overflow, i32::MIN / -1
                let is_dividend_max_negative = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_dividend_max_negative",
                    dividend.value(),
                    (1u64 << (BIT_WIDTH - 1)).into()
                )?;
                let is_divisor_minus_one = IsEqualConfig::construct_circuit(
                    cb,
                    || "is_divisor_minus_one",
                    divisor.value(),
                    ((1u64 << BIT_WIDTH) - 1).into()
                )?;
                let is_signed_overflow = cb.flatten_expr(
                    || "signed_division_overflow",
                    is_dividend_max_negative.expr() * is_divisor_minus_one.expr()
                )?;

                let quotient_signed: Signed<E> = Signed::construct_circuit(cb, || "quotient_signed", &quotient)?;
                let remainder_signed: Signed<E> = Signed::construct_circuit(cb, || "remainder_signed", &quotient)?;

                // For signed integer overflow, dividend side of division
                // relation is set to a different value, +2^31, corresponding
                // to the dividend we would need to satisfy the division
                // relation with the required output quotient -2^31 and
                // remainder 0 with the overflow divisor -1. The two distinct
                // possibilities are handled with `condition_require_equal`
                let div_rel_expr = quotient_signed.expr() * divisor_signed.expr() + remainder_signed.expr();
                cb.condition_require_equal(
                    || "signed_division_relation",
                    is_signed_overflow.expr(),
                    div_rel_expr,
                    // overflow replacement dividend, +2^31
                    (1u64 << (BIT_WIDTH - 1)).into(),
                    dividend_signed.expr())?;

                // Check required inequalities for remainder value; change sign
                // for remainder and divisor so that checked inequality is the
                // usual unsigned one, 0 <= remainder < divisor
                let remainder_pos_orientation = (Expression::ONE - Expression::<E>::from(2)*negative_division.expr()) * remainder_signed.expr();
                let divisor_pos_orientation = (Expression::ONE - Expression::<E>::from(2)*divisor_signed.is_negative.expr()) * divisor_signed.expr();

                let remainder_nonnegative = AssertLTConfig::construct_circuit(
                    cb,
                    || "oriented_remainder_nonnegative",
                    (-1).into(),
                    remainder_pos_orientation.clone(),
                    UINT_LIMBS
                )?;

                (InternalDivRem::Signed {
                    dividend_signed,
                    divisor_signed,
                    negative_division,
                    is_dividend_max_negative,
                    is_divisor_minus_one,
                    is_signed_overflow,
                    quotient_signed,
                    remainder_signed,
                    remainder_nonnegative,
                },
                remainder_pos_orientation,
                divisor_pos_orientation)
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        // For signed division overflow, dividend = -2^31, and divisor = -1, so
        // that we would require quotient = 2^31 which is too large for signed
        // 32-bit values.  In this case, quotient and remainder must be set to
        // -2^31 and 0 respectively.  This is assured by the constraints
        //
        //   2^31 = divisor * quotient + remainder
        //   0 <= remainder < divisor (positive) or divisor < remainder <= 0 (negative)
        //
        // The second condition is the same whether or not overflow occurs, and
        // the first condition is only different from the usual value in the
        // left side of the equality, which can be controlled by a conditional
        // equality constraint.
        // 
        // cb.condition_require_equal(
        //     || "division_signed_overflow",
        //     is_signed_overflow.expr(),
        //     div_rhs,
        //     (1u64 << (UInt::<E>::TOTAL_BITS - 1)).into(),
        //     dividend.value(),
        // );

        let is_divisor_zero = IsZeroConfig::construct_circuit(cb, || "is_divisor_zero", divisor.value())?;

        // For zero division, quotient must be the "all ones" register for both
        // unsigned and signed cases, representing 2^32-1 and -1 respectively
        cb.condition_require_equal(
            || "quotient_zero_division",
            is_divisor_zero.expr(),
            quotient.value(),
            ((1u64 << UInt::<E>::TOTAL_BITS) - 1).into(),
            quotient.value(),
        )?;

        // Check whether the (suitably oriented) remainder is less than the
        // (suitably oriented) divisor, where "suitably oriented" is subtle for
        // the signed case, involving both signs and the constraints used for
        // signed division overflow
        let is_remainder_lt_divisor = IsLtConfig::construct_circuit(
            cb,
            || "is_remainder_lt_divisor",
            rem_e,
            div_e,
            UINT_LIMBS
        )?;

        // When divisor is nonzero, remainder must be less than divisor,
        // but when divisor is zero, remainder can't be less than
        // divisor; so require that exactly one of these is true, i.e.
        // sum of bit expressions is equal to 1.
        cb.require_equal(
            || "remainder < divisor iff divisor nonzero",
            is_divisor_zero.expr() + is_remainder_lt_divisor.expr(),
            1.into(),
        )?;

        let rd_written_e = match I::INST_KIND {
            InsnKind::DIVU | InsnKind::DIV => { quotient.register_expr() },
            InsnKind::REMU | InsnKind::REM => { remainder.register_expr() },
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

    // TODO rewrite assign_instance
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

        config.dividend.assign_limbs(instance, dividend_v.as_u16_limbs());
        config.divisor.assign_limbs(instance, divisor_v.as_u16_limbs());

        let (quotient, remainder) = match &config.internal_config {
            InternalDivRem::Unsigned => {
                if divisor == 0 {
                    (u32::MAX, dividend)
                } else {
                    (dividend / divisor, dividend % divisor)
                }
            },
            InternalDivRem::Signed{ .. } => {
                let dividend_s = dividend as i32;
                let divisor_s = divisor as i32;

                let (quotient_s, remainder_s) = if divisor_s == 0 {
                    (-1i32, dividend_s)
                } else {
                    // these correctly handle signed division overflow
                    (dividend_s.wrapping_div(divisor_s), dividend_s.wrapping_rem(divisor_s))
                };

                (quotient_s as u32, remainder_s as u32)
            }
        };

        let quotient_v = Value::new(quotient, lkm);
        let remainder_v = Value::new(remainder, lkm);

        config.quotient.assign_limbs(instance, quotient_v.as_u16_limbs());
        config.remainder.assign_limbs(instance, remainder_v.as_u16_limbs());

        let (rem_pos, div_pos) = match &config.internal_config {
            InternalDivRem::Unsigned => {
                (remainder, divisor)
            }
            InternalDivRem::Signed { 
                dividend_signed,
                divisor_signed,
                negative_division,
                is_dividend_max_negative,
                is_divisor_minus_one,
                is_signed_overflow,
                quotient_signed,
                remainder_signed,
                remainder_nonnegative } =>
            {
                let dividend_s = dividend as i32;
                let divisor_s = divisor as i32;
                let remainder_s = remainder as i32;

                dividend_signed.assign_instance(instance, lkm, &dividend_v)?;
                divisor_signed.assign_instance(instance, lkm, &divisor_v)?;

                let negative_division_b = (dividend_s < 0) ^ (divisor_s < 0);
                set_val!(instance, negative_division, negative_division_b as u64);

                is_dividend_max_negative.assign_instance(instance, (dividend as u64).into(), ((i32::MIN as u32) as u64).into())?;
                is_divisor_minus_one.assign_instance(instance, (divisor as u64).into(), ((-1i32 as u32) as u64).into())?;

                let signed_div_overflow_b = dividend_s == i32::MIN && divisor_s == -1i32;
                set_val!(instance, is_signed_overflow, signed_div_overflow_b as u64);

                quotient_signed.assign_instance(instance, lkm, &quotient_v)?;
                remainder_signed.assign_instance(instance, lkm, &remainder_v)?;

                let remainder_pos_orientation = if negative_division_b { -(remainder_s as i64) } else { remainder_s as i64 };
                let divisor_pos_orientation = if divisor_s < 0 { -(divisor_s as i64) } else { divisor_s as i64 };

                remainder_nonnegative.assign_instance(instance, lkm,
                    <E::BaseField as SmallField>::MODULUS_U64.wrapping_add_signed(-1),
                    <E::BaseField as SmallField>::MODULUS_U64.wrapping_add_signed(remainder_pos_orientation))?;

                (remainder_pos_orientation as u32, divisor_pos_orientation as u32)
            },
        };

        config.is_divisor_zero.assign_instance(instance, (divisor as u64).into())?;

        config.is_remainder_lt_divisor.assign_instance(instance, lkm, rem_pos as u64, div_pos as u64)?;

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
                riscv::{constants::UInt, divu::DivUInstruction},
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
                    |cb| Ok(DivUInstruction::construct_circuit(cb)),
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
                DivUInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
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
                .test
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
        fn test_opcode_divu_unstatisfied() {
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
}
