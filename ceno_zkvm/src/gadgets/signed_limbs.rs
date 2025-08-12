/// circuit implementation refer from https://github.com/openvm-org/openvm/blob/ca36de3803213da664b03d111801ab903d55e360/extensions/rv32im/circuit/src/branch_lt/core.rs
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::riscv::constants::{LIMB_BITS, UINT_LIMBS, UInt},
};
use ff_ext::{ExtensionField, FieldInto, SmallField};
use gkr_iop::error::CircuitBuilderError;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::{array, marker::PhantomData};
use witness::set_val;

#[derive(Debug)]
pub struct UIntLimbsLTConfig<E: ExtensionField> {
    // Most significant limb of a and b respectively as a field element, will be range
    // checked to be within [-32768, 32767) if signed and [0, 65536) if unsigned.
    pub a_msb_f: WitIn,
    pub b_msb_f: WitIn,

    // 1 at the most significant index i such that a[i] != b[i], otherwise 0. If such
    // an i exists, diff_val = a[i] - b[i].
    pub diff_marker: [WitIn; UINT_LIMBS],
    pub diff_val: WitIn,

    // 1 if a < b, 0 otherwise.
    pub cmp_lt: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> UIntLimbsLTConfig<E> {
    pub fn is_lt(&self) -> Expression<E> {
        self.cmp_lt.expr()
    }
}

pub struct UIntLimbsLT<E: ExtensionField> {
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> UIntLimbsLT<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        a: &UInt<E>,
        b: &UInt<E>,
        is_sign_comparison: bool,
    ) -> Result<UIntLimbsLTConfig<E>, ZKVMError> {
        // 1 if a < b, 0 otherwise.
        let cmp_lt = circuit_builder.create_bit(|| "cmp_lt")?;

        let a_expr = a.expr();
        let b_expr = b.expr();

        let a_msb_f = circuit_builder.create_witin(|| "a_msb_f");
        let b_msb_f = circuit_builder.create_witin(|| "b_msb_f");
        let diff_marker: [WitIn; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_bit(|| format!("diff_maker_{i}"))
                .expect("create_bit_error")
        });
        let diff_val = circuit_builder.create_witin(|| "diff_val");

        // Check if a_msb_f and b_msb_f are signed values of a[NUM_LIMBS - 1] and b[NUM_LIMBS - 1] in prime field F.
        let a_diff = a_expr[UINT_LIMBS - 1].expr() - a_msb_f.expr();
        let b_diff = b_expr[UINT_LIMBS - 1].expr() - b_msb_f.expr();

        circuit_builder.require_zero(
            || "a_diff",
            a_diff.expr()
                * (E::BaseField::from_canonical_u32(1 << LIMB_BITS).expr() - a_diff.expr()),
        )?;
        circuit_builder.require_zero(
            || "b_diff",
            b_diff.expr()
                * (E::BaseField::from_canonical_u32(1 << LIMB_BITS).expr() - b_diff.expr()),
        )?;

        let mut prefix_sum = Expression::ZERO;

        for i in (0..UINT_LIMBS).rev() {
            let diff = (if i == UINT_LIMBS - 1 {
                b_msb_f.expr() - a_msb_f.expr()
            } else {
                b_expr[i].expr() - a_expr[i].expr()
            }) * (E::BaseField::from_canonical_u8(2).expr() * cmp_lt.expr()
                - E::BaseField::ONE.expr());
            prefix_sum += diff_marker[i].expr();
            circuit_builder.require_zero(
                || format!("prefix_diff_zero_{i}"),
                (E::BaseField::ONE.expr() - prefix_sum.expr()) * diff.clone(),
            )?;
            circuit_builder.condition_require_zero(
                || format!("diff_maker_conditional_equal_{i}"),
                diff_marker[i].expr(),
                diff_val.expr() - diff.expr(),
            )?;
        }

        // - If x != y, then prefix_sum = 1 so marker[i] must be 1 iff i is the first index where diff != 0.
        //   Constrains that diff == diff_val where diff_val is non-zero.
        // - If x == y, then prefix_sum = 0 and cmp_lt = 0.
        //   Here, prefix_sum cannot be 1 because all diff are zero, making diff == diff_val fails.

        circuit_builder.assert_bit(|| "prefix_sum_bit", prefix_sum.expr())?;
        circuit_builder.condition_require_zero(
            || "cmp_lt_conditional_zero",
            E::BaseField::ONE.expr() - prefix_sum.expr(),
            cmp_lt.expr(),
        )?;

        // Range check to ensure diff_val is non-zero.
        circuit_builder.assert_ux::<_, _, LIMB_BITS>(
            || "diff_val is non-zero",
            prefix_sum.expr() * (diff_val.expr() - E::BaseField::ONE.expr()),
        )?;

        circuit_builder.assert_ux::<_, _, LIMB_BITS>(
            || "a_msb_f_signed_range_check",
            a_msb_f.expr()
                + if is_sign_comparison {
                    E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr()
                } else {
                    Expression::ZERO
                },
        )?;

        circuit_builder.assert_ux::<_, _, LIMB_BITS>(
            || "b_msb_f_signed_range_check",
            b_msb_f.expr()
                + if is_sign_comparison {
                    E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr()
                } else {
                    Expression::ZERO
                },
        )?;

        Ok(UIntLimbsLTConfig {
            a_msb_f,
            b_msb_f,
            diff_marker,
            diff_val,
            cmp_lt,
            phantom: PhantomData,
        })
    }

    pub fn assign(
        config: &UIntLimbsLTConfig<E>,
        instance: &mut [E::BaseField],
        lkm: &mut gkr_iop::utils::lk_multiplicity::LkMultiplicity,
        a: &[u16],
        b: &[u16],
        is_sign_comparison: bool,
    ) -> Result<(), CircuitBuilderError> {
        let (cmp_lt, diff_idx, a_sign, b_sign) = run_cmp(is_sign_comparison, a, b);
        config
            .diff_marker
            .iter()
            .enumerate()
            .for_each(|(i, witin)| {
                set_val!(instance, witin, (i == diff_idx) as u64);
            });
        set_val!(instance, config.cmp_lt, cmp_lt as u64);

        // We range check (read_rs1_msb_f + 32768) and (read_rs2_msb_f + 32768) if signed,
        // read_rs1_msb_f and read_rs2_msb_f if not
        let (a_msb_f, a_msb_range) = if a_sign {
            (
                -E::BaseField::from_canonical_u32((1 << LIMB_BITS) - a[UINT_LIMBS - 1] as u32),
                a[UINT_LIMBS - 1] - (1 << (LIMB_BITS - 1)),
            )
        } else {
            (
                E::BaseField::from_canonical_u16(a[UINT_LIMBS - 1]),
                a[UINT_LIMBS - 1] + ((is_sign_comparison as u16) << (LIMB_BITS - 1)),
            )
        };
        let (b_msb_f, b_msb_range) = if b_sign {
            (
                -E::BaseField::from_canonical_u32((1 << LIMB_BITS) - b[UINT_LIMBS - 1] as u32),
                b[UINT_LIMBS - 1] - (1 << (LIMB_BITS - 1)),
            )
        } else {
            (
                E::BaseField::from_canonical_u16(b[UINT_LIMBS - 1]),
                b[UINT_LIMBS - 1] + ((is_sign_comparison as u16) << (LIMB_BITS - 1)),
            )
        };

        set_val!(instance, config.a_msb_f, a_msb_f);
        set_val!(instance, config.b_msb_f, b_msb_f);

        let diff_val = if diff_idx == UINT_LIMBS {
            0
        } else if diff_idx == (UINT_LIMBS - 1) {
            if cmp_lt {
                b_msb_f - a_msb_f
            } else {
                a_msb_f - b_msb_f
            }
            .to_canonical_u64() as u16
        } else if cmp_lt {
            b[diff_idx] - a[diff_idx]
        } else {
            a[diff_idx] - b[diff_idx]
        };
        set_val!(instance, config.diff_val, diff_val as u64);

        if diff_idx != UINT_LIMBS {
            lkm.assert_ux::<LIMB_BITS>((diff_val - 1) as u64);
        } else {
            lkm.assert_ux::<LIMB_BITS>(0);
        }

        lkm.assert_ux::<LIMB_BITS>(a_msb_range as u64);
        lkm.assert_ux::<LIMB_BITS>(b_msb_range as u64);

        Ok(())
    }
}

// returns (cmp_lt, diff_idx, x_sign, y_sign)
// cmp_lt = true if a < b else false
pub fn run_cmp(signed: bool, x: &[u16], y: &[u16]) -> (bool, usize, bool, bool) {
    let x_sign = (x[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1) && signed;
    let y_sign = (y[UINT_LIMBS - 1] >> (LIMB_BITS - 1) == 1) && signed;
    for i in (0..UINT_LIMBS).rev() {
        if x[i] != y[i] {
            return ((x[i] < y[i]) ^ x_sign ^ y_sign, i, x_sign, y_sign);
        }
    }
    (false, UINT_LIMBS, x_sign, y_sign)
}
