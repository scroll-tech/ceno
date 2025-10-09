// The struct `FieldLtCols` is modified from succinctlabs/sp1 under MIT license

// The MIT License (MIT)

// Copyright (c) 2023 Succinct Labs

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use ff_ext::{ExtensionField, SmallField};
use generic_array::{GenericArray, sequence::GenericSequence};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num::BigUint;
use sp1_curves::{
    params::{FieldParameters, Limbs},
    polynomial::Polynomial,
};
use std::fmt::Debug;

use crate::witness::LkMultiplicity;

/// Operation columns for verifying that `lhs < rhs`.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FieldLtCols<T, P: FieldParameters> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) byte_flags: Limbs<T, P::Limbs>,

    pub(crate) lhs_comparison_byte: T,

    pub(crate) rhs_comparison_byte: T,
}
impl<P: FieldParameters> FieldLtCols<WitIn, P> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            byte_flags: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_byte_flag", name))
            })),
            lhs_comparison_byte: cb.create_witin(|| format!("{}_lhs_comparison_byte", name)),
            rhs_comparison_byte: cb.create_witin(|| format!("{}_rhs_comparison_byte", name)),
        }
    }
}

impl<F: SmallField, P: FieldParameters> FieldLtCols<F, P> {
    pub fn populate(&mut self, record: &mut LkMultiplicity, lhs: &BigUint, rhs: &BigUint) {
        assert!(lhs < rhs);

        let value_limbs = P::to_limbs(lhs);
        let modulus = P::to_limbs(rhs);

        let mut byte_flags = vec![0u8; P::NB_LIMBS];

        for (byte, modulus_byte, flag) in izip!(
            value_limbs.iter().rev(),
            modulus.iter().rev(),
            byte_flags.iter_mut().rev()
        ) {
            assert!(byte <= modulus_byte);
            if byte < modulus_byte {
                *flag = 1;
                self.lhs_comparison_byte = F::from_canonical_u8(*byte);
                self.rhs_comparison_byte = F::from_canonical_u8(*modulus_byte);
                record.lookup_ltu_byte(*byte as u64, *modulus_byte as u64);
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.0.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }
    }
}

impl<Expr: Clone, P: FieldParameters> FieldLtCols<Expr, P> {
    pub fn eval<E, E1, E2>(
        &self,
        builder: &mut CircuitBuilder<E>,
        lhs: &E1,
        rhs: &E2,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        E1: Into<Polynomial<Expression<E>>> + Clone,
        E2: Into<Polynomial<Expression<E>>> + Clone,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the lhs is smaller than the modulus. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the lhs byte is equal to the modulus byte.
        // * For the `first_eq` byte the lhs byte is smaller than the modulus byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: Expression<E> = 0.into();
        for flag in self.byte_flags.0.iter() {
            // Assert that the flag is boolean.
            builder.assert_bit(|| "flag", flag.expr())?;
            // Add the flag to the sum.
            sum_flags = sum_flags.clone() + flag.expr();
        }
        // Assert that the sum is equal to one.
        builder.require_one(|| "sum_flags", sum_flags)?;

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited: Expression<E> = 0.into();

        let rhs: Polynomial<_> = rhs.clone().into();
        let lhs: Polynomial<_> = lhs.clone().into();

        let mut lhs_comparison_byte: Expression<E> = 0.into();
        let mut rhs_comparison_byte: Expression<E> = 0.into();
        for (lhs_byte, rhs_byte, flag) in izip!(
            lhs.coefficients().iter().rev(),
            rhs.coefficients().iter().rev(),
            self.byte_flags.0.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.expr() + flag.expr();

            lhs_comparison_byte = lhs_comparison_byte.expr() + lhs_byte.expr() * flag.expr();
            rhs_comparison_byte = rhs_comparison_byte.expr() + flag.expr() * rhs_byte.expr();

            builder.require_zero(
                || "when not inequality visited, assert lhs_byte == rhs_byte",
                (1 - is_inequality_visited.clone()) * (lhs_byte.clone() - rhs_byte.clone()),
            )?;
        }

        builder.require_equal(
            || "lhs_comparison_byte == lhs_comparison_byte",
            self.lhs_comparison_byte.expr(),
            lhs_comparison_byte,
        )?;
        builder.require_equal(
            || "rhs_comparison_byte == rhs_comparison_byte",
            self.rhs_comparison_byte.expr(),
            rhs_comparison_byte,
        )?;

        // Send the comparison interaction.
        builder.lookup_ltu_byte(
            self.lhs_comparison_byte.expr(),
            self.rhs_comparison_byte.expr(),
            1.into(),
        )
    }

    pub fn condition_eval<E, E1, E2>(
        &self,
        builder: &mut CircuitBuilder<E>,
        lhs: &E1,
        rhs: &E2,
        cond: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        E1: Into<Polynomial<Expression<E>>> + Clone,
        E2: Into<Polynomial<Expression<E>>> + Clone,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the lhs is smaller than the modulus. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the lhs byte is equal to the modulus byte.
        // * For the `first_eq` byte the lhs byte is smaller than the modulus byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: Expression<E> = 0.into();
        for flag in self.byte_flags.0.iter() {
            // Assert that the flag is boolean.
            builder.assert_bit(|| "if cond, flag", cond.expr() * flag.expr())?;
            // Add the flag to the sum.
            sum_flags = sum_flags.clone() + flag.expr();
        }
        // Assert that the sum is equal to one.
        builder.condition_require_one(|| "sum_flags", cond.expr(), sum_flags.expr())?;
        builder.condition_require_zero(|| "sum_flags", 1 - cond.expr(), sum_flags.expr())?;

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited: Expression<E> = 0.into();

        let rhs: Polynomial<_> = rhs.clone().into();
        let lhs: Polynomial<_> = lhs.clone().into();

        let mut lhs_comparison_byte: Expression<E> = 0.into();
        let mut rhs_comparison_byte: Expression<E> = 0.into();
        for (lhs_byte, rhs_byte, flag) in izip!(
            lhs.coefficients().iter().rev(),
            rhs.coefficients().iter().rev(),
            self.byte_flags.0.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.expr() + flag.expr();

            lhs_comparison_byte = lhs_comparison_byte.expr() + lhs_byte.expr() * flag.expr();
            rhs_comparison_byte = rhs_comparison_byte.expr() + flag.expr() * rhs_byte.expr();

            builder.condition_require_zero(
                || "if cond, when not inequality visited, assert lhs_byte == rhs_byte",
                cond.expr(),
                (1 - is_inequality_visited.clone()) * (lhs_byte.clone() - rhs_byte.clone()),
            )?;
        }

        builder.condition_require_zero(
            || "if cond, lhs_comparison_byte == lhs_comparison_byte",
            cond.expr(),
            self.lhs_comparison_byte.expr() - lhs_comparison_byte,
        )?;
        builder.condition_require_zero(
            || "if cond, rhs_comparison_byte == rhs_comparison_byte",
            cond.expr(),
            self.rhs_comparison_byte.expr() - rhs_comparison_byte,
        )?;

        // Send the comparison interaction.
        // Since sum_flags = 1 when cond = 1, and sum_flags = 0 when cond = 0,
        // we have (self.lhs_comparison_byte < self.rhs_comparison_byte) == sum_flags
        builder.lookup_ltu_byte(
            self.lhs_comparison_byte.expr(),
            self.rhs_comparison_byte.expr(),
            sum_flags,
        )
    }
}
