// The struct `FieldSqrtCols` is modified from succinctlabs/sp1 under MIT license

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

use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num::BigUint;
use sp1_curves::params::{FieldParameters, Limbs};
use std::fmt::Debug;

use crate::{
    gadgets::{field::FieldOperation, field_op::FieldOpCols, range::FieldLtCols},
    witness::LkMultiplicity,
};

/// A set of columns to compute the square root in emulated arithmetic.
///
/// *Safety*: The `FieldSqrtCols` asserts that `multiplication.result` is a square root of the given
/// input lying within the range `[0, modulus)` with the least significant bit `lsb`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldSqrtCols<T, P: FieldParameters> {
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: FieldOpCols<T, P>,

    pub range: FieldLtCols<T, P>,

    // The least significant bit of the square root.
    pub lsb: T,
}

impl<P: FieldParameters> FieldSqrtCols<WitIn, P> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            multiplication: FieldOpCols::create(cb, || format!("{}_multiplication", name)),
            range: FieldLtCols::create(cb, || format!("{}_range", name)),
            lsb: cb.create_bit(|| format!("{}_lsb", name)).unwrap(),
        }
    }
}

impl<F: SmallField, P: FieldParameters> FieldSqrtCols<F, P> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        record: &mut LkMultiplicity,
        a: &BigUint,
        sqrt_fn: impl Fn(&BigUint) -> BigUint,
    ) -> BigUint {
        let modulus = P::modulus();
        assert!(a < &modulus);
        let sqrt = sqrt_fn(a);
        debug_assert!(sqrt.clone() * sqrt.clone() % &modulus == *a);

        // Use FieldOpCols to compute result * result.
        let sqrt_squared = self
            .multiplication
            .populate(record, &sqrt, &sqrt, FieldOperation::Mul);

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, a.clone());

        // This is a hack to save a column in FieldSqrtCols. We will receive the value a again in
        // the eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = P::to_limbs_field::<F, _>(&sqrt);

        // Populate the range columns.
        self.range.populate(record, &sqrt, &modulus);

        let sqrt_bytes = P::to_limbs(&sqrt);
        self.lsb = F::from_canonical_u8(sqrt_bytes[0] & 1);

        record.lookup_and_byte(sqrt_bytes[0] as u64, 1);

        // Add the byte range check for `sqrt`.
        record.assert_byte_fields(&self.multiplication.result.0);

        sqrt
    }
}

impl<Expr: Clone, P: FieldParameters> FieldSqrtCols<Expr, P> {
    /// Calculates the square root of `a`.
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &Limbs<Expr, P::Limbs>,
        is_odd: impl ToExpr<E, Output = Expression<E>> + Clone,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result.clone();
        let mut multiplication = self.multiplication.clone();
        multiplication.result = a.clone();

        // Compute sqrt * sqrt. We pass in P since we want its BaseField to be the mod.
        multiplication.eval(builder, &sqrt, &sqrt, FieldOperation::Mul)?;

        let modulus_limbs = P::to_limbs_expr(&P::modulus());
        self.range.eval(builder, &sqrt, &modulus_limbs)?;

        // Range check that `sqrt` limbs are bytes.
        builder.assert_bytes(|| "sqrt", sqrt.0.as_slice())?;

        // Assert that the square root is the positive one, i.e., with least significant bit 0.
        // This is done by computing LSB = least_significant_byte & 1.
        builder.assert_bit(|| "lsb", self.lsb.clone().into())?;
        builder.require_equal(|| "lsb equality", self.lsb.clone().into(), is_odd.expr())?;
        builder.lookup_and_byte(sqrt[0].clone().into(), 1.into(), self.lsb.clone().into())
    }
}
