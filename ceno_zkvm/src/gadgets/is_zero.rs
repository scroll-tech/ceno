// The crate is zero gadget is modified from succinctlabs/sp1 under MIT license

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

//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.

use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl IsZeroOperation<WitIn> {
    pub fn create<E: ExtensionField>(cb: &mut CircuitBuilder<E>) -> Self {
        Self {
            inverse: cb.create_witin(|| "IsZeroOperation::inverse"),
            result: cb.create_bit(|| "IsZeroOperation::result").unwrap(),
        }
    }

    pub fn eval<E: ExtensionField>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        let one: Expression<E> = Expression::ZERO;

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.
        let is_zero = one - self.inverse.expr() * a.expr();
        builder.require_equal(
            || "IsZeroOperation: is_zero == self.result",
            is_zero,
            self.result.expr(),
        )?;

        // If the result is 1, then the input is 0.
        builder.require_zero(
            || "IsZeroOperation: result * input == 0",
            self.result.expr() * a,
        )
    }
}

impl<F: SmallField> IsZeroOperation<F> {
    pub fn populate(&mut self, a: u32) -> u32 {
        self.populate_from_field_element(F::from_canonical_u32(a))
    }

    pub fn populate_from_field_element(&mut self, a: F) -> u32 {
        if a == F::ZERO {
            self.inverse = F::ZERO;
            self.result = F::ONE;
        } else {
            self.inverse = a.inverse();
            self.result = F::ZERO;
        }
        let prod = self.inverse * a;
        debug_assert!(prod == F::ONE || prod == F::ZERO);
        (a == F::ZERO) as u32
    }
}
