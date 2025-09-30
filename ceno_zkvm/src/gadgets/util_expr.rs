// This file is modified from succinctlabs/sp1 under MIT license

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

use ff_ext::ExtensionField;
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr};
use p3::field::FieldAlgebra;
use sp1_curves::{params::FieldParameters, polynomial::Polynomial};

pub fn eval_field_operation<E: ExtensionField, P: FieldParameters>(
    builder: &mut CircuitBuilder<E>,
    p_vanishing: &Polynomial<Expression<E>>,
    p_witness_low: &Polynomial<Expression<E>>,
    p_witness_high: &Polynomial<Expression<E>>,
) -> Result<(), CircuitBuilderError> {
    // Reconstruct and shift back the witness polynomial
    let limb: Expression<E> =
        E::BaseField::from_canonical_u32(2u32.pow(P::NB_BITS_PER_LIMB as u32)).expr();

    let p_witness_shifted = p_witness_low + &(p_witness_high * limb.clone());

    // Shift down the witness polynomial. Shifting is needed to range check that each
    // coefficient w_i of the witness polynomial satisfies |w_i| < 2^WITNESS_OFFSET.
    let offset: Expression<E> = E::BaseField::from_canonical_u32(P::WITNESS_OFFSET as u32).expr();
    let len = p_witness_shifted.coefficients().len();
    let p_witness = p_witness_shifted - Polynomial::new(vec![offset; len]);

    // Multiply by (x-2^NB_BITS_PER_LIMB) and make the constraint
    let root_monomial = Polynomial::new(vec![-limb, E::BaseField::ONE.expr()]);

    let constraints = p_vanishing - &(p_witness * root_monomial);
    for constr in constraints.as_coefficients() {
        builder.require_zero(|| "eval_field_operation require zero", constr)?;
    }
    Ok(())
}
