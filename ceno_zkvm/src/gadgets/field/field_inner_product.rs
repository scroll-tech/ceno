// The struct `FieldInnerProductCols` is modified from succinctlabs/sp1 under MIT license

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
use generic_array::{GenericArray, sequence::GenericSequence};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num::{BigUint, Zero};
use sp1_curves::{
    params::{FieldParameters, Limbs},
    polynomial::Polynomial,
};
use std::fmt::Debug;

use crate::{
    gadgets::{
        util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
        util_expr::eval_field_operation,
    },
    witness::LkMultiplicity,
};

/// A set of columns to compute `InnerProduct([a], [b])` where a, b are emulated elements.
///
/// *Safety*: The `FieldInnerProductCols` asserts that `result = sum_i a_i * b_i mod M` where
/// `M` is the modulus `P::modulus()` under the assumption that the length of `a` and `b` is small
/// enough so that the vanishing polynomial has limbs bounded by the witness shift. It is the
/// responsibility of the caller to ensure that the length of `a` and `b` is small enough.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T, P: FieldParameters> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

impl<P: FieldParameters> FieldInnerProductCols<WitIn, P> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            result: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_result", name))
            })),
            carry: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_carry", name))
            })),
            witness_low: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_low", name))
            })),
            witness_high: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_high", name))
            })),
        }
    }
}

impl<F: SmallField, P: FieldParameters> FieldInnerProductCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut LkMultiplicity,
        a: &[BigUint],
        b: &[BigUint],
    ) -> BigUint {
        let p_a_vec: Vec<Polynomial<F>> = a
            .iter()
            .map(|x| P::to_limbs_field::<F, _>(x).into())
            .collect();
        let p_b_vec: Vec<Polynomial<F>> = b
            .iter()
            .map(|x| P::to_limbs_field::<F, _>(x).into())
            .collect();

        let modulus = &P::modulus();
        let inner_product = a
            .iter()
            .zip(b.iter())
            .fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

        let result = &(&inner_product % modulus);
        let carry = &((&inner_product - result) / modulus);
        assert!(result < modulus);
        assert!(carry < &(2u32 * modulus));
        assert_eq!(carry * modulus, inner_product - result);

        let p_modulus: Polynomial<F> = P::to_limbs_field::<F, _>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(carry).into();

        // Compute the vanishing polynomial.
        let p_inner_product = p_a_vec
            .into_iter()
            .zip(p_b_vec)
            .fold(Polynomial::<F>::new(vec![F::ZERO]), |acc, (c, d)| {
                acc + &c * &d
            });
        let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
        assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            P::NB_WITNESS_LIMBS,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        // Range checks
        record.assert_byte_fields(&self.result.0);
        record.assert_byte_fields(&self.carry.0);
        record.assert_byte_fields(&self.witness_low.0);
        record.assert_byte_fields(&self.witness_high.0);

        result.clone()
    }
}

impl<Expr: Clone, P: FieldParameters> FieldInnerProductCols<Expr, P> {
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &[impl Into<Polynomial<Expression<E>>> + Clone],
        b: &[impl Into<Polynomial<Expression<E>>> + Clone],
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_a_vec: Vec<Polynomial<Expression<E>>> = a.iter().cloned().map(|x| x.into()).collect();
        let p_b_vec: Vec<Polynomial<Expression<E>>> = b.iter().cloned().map(|x| x.into()).collect();
        let p_result: Polynomial<Expression<E>> = self.result.clone().into();
        let p_carry: Polynomial<Expression<E>> = self.carry.clone().into();

        let p_zero = Polynomial::<Expression<E>>::new(vec![Expression::<E>::ZERO]);

        let p_inner_product = p_a_vec
            .iter()
            .zip(p_b_vec.iter())
            .map(|(p_a, p_b)| p_a * p_b)
            .collect::<Vec<_>>()
            .iter()
            .fold(p_zero, |acc, x| acc + x);

        let p_inner_product_minus_result = &p_inner_product - &p_result;
        let p_limbs =
            Polynomial::from_iter(P::modulus_field_iter::<E::BaseField>().map(|x| x.expr()));
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();

        eval_field_operation::<E, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high)?;

        // Range checks for the result, carry, and witness columns.
        builder.assert_bytes(|| "field_inner_product result", &self.result.0)?;
        builder.assert_bytes(|| "field_inner_product carry", &self.carry.0)?;
        builder.assert_bytes(|| "field_inner_product witness_low", &self.witness_low.0)?;
        builder.assert_bytes(|| "field_inner_product witness_high", &self.witness_high.0)
    }
}
