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

use ff_ext::SmallField;
use num::BigUint;
use sp1_curves::polynomial::Polynomial;

fn biguint_to_field<F: SmallField>(num: BigUint) -> F {
    let mut x = F::ZERO;
    let mut power = F::from_canonical_u32(1u32);
    let base = F::from_canonical_u64((1 << 32) % F::MODULUS_U64);
    let digits = num.iter_u32_digits();
    for digit in digits.into_iter() {
        x += F::from_canonical_u32(digit) * power;
        power *= base;
    }
    x
}

#[inline]
pub fn compute_root_quotient_and_shift<F: SmallField>(
    p_vanishing: &Polynomial<F>,
    offset: usize,
    nb_bits_per_limb: u32,
    nb_limbs: usize,
) -> Vec<F> {
    // Evaluate the vanishing polynomial at x = 2^nb_bits_per_limb.

    let p_vanishing_eval = p_vanishing
        .coefficients()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            biguint_to_field::<F>(BigUint::from(2u32) << (nb_bits_per_limb * i as u32)) * *x
        })
        .sum::<F>();
    debug_assert_eq!(p_vanishing_eval, F::ZERO);

    // Compute the witness polynomial by witness(x) = vanishing(x) / (x - 2^nb_bits_per_limb).
    let root_monomial = F::from_canonical_u32(2u32.pow(nb_bits_per_limb));
    let p_quotient = p_vanishing.root_quotient(root_monomial);
    debug_assert_eq!(p_quotient.degree(), p_vanishing.degree() - 1);

    // Sanity Check #1: For all i, |w_i| < 2^20 to prevent overflows.
    let offset_u64 = offset as u64;
    for c in p_quotient.coefficients().iter() {
        debug_assert!(c.neg().to_canonical_u64() < offset_u64 || c.to_canonical_u64() < offset_u64);
    }

    // Sanity Check #2: w(x) * (x - 2^nb_bits_per_limb) = vanishing(x).
    let x_minus_root = Polynomial::<F>::from_coefficients(&[-root_monomial, F::ONE]);
    debug_assert_eq!(&p_quotient * &x_minus_root, *p_vanishing);

    let mut p_quotient_coefficients = p_quotient.as_coefficients();
    p_quotient_coefficients.resize(nb_limbs, F::ZERO);

    // Shifting the witness polynomial to make it positive
    p_quotient_coefficients
        .into_iter()
        .map(|x| x + F::from_canonical_u64(offset_u64))
        .collect::<Vec<F>>()
}

#[inline]
pub fn split_u16_limbs_to_u8_limbs<F: SmallField>(slice: &[F]) -> (Vec<F>, Vec<F>) {
    (
        slice
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .map(|x| F::from_canonical_u8(x))
            .collect(),
        slice
            .iter()
            .map(|x| (x.to_canonical_u64() >> 8) as u8)
            .map(|x| F::from_canonical_u8(x))
            .collect(),
    )
}
