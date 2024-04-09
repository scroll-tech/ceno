use crate::{
    poly::{multilinear::zip_self, Polynomial},
    sum_check::classic::{ClassicSumCheckProver, ClassicSumCheckRoundMessage, ProverState},
    util::{
        arithmetic::{div_ceil, horner},
        expression::{CommonPolynomial, Expression, Rotation},
        impl_index,
        parallel::{num_threads, parallelize_iter},
        transcript::{FieldTranscriptRead, FieldTranscriptWrite},
    },
    Error,
};
use ff::PrimeField;
use itertools::Itertools;
use std::{fmt::Debug, iter, ops::AddAssign};

#[derive(Debug)]
pub struct Coefficients<F>(Vec<F>);

impl<F: PrimeField> ClassicSumCheckRoundMessage<F> for Coefficients<F> {
    type Auxiliary = ();

    fn write(&self, transcript: &mut impl FieldTranscriptWrite<F>) -> Result<(), Error> {
        transcript.write_field_elements(&self.0)
    }

    fn read(degree: usize, transcript: &mut impl FieldTranscriptRead<F>) -> Result<Self, Error> {
        transcript.read_field_elements(degree + 1).map(Self)
    }

    fn sum(&self) -> F {
        self[1..]
            .iter()
            .fold(self[0].double(), |acc, coeff| acc + coeff)
    }

    fn evaluate(&self, _: &Self::Auxiliary, challenge: &F) -> F {
        horner(&self.0, challenge)
    }
}

impl<'rhs, F: PrimeField> AddAssign<&'rhs F> for Coefficients<F> {
    fn add_assign(&mut self, rhs: &'rhs F) {
        self[0] += rhs;
    }
}

impl<'rhs, F: PrimeField> AddAssign<(&'rhs F, &'rhs Coefficients<F>)> for Coefficients<F> {
    fn add_assign(&mut self, (scalar, rhs): (&'rhs F, &'rhs Coefficients<F>)) {
        if scalar == &F::ONE {
            self.0
                .iter_mut()
                .zip(rhs.0.iter())
                .for_each(|(lhs, rhs)| *lhs += rhs)
        } else if scalar != &F::ZERO {
            self.0
                .iter_mut()
                .zip(rhs.0.iter())
                .for_each(|(lhs, rhs)| *lhs += &(*scalar * rhs))
        }
    }
}

impl_index!(Coefficients, 0);

/// A CoefficientsProver is represented as a polynomial of the form c + sum_i c_i poly_i, where
/// poly_i are represented as product of polynomial expressions.
#[derive(Clone, Debug)]
pub struct CoefficientsProver<F: PrimeField>(F, Vec<(F, Vec<Expression<F>>)>);

impl<F> CoefficientsProver<F>
where
    F: PrimeField,
{
    fn evals(&self, state: &ProverState<F>) -> Vec<F> {
        let mut result = vec![self.0; 1 << state.num_vars];
        // Next, for every product of polynomials, where each product is assumed to be exactly 2
        // put this into h(X).
        if self.1.iter().all(|(_, products)| products.len() == 2) {
            for (scalar, products) in self.1.iter() {
                let [lhs, rhs] = [0, 1].map(|idx| &products[idx]);
                match (lhs, rhs) {
                    (
                        Expression::CommonPolynomial(CommonPolynomial::EqXY(idx)),
                        Expression::Polynomial(query),
                    )
                    | (
                        Expression::Polynomial(query),
                        Expression::CommonPolynomial(CommonPolynomial::EqXY(idx)),
                    ) if query.rotation() == Rotation::cur() => {
                        let lhs = &state.eq_xys[*idx];
                        let rhs = &state.polys[query.poly()][state.num_vars];
                        assert_eq!(lhs.num_vars(), rhs.num_vars());
                        result.iter_mut().enumerate().for_each(|(i, v)| {
                            *v += lhs.evals()[i % lhs.evals().len()]
                                * rhs.evals()[i % rhs.evals().len()]
                                * scalar;
                        })
                    }
                    _ => unimplemented!(),
                }
            }
        } else {
            unimplemented!()
        }
        result
    }
}

impl<F> ClassicSumCheckProver<F> for CoefficientsProver<F>
where
    F: PrimeField,
{
    type RoundMessage = Coefficients<F>;

    fn new(state: &ProverState<F>) -> Self {
        let (constant, flattened) = state.expression.evaluate(
            &|constant| (constant, vec![]),
            &|poly| {
                (
                    F::ZERO,
                    vec![(F::ONE, vec![Expression::CommonPolynomial(poly)])],
                )
            },
            &|query| (F::ZERO, vec![(F::ONE, vec![Expression::Polynomial(query)])]),
            &|challenge| (state.challenges[challenge], vec![]),
            &|(constant, mut products)| {
                products.iter_mut().for_each(|(scalar, _)| {
                    *scalar = -*scalar;
                });
                (-constant, products)
            },
            &|(lhs_constnat, mut lhs_products), (rhs_constant, rhs_products)| {
                lhs_products.extend(rhs_products);
                (lhs_constnat + rhs_constant, lhs_products)
            },
            &|(lhs_constant, lhs_products), (rhs_constant, rhs_products)| {
                let mut outputs =
                    Vec::with_capacity((lhs_products.len() + 1) * (rhs_products.len() + 1));
                for (constant, products) in
                    [(lhs_constant, &rhs_products), (rhs_constant, &lhs_products)]
                {
                    if constant != F::ZERO {
                        outputs.extend(
                            products
                                .iter()
                                .map(|(scalar, polys)| (constant * scalar, polys.clone())),
                        )
                    }
                }
                for ((lhs_scalar, lhs_polys), (rhs_scalar, rhs_polys)) in
                    lhs_products.iter().cartesian_product(rhs_products.iter())
                {
                    outputs.push((
                        *lhs_scalar * rhs_scalar,
                        iter::empty()
                            .chain(lhs_polys)
                            .chain(rhs_polys)
                            .cloned()
                            .collect_vec(),
                    ));
                }
                (lhs_constant * rhs_constant, outputs)
            },
            &|(constant, mut products), rhs| {
                products.iter_mut().for_each(|(lhs, _)| {
                    *lhs *= &rhs;
                });
                (constant * &rhs, products)
            },
        );
        Self(constant, flattened)
    }

    fn prove_round(&self, state: &ProverState<F>) -> Self::RoundMessage {
        // Initialize h(X) to zero
        let mut coeffs = Coefficients(vec![F::ZERO; state.expression.degree() + 1]);
        // First, sum the constant over the hypercube and add to h(X)
        coeffs += &(F::from(state.size() as u64) * &self.0);
        // Next, for every product of polynomials, where each product is assumed to be exactly 2
        // put this into h(X).
        if self.1.iter().all(|(_, products)| products.len() == 2) {
            for (scalar, products) in self.1.iter() {
                let [lhs, rhs] = [0, 1].map(|idx| &products[idx]);
                if cfg!(feature = "sanity-check") {
                    // When LAZY = false, coeffs[1] will also be computed during the process
                    coeffs += (scalar, &self.karatsuba::<false>(state, lhs, rhs));
                } else {
                    coeffs += (scalar, &self.karatsuba::<true>(state, lhs, rhs));
                }
            }
            if cfg!(feature = "sanity-check") {
                assert_eq!(coeffs[0].double() + coeffs[1] + coeffs[2], state.sum);
            } else {
                coeffs[1] = state.sum - coeffs[0].double() - coeffs[2];
            }
        } else {
            unimplemented!()
        }
        coeffs
    }

    fn sum(&self, state: &ProverState<F>) -> F {
        self.evals(state).iter().sum()
    }
}

impl<F: PrimeField> CoefficientsProver<F> {
    /// Given two polynomials, represented as polynomial expressions, compute the coefficients
    /// of their product, with certain variables fixed and other variables summed according to
    /// the state.
    fn karatsuba<const LAZY: bool>(
        &self,
        state: &ProverState<F>,
        lhs: &Expression<F>,
        rhs: &Expression<F>,
    ) -> Coefficients<F> {
        let mut coeffs = [F::ZERO; 3];
        match (lhs, rhs) {
            (
                Expression::CommonPolynomial(CommonPolynomial::EqXY(idx)),
                Expression::Polynomial(query),
            )
            | (
                Expression::Polynomial(query),
                Expression::CommonPolynomial(CommonPolynomial::EqXY(idx)),
            ) if query.rotation() == Rotation::cur() => {
                let lhs = &state.eq_xys[*idx];
                let rhs = &state.polys[query.poly()][state.num_vars];

                // lhs and rhs are guaranteed to have the same number of variables and are both
                // multilinear. However, their number of variables may be smaller than the total
                // number of variables of this sum-check protocol. In that case, simply pretend
                // that the evaluation representations are of the full sizes, by repeating the
                // existing evaluations.

                let evaluate_serial = |coeffs: &mut [F; 3], start: usize, n: usize| {
                    zip_self!(iter::repeat(lhs).flat_map(|x| x.iter()), 2, start * 2)
                        .zip(zip_self!(
                            iter::repeat(rhs).flat_map(|x| x.iter()),
                            2,
                            start * 2
                        ))
                        .take(n)
                        .for_each(|((lhs_0, lhs_1), (rhs_0, rhs_1))| {
                            let coeff_0 = *lhs_0 * rhs_0;
                            let coeff_2 = (*lhs_1 - lhs_0) * &(*rhs_1 - rhs_0);
                            coeffs[0] += &coeff_0;
                            coeffs[2] += &coeff_2;
                            if !LAZY {
                                coeffs[1] += &(*lhs_1 * rhs_1 - &coeff_0 - &coeff_2);
                            }
                        });
                };

                let num_threads = num_threads();
                if state.size() < num_threads {
                    evaluate_serial(&mut coeffs, 0, state.size());
                } else {
                    let chunk_size = div_ceil(state.size(), num_threads);
                    let mut partials = vec![[F::ZERO; 3]; num_threads];
                    parallelize_iter(
                        partials.iter_mut().zip((0..).step_by(chunk_size)),
                        |(partial, start)| {
                            // It is possible that the previous chunks already covers all
                            // the positions
                            if state.size() > start {
                                let chunk_size = chunk_size.min(state.size() - start);
                                evaluate_serial(partial, start, chunk_size);
                            }
                        },
                    );
                    partials.iter().for_each(|partial| {
                        coeffs[0] += partial[0];
                        coeffs[2] += partial[2];
                        if !LAZY {
                            coeffs[1] += partial[1];
                        }
                    })
                };
            }
            _ => unimplemented!(),
        }
        Coefficients(coeffs.to_vec())
    }
}
