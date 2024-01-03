use crate::{
    poly::multilinear::MultilinearPolynomial,
    util::{
        arithmetic::{inner_product, powers, product, BooleanHypercube, Field, PrimeField},
        expression::{CommonPolynomial, Expression, Query},
        transcript::{FieldTranscriptRead, FieldTranscriptWrite},
        BitIndex, Itertools,
    },
    Error,
};
use std::{collections::HashMap, fmt::Debug};

pub mod classic;

#[derive(Clone, Debug)]
pub struct VirtualPolynomial<'a, F> {
    expression: &'a Expression<F>,
    polys: Vec<&'a MultilinearPolynomial<F>>,
    challenges: &'a [F],
    ys: &'a [Vec<F>],
}

impl<'a, F: PrimeField> VirtualPolynomial<'a, F> {
    pub fn new(
        expression: &'a Expression<F>,
        polys: impl IntoIterator<Item = &'a MultilinearPolynomial<F>>,
        challenges: &'a [F],
        ys: &'a [Vec<F>],
    ) -> Self {
        Self {
            expression,
            polys: polys.into_iter().collect(),
            challenges,
            ys,
        }
    }
}

pub trait SumCheck<F: Field>: Clone + Debug {
    type ProverParam: Clone + Debug;
    type VerifierParam: Clone + Debug;

    fn prove(
        pp: &Self::ProverParam,
        num_vars: usize,
        virtual_poly: VirtualPolynomial<F>,
        sum: F,
        transcript: &mut impl FieldTranscriptWrite<F>,
    ) -> Result<(Vec<F>, Vec<F>), Error>;

    fn verify(
        vp: &Self::VerifierParam,
        num_vars: usize,
        degree: usize,
        sum: F,
        transcript: &mut impl FieldTranscriptRead<F>,
    ) -> Result<(F, Vec<F>), Error>;
}

pub fn evaluate<F: PrimeField>(
    expression: &Expression<F>,
    num_vars: usize,
    evals: &HashMap<Query, F>,
    challenges: &[F],
    ys: &[&[F]],
    x: &[F],
) -> F {
    assert!(num_vars > 0 && expression.max_used_rotation_distance() <= num_vars);
    let identity = identity_eval(x);
    let lagranges = {
        let bh = BooleanHypercube::new(num_vars).iter().collect_vec();
        expression
            .used_langrange()
            .into_iter()
            .map(|i| {
                let b = bh[i.rem_euclid(1 << num_vars as i32) as usize];
                (i, lagrange_eval(x, b))
            })
            .collect::<HashMap<_, _>>()
    };
    let eq_xys = ys.iter().map(|y| eq_xy_eval(x, y)).collect_vec();
    expression.evaluate(
        &|scalar| scalar,
        &|poly| match poly {
            CommonPolynomial::Identity => identity,
            CommonPolynomial::Lagrange(i) => lagranges[&i],
            CommonPolynomial::EqXY(idx) => eq_xys[idx],
        },
        &|query| evals[&query],
        &|idx| challenges[idx],
        &|scalar| -scalar,
        &|lhs, rhs| lhs + &rhs,
        &|lhs, rhs| lhs * &rhs,
        &|value, scalar| scalar * value,
    )
}

pub fn lagrange_eval<F: PrimeField>(x: &[F], b: usize) -> F {
    assert!(!x.is_empty());

    product(x.iter().enumerate().map(
        |(idx, x_i)| {
            if b.nth_bit(idx) {
                *x_i
            } else {
                F::ONE - x_i
            }
        },
    ))
}

pub fn eq_xy_eval<F: PrimeField>(x: &[F], y: &[F]) -> F {
    assert!(!x.is_empty());
    assert_eq!(x.len(), y.len());

    product(
        x.iter()
            .zip(y)
            .map(|(x_i, y_i)| (*x_i * y_i).double() + F::ONE - x_i - y_i),
    )
}

fn identity_eval<F: PrimeField>(x: &[F]) -> F {
    inner_product(x, &powers(F::from(2)).take(x.len()).collect_vec())
}

#[cfg(test)]
pub(super) mod test {
    use crate::{
        poly::multilinear::{rotation_eval, MultilinearPolynomial},
        sum_check::{evaluate, SumCheck, VirtualPolynomial},
        util::{
            expression::Expression,
            transcript::{InMemoryTranscript, Keccak256Transcript},
        },
    };
    use halo2_curves::bn256::Fr;
    use std::ops::Range;

    pub fn run_sum_check<S: SumCheck<Fr>>(
        num_vars_range: Range<usize>,
        expression_fn: impl Fn(usize) -> Expression<Fr>,
        param_fn: impl Fn(usize) -> (S::ProverParam, S::VerifierParam),
        assignment_fn: impl Fn(usize) -> (Vec<MultilinearPolynomial<Fr>>, Vec<Fr>, Vec<Fr>),
        sum: Fr,
    ) {
        for num_vars in num_vars_range {
            let expression = expression_fn(num_vars);
            let degree = expression.degree();
            let (pp, vp) = param_fn(expression.degree());
            let (polys, challenges, y) = assignment_fn(num_vars);
            let ys = [y];
            let proof = {
                let virtual_poly = VirtualPolynomial::new(&expression, &polys, &challenges, &ys);
                let mut transcript = Keccak256Transcript::default();
                S::prove(&pp, num_vars, virtual_poly, sum, &mut transcript).unwrap();
                transcript.into_proof()
            };
            let accept = {
                let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
                let (x_eval, x) =
                    S::verify(&vp, num_vars, degree, Fr::zero(), &mut transcript).unwrap();
                let evals = expression
                    .used_query()
                    .into_iter()
                    .map(|query| {
                        let evaluate_for_rotation =
                            polys[query.poly()].evaluate_for_rotation(&x, query.rotation());
                        let eval = rotation_eval(&x, query.rotation(), &evaluate_for_rotation);
                        (query, eval)
                    })
                    .collect();
                x_eval == evaluate(&expression, num_vars, &evals, &challenges, &[&ys[0]], &x)
            };
            assert!(accept);
        }
    }

    pub fn run_zero_check<S: SumCheck<Fr>>(
        num_vars_range: Range<usize>,
        expression_fn: impl Fn(usize) -> Expression<Fr>,
        param_fn: impl Fn(usize) -> (S::ProverParam, S::VerifierParam),
        assignment_fn: impl Fn(usize) -> (Vec<MultilinearPolynomial<Fr>>, Vec<Fr>, Vec<Fr>),
    ) {
        run_sum_check::<S>(
            num_vars_range,
            expression_fn,
            param_fn,
            assignment_fn,
            Fr::zero(),
        )
    }

    macro_rules! tests {
        ($impl:ty) => {
            #[test]
            fn sum_check_lagrange() {
                use halo2_curves::bn256::Fr;
                use $crate::{
                    poly::multilinear::MultilinearPolynomial,
                    sum_check::test::run_zero_check,
                    util::{
                        arithmetic::{BooleanHypercube, Field},
                        expression::{CommonPolynomial, Expression, Query, Rotation},
                        test::{rand_vec, seeded_std_rng},
                        Itertools,
                    },
                };

                run_zero_check::<$impl>(
                    2..4,
                    |num_vars| {
                        let polys = (0..1 << num_vars)
                            .map(|idx| {
                                Expression::<Fr>::Polynomial(Query::new(idx, Rotation::cur()))
                            })
                            .collect_vec();
                        let gates = polys
                            .iter()
                            .enumerate()
                            .map(|(i, poly)| {
                                Expression::CommonPolynomial(CommonPolynomial::Lagrange(i as i32))
                                    - poly
                            })
                            .collect_vec();
                        let alpha = Expression::Challenge(0);
                        let eq = Expression::eq_xy(0);
                        Expression::distribute_powers(&gates, &alpha) * eq
                    },
                    |_| ((), ()),
                    |num_vars| {
                        let polys = BooleanHypercube::new(num_vars)
                            .iter()
                            .map(|idx| {
                                let mut polys =
                                    MultilinearPolynomial::new(vec![Fr::zero(); 1 << num_vars]);
                                polys[idx] = Fr::one();
                                polys
                            })
                            .collect_vec();
                        let alpha = Fr::random(seeded_std_rng());
                        (polys, vec![alpha], rand_vec(num_vars, seeded_std_rng()))
                    },
                );
            }

            #[test]
            fn sum_check_rotation() {
                use halo2_curves::bn256::Fr;
                use std::iter;
                use $crate::{
                    poly::multilinear::MultilinearPolynomial,
                    sum_check::test::run_zero_check,
                    util::{
                        arithmetic::{BooleanHypercube, Field},
                        expression::{Expression, Query, Rotation},
                        test::{rand_vec, seeded_std_rng},
                        Itertools,
                    },
                };

                run_zero_check::<$impl>(
                    2..16,
                    |num_vars| {
                        let polys = (-(num_vars as i32) + 1..num_vars as i32)
                            .rev()
                            .enumerate()
                            .map(|(idx, rotation)| {
                                Expression::<Fr>::Polynomial(Query::new(idx, rotation.into()))
                            })
                            .collect_vec();
                        let gates = polys
                            .windows(2)
                            .map(|polys| &polys[1] - &polys[0])
                            .collect_vec();
                        let alpha = Expression::Challenge(0);
                        let eq = Expression::eq_xy(0);
                        Expression::distribute_powers(&gates, &alpha) * eq
                    },
                    |_| ((), ()),
                    |num_vars| {
                        let bh = BooleanHypercube::new(num_vars);
                        let rotate = |f: &Vec<Fr>| {
                            (0..1 << num_vars)
                                .map(|idx| f[bh.rotate(idx, Rotation::next())])
                                .collect_vec()
                        };
                        let poly = rand_vec(1 << num_vars, seeded_std_rng());
                        let polys = iter::successors(Some(poly), |poly| Some(rotate(poly)))
                            .map(MultilinearPolynomial::new)
                            .take(2 * num_vars - 1)
                            .collect_vec();
                        let alpha = Fr::random(seeded_std_rng());
                        (polys, vec![alpha], rand_vec(num_vars, seeded_std_rng()))
                    },
                );
            }

            // #[test]
            // fn sum_check_vanilla_plonk() {
            //     use halo2_curves::bn256::Fr;
            //     use $crate::{
            //         backend::hyperplonk::util::{
            //             rand_vanilla_plonk_assignment, vanilla_plonk_expression,
            //         },
            //         sum_check::test::run_zero_check,
            //         util::test::{rand_vec, seeded_std_rng},
            //     };

            //     run_zero_check::<$impl>(
            //         2..16,
            //         |num_vars| vanilla_plonk_expression(num_vars),
            //         |_| ((), ()),
            //         |num_vars| {
            //             let (polys, challenges) = rand_vanilla_plonk_assignment(
            //                 num_vars,
            //                 seeded_std_rng(),
            //                 seeded_std_rng(),
            //             );
            //             (polys, challenges, rand_vec(num_vars, seeded_std_rng()))
            //         },
            //     );
            // }

            // #[test]
            // fn sum_check_vanilla_plonk_with_lookup() {
            //     use halo2_curves::bn256::Fr;
            //     use $crate::{
            //         backend::hyperplonk::util::{
            //             rand_vanilla_plonk_with_lookup_assignment,
            //             vanilla_plonk_with_lookup_expression,
            //         },
            //         sum_check::test::run_zero_check,
            //         util::test::{rand_vec, seeded_std_rng},
            //     };

            //     run_zero_check::<$impl>(
            //         2..16,
            //         |num_vars| vanilla_plonk_with_lookup_expression(num_vars),
            //         |_| ((), ()),
            //         |num_vars| {
            //             let (polys, challenges) = rand_vanilla_plonk_with_lookup_assignment(
            //                 num_vars,
            //                 seeded_std_rng(),
            //                 seeded_std_rng(),
            //             );
            //             (polys, challenges, rand_vec(num_vars, seeded_std_rng()))
            //         },
            //     );
            // }
        };
    }

    pub(super) use tests;
}
