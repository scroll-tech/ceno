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
