use crate::{
    sum_check::classic::{ClassicSumCheckProver, ClassicSumCheckRoundMessage, ProverState},
    util::{
        arithmetic::{
            barycentric_interpolate, barycentric_weights, div_ceil, steps, BooleanHypercube,
            PrimeField,
        },
        expression::{
            evaluator::{ExpressionRegistry, Offsets},
            CommonPolynomial, Expression,
        },
        impl_index,
        parallel::{num_threads, parallelize_iter},
        transcript::{FieldTranscriptRead, FieldTranscriptWrite},
    },
    Error,
};
use num_integer::Integer;
use std::{collections::BTreeSet, fmt::Debug, iter, ops::AddAssign};

#[derive(Clone, Debug)]
pub struct Evaluations<F>(Vec<F>);

impl<F: PrimeField> Evaluations<F> {
    fn new(degree: usize) -> Self {
        Self(vec![F::ZERO; degree + 1])
    }

    fn points(degree: usize) -> Vec<F> {
        steps(F::ZERO).take(degree + 1).collect()
    }
}

impl<F: PrimeField> ClassicSumCheckRoundMessage<F> for Evaluations<F> {
    type Auxiliary = (Vec<F>, Vec<F>);

    fn write(&self, transcript: &mut impl FieldTranscriptWrite<F>) -> Result<(), Error> {
        transcript.write_field_elements(&self.0)
    }

    fn read(degree: usize, transcript: &mut impl FieldTranscriptRead<F>) -> Result<Self, Error> {
        transcript.read_field_elements(degree + 1).map(Self)
    }

    fn sum(&self) -> F {
        self[0] + self[1]
    }

    fn auxiliary(degree: usize) -> Self::Auxiliary {
        let points = Self::points(degree);
        (barycentric_weights(&points), points)
    }

    fn evaluate(&self, (weights, points): &Self::Auxiliary, challenge: &F) -> F {
        barycentric_interpolate(weights, points, &self.0, challenge)
    }
}

impl<'rhs, F: PrimeField> AddAssign<&'rhs Evaluations<F>> for Evaluations<F> {
    fn add_assign(&mut self, rhs: &'rhs Evaluations<F>) {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(lhs, rhs)| *lhs += rhs);
    }
}

impl_index!(Evaluations, 0);

#[derive(Clone, Debug)]
pub struct EvaluationsProver<F: PrimeField>(Vec<SumCheckEvaluator<F>>);

impl<F> ClassicSumCheckProver<F> for EvaluationsProver<F>
where
    F: PrimeField,
{
    type RoundMessage = Evaluations<F>;

    fn new(state: &ProverState<F>) -> Self {
        let (dense, sparse) = split_sparse(state);
        Self(
            iter::empty()
                .chain(Some((&dense, false)))
                .chain(sparse.iter().zip(iter::repeat(true)))
                .filter_map(|(expression, is_sparse)| {
                    SumCheckEvaluator::new(state.num_vars, state.challenges, expression, is_sparse)
                })
                .collect(),
        )
    }

    fn prove_round(&self, state: &ProverState<F>) -> Evaluations<F> {
        if state.round > 0 {
            self.evals::<false>(state)
        } else {
            self.evals::<true>(state)
        }
    }
}

impl<F: PrimeField> EvaluationsProver<F> {
    fn evals<const IS_FIRST_ROUND: bool>(&self, state: &ProverState<F>) -> Evaluations<F> {
        let mut evals = Evaluations::new(state.degree);

        let size = state.size();
        let chunk_size = div_ceil(size, num_threads());
        let mut partials = vec![Evaluations::new(state.degree); div_ceil(size, chunk_size)];
        for ev in self.0.iter() {
            if let Some(sparse_bs) = ev.sparse_bs(state) {
                let mut cache = ev.cache(state);
                sparse_bs.into_iter().for_each(|b| {
                    ev.evaluate::<IS_FIRST_ROUND>(&mut partials[0], &mut cache, state, b)
                })
            } else {
                parallelize_iter(
                    partials.iter_mut().zip((0..).step_by(chunk_size)),
                    |(partials, start)| {
                        let bs = start..(start + chunk_size).min(size);
                        let mut cache = ev.cache(state);
                        bs.for_each(|b| {
                            ev.evaluate::<IS_FIRST_ROUND>(partials, &mut cache, state, b)
                        })
                    },
                );
            }
        }
        partials.iter().for_each(|partials| evals += partials);

        evals[0] = state.sum - evals[1];
        evals
    }
}

#[derive(Clone, Debug, Default)]
struct SumCheckEvaluator<F: PrimeField> {
    num_vars: usize,
    reg: ExpressionRegistry<F>,
    sparse: Option<Expression<F>>,
}

impl<F: PrimeField> SumCheckEvaluator<F> {
    fn new(
        num_vars: usize,
        challenges: &[F],
        expression: &Expression<F>,
        is_sparse: bool,
    ) -> Option<Self> {
        let expression = expression.simplified(Some(challenges))?;
        let mut reg = ExpressionRegistry::new();
        reg.register(&expression);

        let sparse = is_sparse.then_some(expression);

        Some(Self {
            num_vars,
            reg,
            sparse,
        })
    }

    fn sparse_bs(&self, state: &ProverState<F>) -> Option<Vec<usize>> {
        self.sparse.as_ref().map(|sparse| {
            sparse
                .evaluate(
                    &|_| None,
                    &|poly| match poly {
                        CommonPolynomial::Identity => unimplemented!(),
                        CommonPolynomial::Lagrange(i) => Some(vec![state.lagranges[&i].0 >> 1]),
                        _ => None,
                    },
                    &|_| None,
                    &|_| None,
                    &|bs| bs,
                    &|lhs, rhs| match (lhs, rhs) {
                        (None, None) => None,
                        (Some(bs), None) | (None, Some(bs)) => Some(bs),
                        (Some(mut lhs), Some(rhs)) => {
                            lhs.extend(rhs);
                            Some(lhs)
                        }
                    },
                    &|lhs, rhs| match (lhs, rhs) {
                        (None, None) => None,
                        (Some(bs), None) | (None, Some(bs)) => Some(bs),
                        (Some(lhs), Some(rhs)) => Some(
                            BTreeSet::from_iter(lhs)
                                .intersection(&BTreeSet::from_iter(rhs))
                                .cloned()
                                .collect(),
                        ),
                    },
                    &|bs, _| bs,
                )
                .unwrap()
        })
    }

    fn cache(&self, state: &ProverState<F>) -> EvaluatorCache<F> {
        EvaluatorCache {
            offsets: *self.reg.offsets(),
            bs: vec![(0, 0); self.reg.rotations().len()],
            identity_step: F::from(1 << state.round),
            lagrange_steps: vec![F::ZERO; self.reg.lagranges().len()],
            eq_xy_steps: vec![F::ZERO; self.reg.eq_xys().len()],
            poly_steps: vec![F::ZERO; self.reg.polys().len()],
            cache: self.reg.cache(),
        }
    }

    fn evaluate_polys_next<const IS_FIRST_ROUND: bool, const IS_FIRST_POINT: bool>(
        &self,
        cache: &mut EvaluatorCache<F>,
        state: &ProverState<F>,
        b: usize,
    ) {
        if IS_FIRST_ROUND && IS_FIRST_POINT {
            let bh = BooleanHypercube::new(self.num_vars);
            cache
                .bs
                .iter_mut()
                .zip(self.reg.rotations())
                .for_each(|(bs, rotation)| {
                    let [b_0, b_1] = [b << 1, (b << 1) + 1].map(|b| bh.rotate(b, *rotation));
                    *bs = (b_0, b_1);
                });
        }

        if IS_FIRST_POINT {
            let (b_0, b_1) = if IS_FIRST_ROUND {
                cache.bs[0]
            } else {
                (b << 1, (b << 1) + 1)
            };
            cache.cache[cache.offsets.identity()] =
                state.identity + F::from(((1 << state.round) + (b << (state.round + 1))) as u64);
            cache
                .lagrange_iter_mut()
                .zip(self.reg.lagranges())
                .for_each(|((eval, step), i)| {
                    let lagrange = &state.lagranges[i];
                    if b == lagrange.0 >> 1 {
                        if lagrange.0.is_even() {
                            *step = -lagrange.1;
                        } else {
                            *eval = lagrange.1;
                            *step = lagrange.1;
                        }
                    } else {
                        *eval = F::ZERO;
                        *step = F::ZERO;
                    }
                });
            cache
                .eq_xy_iter_mut()
                .zip(self.reg.eq_xys())
                .for_each(|((eval, step), idx)| {
                    *eval = state.eq_xys[*idx][b_1];
                    *step = state.eq_xys[*idx][b_1] - &state.eq_xys[*idx][b_0];
                });
            cache.poly_iter_mut().zip(self.reg.polys()).for_each(
                |(((eval, step), bs), (query, rotation))| {
                    if IS_FIRST_ROUND {
                        let (b_0, b_1) = bs[*rotation];
                        let poly = &state.polys[query.poly()][self.num_vars];
                        *eval = poly[b_1];
                        *step = poly[b_1] - &poly[b_0];
                    } else {
                        let rotation = (self.num_vars as i32 + query.rotation().0) as usize;
                        let poly = &state.polys[query.poly()][rotation];
                        *eval = poly[b_1];
                        *step = poly[b_1] - &poly[b_0];
                    }
                },
            );
        } else {
            cache.cache[cache.offsets.identity()] += &cache.identity_step;
            cache
                .lagrange_iter_mut()
                .for_each(|(eval, step)| *eval += step as &_);
            cache
                .eq_xy_iter_mut()
                .for_each(|(eval, step)| *eval += step as &_);
            cache
                .poly_iter_mut()
                .for_each(|((eval, step), _)| *eval += step as &_);
        }
    }

    fn evaluate_next<const IS_FIRST_ROUND: bool, const IS_FIRST_POINT: bool>(
        &self,
        eval: &mut F,
        state: &ProverState<F>,
        cache: &mut EvaluatorCache<F>,
        b: usize,
    ) {
        self.evaluate_polys_next::<IS_FIRST_ROUND, IS_FIRST_POINT>(cache, state, b);

        for (calculation, idx) in self
            .reg
            .indexed_calculations()
            .iter()
            .zip(self.reg.offsets().calculations()..)
        {
            calculation.calculate(&mut cache.cache, idx);
        }
        *eval += cache.cache.last().unwrap();
    }

    fn evaluate<const IS_FIRST_ROUND: bool>(
        &self,
        evals: &mut Evaluations<F>,
        cache: &mut EvaluatorCache<F>,
        state: &ProverState<F>,
        b: usize,
    ) {
        debug_assert!(evals.0.len() > 2);

        self.evaluate_next::<IS_FIRST_ROUND, true>(&mut evals[1], state, cache, b);
        for eval in evals[2..].iter_mut() {
            self.evaluate_next::<IS_FIRST_ROUND, false>(eval, state, cache, b);
        }
    }
}

#[derive(Debug, Default)]
struct EvaluatorCache<F: PrimeField> {
    offsets: Offsets,
    bs: Vec<(usize, usize)>,
    identity_step: F,
    lagrange_steps: Vec<F>,
    eq_xy_steps: Vec<F>,
    poly_steps: Vec<F>,
    cache: Vec<F>,
}

impl<F: PrimeField> EvaluatorCache<F> {
    fn lagrange_iter_mut(&mut self) -> impl Iterator<Item = (&mut F, &mut F)> {
        self.cache[self.offsets.lagranges()..]
            .iter_mut()
            .zip(self.lagrange_steps.iter_mut())
    }

    fn eq_xy_iter_mut(&mut self) -> impl Iterator<Item = (&mut F, &mut F)> {
        self.cache[self.offsets.eq_xys()..]
            .iter_mut()
            .zip(self.eq_xy_steps.iter_mut())
    }

    fn poly_iter_mut(&mut self) -> impl Iterator<Item = ((&mut F, &mut F), &[(usize, usize)])> {
        self.cache[self.offsets.polys()..]
            .iter_mut()
            .zip(self.poly_steps.iter_mut())
            .zip(iter::repeat(self.bs.as_slice()))
    }
}

fn split_sparse<F: PrimeField>(state: &ProverState<F>) -> (Expression<F>, Vec<Expression<F>>) {
    state.expression.evaluate(
        &|constant| (Expression::Constant(constant), Vec::new()),
        &|poly| {
            if matches!(poly, CommonPolynomial::Lagrange(_)) {
                (Expression::zero(), vec![Expression::CommonPolynomial(poly)])
            } else {
                (poly.into(), Vec::new())
            }
        },
        &|query| {
            // TODO: Recognize sparse selectors
            (query.into(), Vec::new())
        },
        &|challenge| (Expression::Challenge(challenge), Vec::new()),
        &|(dense, sparse)| (-dense, sparse.iter().map(|sparse| -sparse).collect()),
        &|(lhs_dense, lhs_sparse), (rhs_dense, rhs_sparse)| {
            (lhs_dense + rhs_dense, [lhs_sparse, rhs_sparse].concat())
        },
        &|(lhs_dense, lhs_sparse), (rhs_dense, rhs_sparse)| match (
            lhs_dense, lhs_sparse, rhs_dense, rhs_sparse,
        ) {
            (lhs_dense, sparse, rhs_dense, empty) | (rhs_dense, empty, lhs_dense, sparse)
                if empty.is_empty() =>
            {
                let sparse = sparse.iter().map(|sparse| sparse * &rhs_dense).collect();
                (lhs_dense * &rhs_dense, sparse)
            }
            (lhs_dense, lhs_sparse, rhs_dense, rhs_sparse) => {
                let lhs = lhs_dense + lhs_sparse.into_iter().sum::<Expression<_>>();
                let rhs = rhs_dense + rhs_sparse.into_iter().sum::<Expression<_>>();
                (lhs * rhs, Vec::new())
            }
        },
        &|(dense, sparse), scalar| {
            let sparse = sparse.iter().map(|sparse| sparse * scalar).collect();
            (dense * scalar, sparse)
        },
    )
}

#[cfg(test)]
mod test {
    use crate::sum_check::{
        classic::{ClassicSumCheck, EvaluationsProver},
        test::tests,
    };

    tests!(ClassicSumCheck<EvaluationsProver<Fr>>);
}
