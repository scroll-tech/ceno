use crate::{
    poly::multilinear::MultilinearPolynomial,
    sum_check::{SumCheck, VirtualPolynomial},
    util::{
        arithmetic::BooleanHypercube,
        end_timer,
        expression::{Expression, Rotation},
        parallel::par_map_collect,
        start_timer,
        transcript::{FieldTranscriptRead, FieldTranscriptWrite},
    },
    Error,
};
use ff::{Field, PrimeField};
use num_integer::Integer;
use std::{borrow::Cow, collections::HashMap, fmt::Debug, marker::PhantomData};

use itertools::{Itertools};
mod coeff;

pub use coeff::CoefficientsProver;

#[derive(Debug)]
pub struct ProverState<'a, F: Field> {
    num_vars: usize,
    expression: &'a Expression<F>,
    degree: usize,
    sum: F,
    lagranges: HashMap<i32, (usize, F)>,
    identity: F,
    eq_xys: Vec<MultilinearPolynomial<F>>,
    polys: Vec<Vec<Cow<'a, MultilinearPolynomial<F>>>>,
    challenges: &'a [F],
    round: usize,
    bh: BooleanHypercube,
}

impl<'a, F: PrimeField> ProverState<'a, F> {
    fn new(num_vars: usize, sum: F, virtual_poly: VirtualPolynomial<'a, F>) -> Self {
        assert!(num_vars > 0 && virtual_poly.expression.max_used_rotation_distance() <= num_vars);
        let bh = BooleanHypercube::new(num_vars);
        let lagranges = {
            let bh = bh.iter().collect_vec();
            virtual_poly
                .expression
                .used_langrange()
                .into_iter()
                .map(|i| {
                    let b = bh[i.rem_euclid(1 << num_vars) as usize];
                    (i, (b, F::ONE))
                })
                .collect()
        };
        let eq_xys = virtual_poly
            .ys
            .iter()
            .map(|y| MultilinearPolynomial::eq_xy(y))
            .collect_vec();
        let polys = virtual_poly
            .polys
            .iter()
            .map(|poly| {
                let mut polys = vec![Cow::Owned(MultilinearPolynomial::zero()); 2 * num_vars];
                polys[num_vars] = Cow::Borrowed(*poly);
                polys
            })
            .collect_vec();
        Self {
            num_vars,
            expression: virtual_poly.expression,
            degree: virtual_poly.expression.degree(),
            sum,
            lagranges,
            identity: F::ZERO,
            eq_xys,
            polys,
            challenges: virtual_poly.challenges,
            round: 0,
            bh,
        }
    }

    fn size(&self) -> usize {
        1 << (self.num_vars - self.round - 1)
    }

    fn next_round(&mut self, sum: F, challenge: &F) {
        self.sum = sum;
        self.identity += F::from(1 << self.round) * challenge;
        self.lagranges.values_mut().for_each(|(b, value)| {
            if b.is_even() {
                *value *= &(F::ONE - challenge);
            } else {
                *value *= challenge;
            }
            *b >>= 1;
        });
        self.eq_xys.iter_mut().for_each(|eq_xy| {
            if !eq_xy.is_constant() {
                *eq_xy = eq_xy.fix_var(challenge)
            }
        });
        if self.round == 0 {
            let rotation_maps = self
                .expression
                .used_rotation()
                .into_iter()
                .filter_map(|rotation| {
                    (rotation != Rotation::cur())
                        .then(|| (rotation, self.bh.rotation_map(rotation)))
                })
                .collect::<HashMap<_, _>>();
            for query in self.expression.used_query() {
                if query.rotation() != Rotation::cur() {
                    let poly = &self.polys[query.poly()][self.num_vars];
                    let rotated = MultilinearPolynomial::new(par_map_collect(
                        &rotation_maps[&query.rotation()],
                        |b| poly[*b],
                    ))
                    .fix_var(challenge);
                    self.polys[query.poly()]
                        [(query.rotation().0 + self.num_vars as i32) as usize] =
                        Cow::Owned(rotated);
                }
            }
            self.polys.iter_mut().for_each(|polys| {
                polys[self.num_vars] = Cow::Owned(polys[self.num_vars].fix_var(challenge));
            });
        } else {
            self.polys.iter_mut().for_each(|polys| {
                polys.iter_mut().for_each(|poly| {
                    // If it's constant, then fixing a variable is a no-op
                    if !poly.is_constant() {
                        *poly.to_mut() = poly.fix_var(challenge);
                    }
                });
            });
        }
        self.round += 1;
        self.bh = BooleanHypercube::new(self.num_vars - self.round);
    }

    fn into_evals(self) -> Vec<F> {
        assert_eq!(self.round, self.num_vars);
        self.polys
            .iter()
            .map(|polys| polys[self.num_vars][0])
            .collect()
    }
}

pub trait ClassicSumCheckProver<F: Field>: Clone + Debug {
    type RoundMessage: ClassicSumCheckRoundMessage<F>;

    fn new(state: &ProverState<F>) -> Self;

    fn prove_round(&self, state: &ProverState<F>) -> Self::RoundMessage;

    fn sum(&self, state: &ProverState<F>) -> F;
}

pub trait ClassicSumCheckRoundMessage<F: Field>: Sized + Debug {
    type Auxiliary: Default;

    fn write(&self, transcript: &mut impl FieldTranscriptWrite<F>) -> Result<(), Error>;

    fn read(degree: usize, transcript: &mut impl FieldTranscriptRead<F>) -> Result<Self, Error>;

    fn sum(&self) -> F;

    fn auxiliary(_degree: usize) -> Self::Auxiliary {
        Default::default()
    }

    fn evaluate(&self, aux: &Self::Auxiliary, challenge: &F) -> F;

    fn verify_consistency(
        degree: usize,
        mut sum: F,
        msgs: &[Self],
        challenges: &[F],
    ) -> Result<F, Error> {
        let aux = Self::auxiliary(degree);
        for (round, (msg, challenge)) in msgs.iter().zip(challenges.iter()).enumerate() {
            if sum != msg.sum() {
                let msg = if round == 0 {
                    format!("Expect sum {sum:?} but get {:?}", msg.sum())
                } else {
                    format!("Consistency failure at round {round}")
                };
                return Err(Error::InvalidSumcheck(msg));
            }
            sum = msg.evaluate(&aux, challenge);
        }
        Ok(sum)
    }
}

#[derive(Clone, Debug)]
pub struct ClassicSumCheck<P>(PhantomData<P>);

impl<F, P> SumCheck<F> for ClassicSumCheck<P>
where
    F: PrimeField,
    P: ClassicSumCheckProver<F>,
{
    type ProverParam = ();
    type VerifierParam = ();

    fn prove(
        _: &Self::ProverParam,
        num_vars: usize,
        virtual_poly: VirtualPolynomial<F>,
        sum: F,
        transcript: &mut impl FieldTranscriptWrite<F>,
    ) -> Result<(Vec<F>, Vec<F>), Error> {
        let _timer = start_timer(|| {
            let degree = virtual_poly.expression.degree();
            format!("sum_check_prove-{num_vars}-{degree}")
        });

        let mut state = ProverState::new(num_vars, sum, virtual_poly);
        let mut challenges = Vec::with_capacity(num_vars);
        let prover = P::new(&state);

        if cfg!(feature = "sanity-check") {
            assert_eq!(prover.sum(&state), state.sum);
        }

        let aux = P::RoundMessage::auxiliary(state.degree);

        for round in 0..num_vars {
            let timer = start_timer(|| format!("sum_check_prove_round-{round}"));
            let msg = prover.prove_round(&state);
            end_timer(timer);
            msg.write(transcript)?;

            if cfg!(feature = "sanity-check") {
                assert_eq!(
                    msg.evaluate(&aux, &F::ZERO) + msg.evaluate(&aux, &F::ONE),
                    state.sum
                );
            }

            let challenge = transcript.squeeze_challenge();
            challenges.push(challenge);

            let timer = start_timer(|| format!("sum_check_next_round-{round}"));
            state.next_round(msg.evaluate(&aux, &challenge), &challenge);
            end_timer(timer);
        }

        Ok((challenges, state.into_evals()))
    }

    fn verify(
        _: &Self::VerifierParam,
        num_vars: usize,
        degree: usize,
        sum: F,
        transcript: &mut impl FieldTranscriptRead<F>,
    ) -> Result<(F, Vec<F>), Error> {
        let (msgs, challenges) = {
            let mut msgs = Vec::with_capacity(num_vars);
            let mut challenges = Vec::with_capacity(num_vars);
            for _ in 0..num_vars {
                msgs.push(P::RoundMessage::read(degree, transcript)?);
                challenges.push(transcript.squeeze_challenge());
            }
            (msgs, challenges)
        };

        Ok((
            P::RoundMessage::verify_consistency(degree, sum, &msgs, &challenges)?,
            challenges,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        poly::Polynomial,
        sum_check::eq_xy_eval,
        util::{
            arithmetic::inner_product,
            expression::Query,
            transcript::{InMemoryTranscript, Keccak256Transcript},
        },
    };

    use super::*;
    use halo2_curves::bn256::Fr;

    #[test]
    fn test_sum_check_protocol() {
        let polys = vec![
            MultilinearPolynomial::new(vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)]),
            MultilinearPolynomial::new(vec![Fr::from(0), Fr::from(1), Fr::from(1), Fr::from(0)]),
            MultilinearPolynomial::new(vec![Fr::from(0), Fr::from(1)]),
        ];
        let points = vec![vec![Fr::from(1), Fr::from(2)], vec![Fr::from(1)]];
        let expression = Expression::<Fr>::eq_xy(0)
            * Expression::Polynomial(Query::new(0, Rotation::cur()))
            * Fr::from(2)
            + Expression::<Fr>::eq_xy(0)
                * Expression::Polynomial(Query::new(1, Rotation::cur()))
                * Fr::from(3)
            + Expression::<Fr>::eq_xy(1)
                * Expression::Polynomial(Query::new(2, Rotation::cur()))
                * Fr::from(4);
        let virtual_poly = VirtualPolynomial::new(&expression, polys.iter(), &[], &points);
        let sum = inner_product(
            polys[0].evals(),
            MultilinearPolynomial::eq_xy(&points[0]).evals(),
        ) * Fr::from(2)
            + inner_product(
                polys[1].evals(),
                MultilinearPolynomial::eq_xy(&points[0]).evals(),
            ) * Fr::from(3)
            + inner_product(
                polys[2].evals(),
                MultilinearPolynomial::eq_xy(&points[1]).evals(),
            ) * Fr::from(4)
                * Fr::from(2); // The third polynomial is summed twice because the hypercube is larger
        let mut transcript = Keccak256Transcript::<Cursor<Vec<u8>>>::new(());
        let (challenges, evals) = <ClassicSumCheck<CoefficientsProver<Fr>> as SumCheck<Fr>>::prove(
            &(),
            2,
            virtual_poly.clone(),
            sum,
            &mut transcript,
        )
        .unwrap();

        assert_eq!(polys[0].evaluate(&challenges), evals[0]);
        assert_eq!(polys[1].evaluate(&challenges), evals[1]);
        assert_eq!(polys[2].evaluate(&challenges[..1]), evals[2]);

        let proof = transcript.into_proof();
        let mut transcript = Keccak256Transcript::<Cursor<Vec<u8>>>::from_proof((), &proof);

        let (new_sum, verifier_challenges) =
            <ClassicSumCheck<CoefficientsProver<Fr>> as SumCheck<Fr>>::verify(
                &(),
                2,
                2,
                sum,
                &mut transcript,
            )
            .unwrap();

        assert_eq!(verifier_challenges, challenges);
        assert_eq!(
            new_sum,
            evals[0] * eq_xy_eval(&points[0], &challenges[..2]) * Fr::from(2)
                + evals[1] * eq_xy_eval(&points[0], &challenges[..2]) * Fr::from(3)
                + evals[2] * eq_xy_eval(&points[1], &challenges[..1]) * Fr::from(4)
        );

        let mut transcript = Keccak256Transcript::<Cursor<Vec<u8>>>::from_proof((), &proof);

        <ClassicSumCheck<CoefficientsProver<Fr>> as SumCheck<Fr>>::verify(
            &(),
            2,
            2,
            sum + Fr::ONE,
            &mut transcript,
        )
        .expect_err("Should panic");
    }
}
