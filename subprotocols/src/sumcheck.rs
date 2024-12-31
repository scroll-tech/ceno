use std::{iter, mem, sync::Arc, vec};

use ark_std::log2;
use ff_ext::ExtensionField;
use itertools::chain;
use transcript::Transcript;

use crate::{
    error::VerifierError,
    expression::{Expression, Point},
    utils::eq_vecs,
};

use super::utils::{fix_variables_ext, fix_variables_inplace, interpolate_uni_poly};

/// This is an randomly combined sumcheck protocol for the following equation:
/// \sigma = \sum_x (r^0 expr_0(x) + r^1 expr_1(x) + ...)
pub struct SumcheckProverState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    /// Expression.
    expr: Expression,

    /// Extension field mles.
    ext_mles: Vec<&'a mut [E]>,
    /// Base field mles after the first round.
    base_mles_after: Vec<Vec<E>>,
    /// Base field mles.
    base_mles: Vec<&'a [E::BaseField]>,
    /// Eq polys
    eqs: &'a mut [Vec<E>],
    /// Challenges occurred in expressions
    challenges: &'a [E],

    transcript: &'a mut Trans,

    degree: usize,
    num_vars: usize,
}

pub struct SumcheckProof<E: ExtensionField> {
    /// Messages for each round.
    pub univariate_polys: Vec<Vec<Vec<E>>>,
    pub ext_mle_evals: Vec<E>,
    pub base_mle_evals: Vec<E>,
}

pub struct SumcheckProverOutput<E: ExtensionField> {
    pub proof: SumcheckProof<E>,
    pub point: Point<E>,
}

impl<'a, E, Trans> SumcheckProverState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expr: Expression,
        points: &[&[E]],
        ext_mles: Vec<&'a mut [E]>,
        base_mles: Vec<&'a [E::BaseField]>,
        challenges: &'a [E],
        transcript: &'a mut Trans,
        eqs: &'a mut [Vec<E>],
        eq_evals_first_part: &mut [E],
        eq_evals_second_part: &mut [E],
    ) -> Self {
        assert!(!(ext_mles.is_empty() && base_mles.is_empty()));

        let num_vars = if !ext_mles.is_empty() {
            log2(ext_mles[0].len()) as usize
        } else {
            log2(base_mles[0].len()) as usize
        };

        // The length of all mles should be 2^{num_vars}.
        assert!(ext_mles.iter().all(|mle| mle.len() == 1 << num_vars));
        assert!(base_mles.iter().all(|mle| mle.len() == 1 << num_vars));

        let degree = expr.degree();

        assert!(eqs.len() >= points.len());
        eq_vecs(
            points.iter().copied(),
            &vec![E::ONE; points.len()],
            eqs,
            eq_evals_first_part,
            eq_evals_second_part,
        );

        Self {
            expr,
            ext_mles,
            base_mles_after: vec![],
            base_mles,
            eqs,
            challenges,
            transcript,
            num_vars,
            degree,
        }
    }

    pub fn prove(mut self) -> SumcheckProverOutput<E> {
        let (univariate_polys, point) = (0..self.num_vars)
            .map(|round| {
                let round_msg = self.compute_univariate_poly(round);
                self.transcript.append_field_element_exts(&round_msg);

                let r = self
                    .transcript
                    .get_and_append_challenge(b"sumcheck round")
                    .elements;
                self.update_mles(&r, round);
                (vec![round_msg], r)
            })
            .unzip();
        let point = Arc::new(point);

        // Send the final evaluations
        let SumcheckProverState {
            ext_mles,
            base_mles_after,
            base_mles,
            ..
        } = self;
        let ext_mle_evaluations = ext_mles.into_iter().map(|mle| mle[0]).collect();
        let base_mle_evaluations = if !base_mles.is_empty() {
            base_mles.into_iter().map(|mle| E::from(mle[0])).collect()
        } else {
            base_mles_after.into_iter().map(|mle| mle[0]).collect()
        };

        SumcheckProverOutput {
            proof: SumcheckProof {
                univariate_polys,
                ext_mle_evals: ext_mle_evaluations,
                base_mle_evals: base_mle_evaluations,
            },
            point,
        }
    }

    /// Compute f(X) = r^0 \sum_x expr_0(X || x) + r^1 \sum_x expr_1(X || x) + ...
    fn compute_univariate_poly(&self, round: usize) -> Vec<E> {
        self.expr.sumcheck_uni_poly(
            &self.ext_mles,
            &self.base_mles_after,
            &self.base_mles,
            self.eqs,
            self.challenges,
            1 << (self.num_vars - round),
            self.degree,
        )
    }

    fn update_mles(&mut self, r: &E, round: usize) {
        // fix variables of eq polynomials
        self.eqs.iter_mut().for_each(|eq| {
            fix_variables_inplace(eq, r);
        });
        // fix variables of ext field polynomials.
        self.ext_mles.iter_mut().for_each(|mle| {
            fix_variables_inplace(mle, r);
        });
        // fix variables of base field polynomials.
        if round == 0 {
            self.base_mles_after = mem::take(&mut self.base_mles)
                .into_iter()
                .map(|mle| fix_variables_ext(mle, r))
                .collect();
        } else {
            self.base_mles_after
                .iter_mut()
                .for_each(|mle| fix_variables_inplace(mle, r));
        }
    }
}

pub struct SumcheckVerifierState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    sigma: E,
    expr: Expression,
    proof: SumcheckProof<E>,
    challenges: &'a [E],
    transcript: &'a mut Trans,
    out_points: Vec<&'a [E]>,
}

pub struct SumcheckClaims<E: ExtensionField> {
    pub in_point: Point<E>,
    pub base_mle_evals: Vec<E>,
    pub ext_mle_evals: Vec<E>,
}

impl<'a, E, Trans> SumcheckVerifierState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    pub fn new(
        sigma: E,
        expr: Expression,
        out_points: Vec<&'a [E]>,
        proof: SumcheckProof<E>,
        challenges: &'a [E],
        transcript: &'a mut Trans,
    ) -> Self {
        Self {
            sigma,
            expr,
            proof,
            challenges,
            transcript,
            out_points,
        }
    }

    pub fn verify(self) -> Result<SumcheckClaims<E>, VerifierError<E>> {
        let SumcheckVerifierState {
            sigma,
            expr,
            proof,
            challenges,
            transcript,
            out_points,
        } = self;
        let SumcheckProof {
            univariate_polys,
            ext_mle_evals,
            base_mle_evals,
        } = proof;

        let (in_point, expected_claim) = univariate_polys.into_iter().fold(
            (vec![], sigma),
            |(mut last_point, last_sigma), msg| {
                let msg = msg.into_iter().next().unwrap();
                transcript.append_field_element_exts(&msg);

                let len = msg.len() + 1;
                let eval_at_0 = last_sigma - msg[0];

                // Evaluations on degree, degree - 1, ..., 1, 0.
                let evals_iter_rev = chain![msg.into_iter().rev(), iter::once(eval_at_0)];

                let r = transcript
                    .get_and_append_challenge(b"sumcheck round")
                    .elements;
                let sigma = interpolate_uni_poly(evals_iter_rev, len, r);
                last_point.push(r);
                (last_point, sigma)
            },
        );

        // Check the final evaluations.
        let got_claim = expr.evaluate(
            &ext_mle_evals,
            &base_mle_evals,
            &out_points,
            &in_point,
            challenges,
        );
        if expected_claim != got_claim {
            return Err(VerifierError::ClaimNotMatch(
                expr,
                expected_claim,
                got_claim,
            ));
        }

        let in_point = Arc::new(in_point);
        Ok(SumcheckClaims {
            in_point,
            base_mle_evals,
            ext_mle_evals,
        })
    }
}

#[cfg(test)]
mod test {
    use std::array;

    use ff::Field;
    use ff_ext::ExtensionField;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use itertools::{Itertools, izip};
    use transcript::BasicTranscript;

    use crate::{
        expression::{Constant, Expression, Witness},
        field_vec,
        utils::eq_vecs,
    };

    use super::{SumcheckProverOutput, SumcheckProverState, SumcheckVerifierState};

    #[allow(clippy::too_many_arguments)]
    fn run<E: ExtensionField>(
        points: Vec<&[E]>,
        expr: Expression,
        ext_mle_refs: Vec<&mut [E]>,
        base_mle_refs: Vec<&[E::BaseField]>,
        challenges: Vec<E>,

        eqs: &mut [Vec<E>],
        eq_evals_first_part: &mut [E],
        eq_evals_second_part: &mut [E],

        sigma: E,
    ) {
        let mut prover_transcript = BasicTranscript::new(b"test");
        let prover = SumcheckProverState::new(
            expr.clone(),
            &points,
            ext_mle_refs,
            base_mle_refs,
            &challenges,
            &mut prover_transcript,
            eqs,
            eq_evals_first_part,
            eq_evals_second_part,
        );

        let SumcheckProverOutput { proof, .. } = prover.prove();

        let mut verifier_transcript = BasicTranscript::new(b"test");
        let verifier = SumcheckVerifierState::new(
            sigma,
            expr,
            points,
            proof,
            &challenges,
            &mut verifier_transcript,
        );

        verifier.verify().expect("verification failed");
    }

    #[test]
    fn test_sumcheck_trivial() {
        let f = field_vec![F, 2];
        let g = field_vec![F, 3];
        let out_point = vec![];

        let mut eq_evals_first_part = [];
        let mut eq_evals_second_part = [];
        let mut eqs = [vec![]];

        let base_mle_refs = vec![f.as_slice(), g.as_slice()];
        let f = Expression::Wit(Witness::BasePoly(0));
        let g = Expression::Wit(Witness::BasePoly(1));
        let expr = f * g;

        run(
            vec![out_point.as_slice()],
            expr,
            vec![],
            base_mle_refs,
            vec![],
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
            E::from(6),
        );
    }

    #[test]
    fn test_sumcheck_simple() {
        let f = field_vec![F, 1, 2, 3, 4];
        let ans = E::from(f.iter().fold(F::ZERO, |acc, x| acc + x));
        let base_mle_refs = vec![f.as_slice()];
        let expr = Expression::Wit(Witness::BasePoly(0));

        let mut eq_evals_first_part = vec![];
        let mut eq_evals_second_part = vec![];
        let mut eqs = [];

        run(
            vec![],
            expr,
            vec![],
            base_mle_refs,
            vec![],
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
            ans,
        );
    }

    #[test]
    fn test_sumcheck_logup() {
        let num_vars = 2;
        let point = field_vec![E, 2, 3];

        let mut eq_evals_first_part = vec![E::ZERO; 1 << (num_vars >> 1)];
        let mut eq_evals_second_part = vec![E::ZERO; 1 << (num_vars - (num_vars >> 1))];
        let mut eqs = [vec![E::ZERO; 1 << num_vars]];

        eq_vecs(
            [point.as_slice()].into_iter(),
            &[E::ONE],
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
        );

        let d0 = field_vec![E, 1, 2, 3, 4];
        let d1 = field_vec![E, 5, 6, 7, 8];
        let n0 = field_vec![E, 9, 10, 11, 12];
        let n1 = field_vec![E, 13, 14, 15, 16];

        let challenges = vec![E::from(7)];
        let ans = izip!(&eqs[0], &d0, &d1, &n0, &n1)
            .map(|(eq, d0, d1, n0, n1)| *eq * (*d0 * *d1 + challenges[0] * (*d0 * *n1 + *d1 * *n0)))
            .sum();

        let mut ext_mles = [d0, d1, n0, n1];
        let [d0, d1, n0, n1] = array::from_fn(|i| Expression::Wit(Witness::ExtPoly(i)));
        let eq = Expression::Wit(Witness::EqPoly(0));
        let beta = Expression::Const(Constant::Challenge(0));

        let expr = eq * (d0.clone() * d1.clone() + beta * (d0 * n1 + d1 * n0));

        let ext_mle_refs = ext_mles.iter_mut().map(|v| v.as_mut_slice()).collect_vec();
        run(
            vec![point.as_slice()],
            expr,
            ext_mle_refs,
            vec![],
            challenges,
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
            ans,
        );
    }

    #[test]
    fn test_sumcheck_multi_points() {
        let num_vars = 2;
        let num_exprs = 3;

        let challenges = vec![E::from(2)];

        let points = [field_vec![E, 2, 3], field_vec![E, 5, 7], field_vec![
            E, 2, 5
        ]];
        let point_refs = points.iter().map(|v| v.as_slice()).collect_vec();

        let mut eq_evals_first_part = vec![E::ZERO; 1 << (num_vars >> 1)];
        let mut eq_evals_second_part = vec![E::ZERO; 1 << (num_vars - (num_vars >> 1))];
        let mut eqs = vec![vec![E::ZERO; 1 << num_vars]; num_exprs];
        eq_vecs(
            point_refs.clone().into_iter(),
            &vec![E::ONE; points.len()],
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
        );

        let d0 = field_vec![F, 1, 2, 3, 4];
        let d1 = field_vec![F, 5, 6, 7, 8];
        let n0 = field_vec![F, 9, 10, 11, 12];
        let n1 = field_vec![F, 13, 14, 15, 16];

        let ans_0 = izip!(&eqs[0], &d0, &d1)
            .map(|(eq0, d0, d1)| eq0 * d0 * d1)
            .sum::<E>();
        let ans_1 = izip!(&eqs[1], &d0, &n1)
            .map(|(eq1, d0, n1)| eq1 * d0 * n1)
            .sum::<E>();
        let ans_2 = izip!(&eqs[2], &d1, &n0)
            .map(|(eq2, d1, n0)| eq2 * d1 * n0)
            .sum::<E>();
        let ans = (ans_0 * challenges[0] + ans_1) * challenges[0] + ans_2;

        let base_mles = [d0, d1, n0, n1];
        let [eq0, eq1, eq2] = array::from_fn(|i| Expression::Wit(Witness::EqPoly(i)));
        let [d0, d1, n0, n1] = array::from_fn(|i| Expression::Wit(Witness::BasePoly(i)));
        let rlc_challenge = Expression::Const(Constant::Challenge(0));

        let expr = (eq0 * d0.clone() * d1.clone() * rlc_challenge.clone() + eq1 * d0 * n1)
            * rlc_challenge
            + eq2 * d1 * n0;

        let base_mle_refs = base_mles.iter().map(|v| v.as_slice()).collect_vec();
        run(
            point_refs,
            expr,
            vec![],
            base_mle_refs,
            challenges,
            &mut eqs,
            &mut eq_evals_first_part,
            &mut eq_evals_second_part,
            ans,
        );
    }
}
