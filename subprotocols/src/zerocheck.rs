use std::{iter, mem, sync::Arc, vec};

use ark_std::log2;
use ff::BatchInvert;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip, zip_eq};
use transcript::Transcript;

use crate::{
    error::VerifierError,
    expression::Expression,
    sumcheck::{SumcheckProof, SumcheckProverOutput},
};

use super::{
    sumcheck::SumcheckClaims,
    utils::{
        eq_vecs, fix_variables_ext, fix_variables_inplace, grand_product, interpolate_uni_poly,
    },
};

/// This is an randomly combined zerocheck protocol for the following equation:
/// \sigma = \sum_x (r^0 eq_0(X) \cdot expr_0(x) + r^1 eq_1(X) \cdot expr_1(x) + ...)
pub struct ZerocheckProverState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    /// Expressions and corresponding half eq reference.
    exprs: Vec<(Expression, Vec<E>)>,

    /// Extension field mles.
    ext_mles: Vec<&'a mut [E]>,
    /// Base field mles after the first round.
    base_mles_after: Vec<Vec<E>>,
    /// Base field mles.
    base_mles: Vec<&'a [E::BaseField]>,
    /// Challenges occurred in expressions
    challenges: &'a [E],
    /// For each point in points, the inverse of prod_{j < i}(1 - point[i]) for 0 <= i < point.len().
    grand_prod_of_not_inv: Vec<Vec<E>>,

    transcript: &'a mut Trans,

    num_vars: usize,
}

impl<'a, E, Trans> ZerocheckProverState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exprs: Vec<Expression>,
        points: &[&[E]],
        ext_mles: Vec<&'a mut [E]>,
        base_mles: Vec<&'a [E::BaseField]>,
        challenges: &'a [E],
        transcript: &'a mut Trans,
    ) -> Self {
        assert!(!(ext_mles.is_empty() && base_mles.is_empty()));

        let num_vars = if !ext_mles.is_empty() {
            log2(ext_mles[0].len()) as usize
        } else {
            log2(base_mles[0].len()) as usize
        };

        // For each point, compute eq(point[1..], b) for b in [0, 2^{num_vars - 1}).
        let (exprs, grand_prod_of_not_inv) = if num_vars > 0 {
            let half_eq_evals = eq_vecs(points.iter().map(|point| &point[1..]), &vec![
                E::ONE;
                exprs.len()
            ]);
            let exprs = zip_eq(exprs, half_eq_evals).collect_vec();
            let mut grand_prod_of_not_inv = points
                .iter()
                .flat_map(|point| point[1..].iter().map(|p| E::ONE - p).collect_vec())
                .collect_vec();
            BatchInvert::batch_invert(&mut grand_prod_of_not_inv);
            let (_, grand_prod_of_not_inv) =
                points
                    .iter()
                    .fold((0usize, vec![]), |(start, mut last_vec), point| {
                        let end = start + point.len() - 1;
                        last_vec.push(grand_product(&grand_prod_of_not_inv[start..end]));
                        (end, last_vec)
                    });
            (exprs, grand_prod_of_not_inv)
        } else {
            let expr = exprs.into_iter().map(|expr| (expr, vec![])).collect_vec();
            (expr, vec![])
        };

        // The length of all mles should be 2^{num_vars}.
        assert!(ext_mles.iter().all(|mle| mle.len() == 1 << num_vars));
        assert!(base_mles.iter().all(|mle| mle.len() == 1 << num_vars));

        Self {
            exprs,
            ext_mles,
            base_mles_after: vec![],
            base_mles,
            challenges,
            grand_prod_of_not_inv,
            transcript,
            num_vars,
        }
    }

    pub fn prove(mut self) -> SumcheckProverOutput<E> {
        let (univariate_polys, point) = (0..self.num_vars)
            .map(|round| {
                let round_msg = self.compute_univariate_poly(round);
                round_msg
                    .iter()
                    .for_each(|poly| self.transcript.append_field_element_exts(poly));

                let r = self
                    .transcript
                    .get_and_append_challenge(b"sumcheck round")
                    .elements;
                self.update_mles(&r, round);
                (round_msg, r)
            })
            .unzip();
        let point = Arc::new(point);

        // Send the final evaluations
        let ZerocheckProverState {
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

    /// Compute f_i(X) = \sum_x eq_i(x) expr_i(X || x)
    fn compute_univariate_poly(&self, round: usize) -> Vec<Vec<E>> {
        izip!(&self.exprs, &self.grand_prod_of_not_inv)
            .map(|((expr, half_eq_mle), coeff)| {
                let mut uni_poly = expr.zerocheck_uni_poly(
                    &self.ext_mles,
                    &self.base_mles_after,
                    &self.base_mles,
                    self.challenges,
                    half_eq_mle.iter().step_by(1 << round),
                    1 << (self.num_vars - round),
                );
                uni_poly.iter_mut().for_each(|x| *x *= coeff[round]);
                uni_poly
            })
            .collect_vec()
    }

    fn update_mles(&mut self, r: &E, round: usize) {
        // fix variables of base field polynomials.
        self.ext_mles.iter_mut().for_each(|mle| {
            fix_variables_inplace(mle, r);
        });
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

pub struct ZerocheckVerifierState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    sigmas: Vec<E>,
    inv_of_one_minus_points: Vec<Vec<E>>,
    exprs: Vec<(Expression, &'a [E])>,
    proof: SumcheckProof<E>,
    challenges: &'a [E],
    transcript: &'a mut Trans,
}

impl<'a, E, Trans> ZerocheckVerifierState<'a, E, Trans>
where
    E: ExtensionField,
    Trans: Transcript<E>,
{
    pub fn new(
        sigmas: Vec<E>,
        exprs: Vec<Expression>,
        points: Vec<&'a [E]>,
        proof: SumcheckProof<E>,
        challenges: &'a [E],
        transcript: &'a mut Trans,
    ) -> Self {
        let mut inv_of_one_minus_points = points
            .iter()
            .flat_map(|point| point.iter().map(|p| E::ONE - p).collect_vec())
            .collect_vec();
        BatchInvert::batch_invert(&mut inv_of_one_minus_points);
        let (_, inv_of_one_minus_points) =
            points
                .iter()
                .fold((0usize, vec![]), |(start, mut last_vec), point| {
                    let end = start + point.len();
                    last_vec.push(inv_of_one_minus_points[start..start + point.len()].to_vec());
                    (end, last_vec)
                });

        let exprs = zip_eq(exprs, points).collect_vec();
        Self {
            sigmas,
            inv_of_one_minus_points,
            exprs,
            proof,
            challenges,
            transcript,
        }
    }

    pub fn verify(self) -> Result<SumcheckClaims<E>, VerifierError<E>> {
        let ZerocheckVerifierState {
            sigmas,
            inv_of_one_minus_points,
            exprs,
            proof,
            challenges,
            transcript,
            ..
        } = self;
        let SumcheckProof {
            univariate_polys,
            ext_mle_evals,
            base_mle_evals,
        } = proof;

        let (in_point, expected_claims) = univariate_polys.into_iter().enumerate().fold(
            (vec![], sigmas),
            |(mut last_point, last_sigmas), (round, round_msg)| {
                round_msg
                    .iter()
                    .for_each(|poly| transcript.append_field_element_exts(poly));
                let r = transcript
                    .get_and_append_challenge(b"sumcheck round")
                    .elements;
                last_point.push(r);

                let sigmas = izip!(&exprs, &inv_of_one_minus_points, round_msg, last_sigmas)
                    .map(|((_, point), inv_of_one_minus_point, poly, last_sigma)| {
                        let len = poly.len() + 1;
                        // last_sigma = (1 - point[round]) * eval_at_0 + point[round] * eval_at_1
                        // eval_at_0 = (last_sigma - point[round] * eval_at_1) * inv(1 - point[round])
                        let eval_at_0 =
                            (last_sigma - point[round] * poly[0]) * inv_of_one_minus_point[round];

                        // Evaluations on degree, degree - 1, ..., 1, 0.
                        let evals_iter_rev = chain![poly.into_iter().rev(), iter::once(eval_at_0)];

                        interpolate_uni_poly(evals_iter_rev, len, r)
                    })
                    .collect_vec();

                (last_point, sigmas)
            },
        );

        // Check the final evaluations.
        for (expected_claim, (expr, _)) in izip!(expected_claims, exprs) {
            let got_claim = expr.evaluate(&ext_mle_evals, &base_mle_evals, &[], &[], challenges);

            if expected_claim != got_claim {
                return Err(VerifierError::ClaimNotMatch(
                    expr,
                    expected_claim,
                    got_claim,
                ));
            }
        }

        let in_point = Arc::new(in_point);
        Ok(SumcheckClaims {
            in_point,
            ext_mle_evals,
            base_mle_evals,
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
        sumcheck::SumcheckProverOutput,
    };

    use super::{ZerocheckProverState, ZerocheckVerifierState};

    #[allow(clippy::too_many_arguments)]
    fn run<'a, E: ExtensionField>(
        points: Vec<&[E]>,
        exprs: Vec<Expression>,
        ext_mle_refs: Vec<&'a mut [E]>,
        base_mle_refs: Vec<&'a [E::BaseField]>,
        challenges: Vec<E>,

        sigmas: Vec<E>,
    ) {
        let mut prover_transcript = BasicTranscript::new(b"test");
        let prover = ZerocheckProverState::new(
            exprs.clone(),
            &points,
            ext_mle_refs,
            base_mle_refs,
            &challenges,
            &mut prover_transcript,
        );

        let SumcheckProverOutput { proof, .. } = prover.prove();

        let mut verifier_transcript = BasicTranscript::new(b"test");
        let verifier = ZerocheckVerifierState::new(
            sigmas,
            exprs,
            points,
            proof,
            &challenges,
            &mut verifier_transcript,
        );

        verifier.verify().expect("verification failed");
    }

    #[test]
    fn test_zerocheck_trivial() {
        let f = field_vec![F, 2];
        let g = field_vec![F, 3];
        let out_point = vec![];

        let base_mle_refs = vec![f.as_slice(), g.as_slice()];
        let f = Expression::Wit(Witness::BasePoly(0));
        let g = Expression::Wit(Witness::BasePoly(1));
        let expr = f * g;

        run(
            vec![out_point.as_slice()],
            vec![expr],
            vec![],
            base_mle_refs,
            vec![],
            vec![E::from(6)],
        );
    }

    #[test]
    fn test_zerocheck_simple() {
        let f = field_vec![F, 1, 2, 3, 4, 5, 6, 7, 8];
        let out_point = field_vec![E, 2, 3, 5];
        let out_eq = field_vec![E, -8, 16, 12, -24, 10, -20, -15, 30];
        let ans = izip!(&out_eq, &f).fold(E::ZERO, |acc, (c, x)| acc + *c * x);

        let base_mle_refs = vec![f.as_slice()];
        let expr = Expression::Wit(Witness::BasePoly(0));
        run(
            vec![out_point.as_slice()],
            vec![expr.clone()],
            vec![],
            base_mle_refs,
            vec![],
            vec![ans],
        );
    }

    #[test]
    fn test_zerocheck_logup() {
        let out_point = field_vec![E, 2, 3, 5];
        let out_eq = field_vec![E, -8, 16, 12, -24, 10, -20, -15, 30];

        let d0 = field_vec![E, 1, 2, 3, 4, 5, 6, 7, 8];
        let d1 = field_vec![E, 9, 10, 11, 12, 13, 14, 15, 16];
        let n0 = field_vec![E, 17, 18, 19, 20, 21, 22, 23, 24];
        let n1 = field_vec![E, 25, 26, 27, 28, 29, 30, 31, 32];

        let challenges = vec![E::from(7)];
        let ans = izip!(&out_eq, &d0, &d1, &n0, &n1)
            .map(|(eq, d0, d1, n0, n1)| *eq * (*d0 * *d1 + challenges[0] * (*d0 * *n1 + *d1 * *n0)))
            .sum();

        let mut ext_mles = [d0, d1, n0, n1];
        let [d0, d1, n0, n1] = array::from_fn(|i| Expression::Wit(Witness::ExtPoly(i)));
        let beta = Expression::Const(Constant::Challenge(0));
        let expr = d0.clone() * d1.clone() + beta * (d0 * n1 + d1 * n0);

        let ext_mles_refs = ext_mles.iter_mut().map(|v| v.as_mut_slice()).collect_vec();
        run(
            vec![out_point.as_slice()],
            vec![expr.clone()],
            ext_mles_refs,
            vec![],
            challenges,
            vec![ans],
        );
    }

    #[test]
    fn test_zerocheck_multi_points() {
        let points = [
            field_vec![E, 2, 3, 5],
            field_vec![E, 7, 11, 13],
            field_vec![E, 17, 19, 23],
        ];
        let out_eqs = [
            field_vec![E, -8, 16, 12, -24, 10, -20, -15, 30],
            field_vec![E, -720, 840, 792, -924, 780, -910, -858, 1001],
            field_vec![E, -6336, 6732, 6688, -7106, 6624, -7038, -6992, 7429],
        ];
        let point_refs = points.iter().map(|v| v.as_slice()).collect_vec();

        let d0 = field_vec![F, 1, 2, 3, 4, 5, 6, 7, 8];
        let d1 = field_vec![F, 9, 10, 11, 12, 13, 14, 15, 16];
        let n0 = field_vec![F, 17, 18, 19, 20, 21, 22, 23, 24];
        let n1 = field_vec![F, 25, 26, 27, 28, 29, 30, 31, 32];

        let ans_0 = izip!(&out_eqs[0], &d0, &d1)
            .map(|(eq0, d0, d1)| eq0 * d0 * d1)
            .sum();
        let ans_1 = izip!(&out_eqs[1], &d0, &n1)
            .map(|(eq1, d0, n1)| eq1 * d0 * n1)
            .sum();
        let ans_2 = izip!(&out_eqs[2], &d1, &n0)
            .map(|(eq2, d1, n0)| eq2 * d1 * n0)
            .sum();

        let base_mles = [d0, d1, n0, n1];
        let [d0, d1, n0, n1] = array::from_fn(|i| Expression::Wit(Witness::BasePoly(i)));

        let exprs = vec![d0.clone() * d1.clone(), d0 * n1, d1 * n0];

        let base_mle_refs = base_mles.iter().map(|v| v.as_slice()).collect_vec();
        run(point_refs, exprs, vec![], base_mle_refs, vec![], vec![
            ans_0, ans_1, ans_2,
        ]);
    }
}
