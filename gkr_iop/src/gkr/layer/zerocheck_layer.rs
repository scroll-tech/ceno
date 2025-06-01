use std::marker::PhantomData;

use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point},
    utils::eval_by_expr_with_instance,
    virtual_poly::{VPAuxInfo, build_eq_x_r_vec, eq_eval},
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3_field::dot_product;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    utils::{rotation_next_base_mle, rotation_selector},
};

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::SumcheckLayerProof};

// rotation contribute
// TODO FIXME from https://hackmd.io/HAAj1JTQQiKfu0SIwOJDRw?view it seems to be 3
const ROTATION_OPENING_COUNT: usize = 2;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RotationProof<E: ExtensionField> {
    proof: IOPProof<E>,
    evals: Vec<E>,
}

pub trait ZerocheckLayer<E: ExtensionField> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E>;

    fn verify(
        &self,
        max_num_variables: usize,
        proof: SumcheckLayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer<E> {
    fn prove(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E> {
        assert_eq!(
            self.outs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            self.outs.len(),
            out_points.len(),
        );

        // process rotation_exprs
        let (rotation_proof, rotation_point) = if self.rotation_exprs.1.len() > 0 {
            let span = entered_span!("rotate_witin_selector", profiling_4 = true);
            let rt = out_points.first().unwrap();
            let mut eq =
                MultilinearExtension::from_evaluations_ext_vec(rt.len(), build_eq_x_r_vec(rt));
            // rotated_mles is non-deterministic input, rotated from existing witness polynomial
            // we will reduce it to zero check, and finally reduce
            let (mut selector, mut rotated_mles) = {
                let mut mles = self
                .rotation_exprs.1
                .par_iter()
                .map(|rotation_expr| match rotation_expr {
                    (Expression::WitIn(source_wit_id), _) => {
                        rotation_next_base_mle(&wit.bases[*source_wit_id as usize], 23, 5)
                    }
                    _ => unimplemented!("unimplemented rotation"),
                })
                .chain(rayon::iter::once(rotation_selector(
                    23,
                    5,
                    wit.bases[0].evaluations().len(), // Take first mle just to retrieve total length
                )))
                .collect::<Vec<_>>();
                let selector = mles.pop().unwrap();
                (selector, mles)
            };
            let rotation_alpha_pows = get_challenge_pows(self.rotation_exprs.1.len(), transcript)
                .into_iter()
                .map(|r| Expression::Constant(Either::Right(r)))
                .collect_vec();
            exit_span!(span);
            // TODO FIXME: we pick a random point from output, does it sound?
            let builder = VirtualPolynomialsBuilder::new_with_mles(
                num_threads,
                max_num_variables,
                // mles format [rotation_mle1, target_mle1, rotation_mle2, target_mle2, ....., selector, eq]
                rotated_mles
                    .iter_mut()
                    .zip_eq(&self.rotation_exprs.1)
                    .flat_map(|(mle, (_, expr))| match expr {
                        Expression::WitIn(wit_id) => {
                            vec![
                                Either::Right(mle),
                                Either::Left(wit.bases[*wit_id as usize].as_ref()),
                            ]
                        }
                        _ => panic!(""),
                    })
                    .chain(std::iter::once(Either::Right(&mut selector)))
                    .chain(std::iter::once(Either::Right(&mut eq)))
                    .collect_vec(),
            );
            // generate rotation expression
            let rotation_expr = (0..)
                .tuples()
                .take(self.rotation_exprs.1.len())
                .zip_eq(&rotation_alpha_pows)
                .map(|((rotate_wit_id, target_wit_id), alpha)| {
                    alpha * (Expression::WitIn(rotate_wit_id) - Expression::WitIn(target_wit_id))
                })
                .sum::<Expression<E>>();
            // last 2 is [selector, eq]
            let (selector_expr, eq_expr) = (
                Expression::<E>::WitIn(
                    (self.rotation_exprs.1.len() * ROTATION_OPENING_COUNT) as u32,
                ),
                Expression::<E>::WitIn(
                    (self.rotation_exprs.1.len() * ROTATION_OPENING_COUNT + 1) as u32,
                ),
            );
            let span = entered_span!("rotation IOPProverState::prove", profiling_4 = true);
            let (rotation_proof, prover_state) = IOPProverState::prove(
                builder.to_virtual_polys(&[eq_expr * selector_expr * rotation_expr], challenges),
                transcript,
            );
            exit_span!(span);
            let mut evals = prover_state.get_mle_flatten_final_evaluations();
            let point = rotation_proof.point.clone();
            // skip selector/eq as verifier can derived itself
            evals.truncate(self.rotation_exprs.1.len() * ROTATION_OPENING_COUNT);
            (
                Some(RotationProof {
                    proof: rotation_proof,
                    evals: evals,
                }),
                Some(point),
            )
        } else {
            (None, None)
        };

        let mut expr_iter = self.exprs.iter();
        let mut zero_check_exprs = Vec::with_capacity(self.outs.len());

        let alpha_pows = get_challenge_pows(
            self.exprs.len() + self.rotation_exprs.1.len() * ROTATION_OPENING_COUNT,
            transcript,
        )
        .into_iter()
        .map(|r| Expression::Constant(Either::Right(r)))
        .collect_vec();
        let mut alpha_pows_iter = alpha_pows.iter();

        let span = entered_span!("gen_expr", profiling_4 = true);
        for (eq_expr, out_evals) in self.outs.iter() {
            let group_length = out_evals.len();
            let zero_check_expr = expr_iter
                .by_ref()
                .take(group_length)
                .cloned()
                .zip_eq(alpha_pows_iter.by_ref().take(group_length))
                .map(|(expr, alpha)| alpha * expr)
                .sum::<Expression<E>>();
            zero_check_exprs.push(eq_expr.clone().unwrap() * zero_check_expr);
        }

        // prepare rotation expr
        let rotation_expr = self
            .rotation_exprs
            .1
            .iter()
            .zip_eq(
                alpha_pows_iter
                    .by_ref()
                    .take(self.rotation_exprs.1.len() * ROTATION_OPENING_COUNT)
                    .tuples(),
            )
            .map(|((rotate_expr, expr), (alpha1, alpha2))| {
                assert!(
                    matches!(rotate_expr, Expression::WitIn(_))
                        && matches!(expr, Expression::WitIn(_))
                );
                alpha1 * rotate_expr + alpha2 * expr
            })
            .sum::<Expression<E>>();

        if let Some(rotation_eq_expr) = self.rotation_exprs.0.as_ref() {
            zero_check_exprs.push(rotation_eq_expr.clone() * rotation_expr)
        }

        exit_span!(span);
        assert!(expr_iter.next().is_none() && alpha_pows_iter.next().is_none());

        let span = entered_span!("build_out_points_eq", profiling_4 = true);
        // zero check eq || rotation eq
        let mut eqs = out_points
            .par_iter()
            .map(|point| {
                MultilinearExtension::from_evaluations_ext_vec(
                    point.len(),
                    build_eq_x_r_vec(&point),
                )
            })
            .chain(rotation_point.into_par_iter().map(|rotation_point| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_point.len(),
                    build_eq_x_r_vec(&rotation_point),
                )
            }))
            .collect::<Vec<_>>();
        exit_span!(span);

        let builder = VirtualPolynomialsBuilder::new_with_mles(
            num_threads,
            max_num_variables,
            wit.bases
                .iter()
                .map(|mle| Either::Left(mle.as_ref()))
                // extend eqs to the end of wit
                .chain(eqs.iter_mut().map(|eq| Either::Right(eq)))
                .collect_vec(),
        );
        let span = entered_span!("IOPProverState::prove", profiling_4 = true);
        let (proof, prover_state) = IOPProverState::prove(
            builder.to_virtual_polys(&[zero_check_exprs.into_iter().sum()], challenges),
            transcript,
        );
        exit_span!(span);
        SumcheckLayerProof {
            proof,
            rotation_proof,
            evals: prover_state.get_mle_flatten_final_evaluations(),
        }
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: SumcheckLayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        assert_eq!(
            self.outs.len(),
            eval_and_dedup_points.len(),
            "out eval length {} != with eval_and_dedup_points {}",
            self.outs.len(),
            eval_and_dedup_points.len(),
        );
        let SumcheckLayerProof {
            proof: IOPProof { proofs, .. },
            mut evals,
            // TODO process rotation proof
            ..
        } = proof;

        let alpha_pows = get_challenge_pows(self.exprs.len(), transcript);

        let sigma: E = dot_product(
            alpha_pows.iter().copied(),
            eval_and_dedup_points
                .iter()
                .map(|(sigmas, _)| sigmas)
                .flatten()
                .copied(),
        );

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            sigma,
            &IOPProof {
                point: vec![], // final claimed point will be derived from sumcheck protocol
                proofs,
            },
            &VPAuxInfo {
                max_degree: self.max_expr_degree + 1, // +1 due to eq
                max_num_variables,
                phantom: PhantomData,
            },
            transcript,
        );
        let in_point = in_point.into_iter().map(|c| c.elements).collect_vec();

        // eval eq and set to respective witin
        eval_and_dedup_points
            .iter()
            .map(|(_, out_point)| eq_eval(out_point.as_ref().unwrap(), &in_point))
            .zip(&self.outs)
            .for_each(|(eval, (eq_expr, _))| match eq_expr {
                Some(Expression::WitIn(witin_id)) => evals[*witin_id as usize] = eval,
                _ => unreachable!(),
            });

        // check the final evaluations.
        let got_claim = self
            .exprs
            .iter()
            .zip_eq(self.outs.iter().flat_map(|(eq_expr, evals)| {
                std::iter::repeat(eq_expr.clone().unwrap()).take(evals.len())
            }))
            .zip_eq(alpha_pows)
            .map(|((expr, eq_expr), alpha)| {
                alpha
                    * eval_by_expr_with_instance(
                        &[],
                        &evals,
                        &[],
                        &[],
                        challenges,
                        &(expr * eq_expr),
                    )
                    .right()
                    .unwrap()
            })
            .sum::<E>();

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                "sumcheck verify failed".to_string(),
                VerifierError::ClaimNotMatch(
                    self.exprs[0].clone(),
                    expected_evaluation,
                    got_claim,
                    self.expr_names[0].clone(),
                ),
            ));
        }

        Ok(LayerClaims { in_point, evals })
    }
}
