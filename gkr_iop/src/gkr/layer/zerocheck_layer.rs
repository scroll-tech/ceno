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
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    gkr::layer::ROTATION_OPENING_COUNT,
    utils::{rotation_next_base_mle, rotation_selector},
};

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::SumcheckLayerProof};

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

        // 1st sumcheck: process rotation_exprs
        let (rotation_eq, rotation_exprs) = &self.rotation_exprs;
        let (rotation_proof, rotation_point) = if !rotation_exprs.is_empty() {
            let span = entered_span!("rotate_witin_selector", profiling_4 = true);
            let rt = out_points.first().unwrap();
            let mut eq =
                MultilinearExtension::from_evaluations_ext_vec(rt.len(), build_eq_x_r_vec(rt));
            // rotated_mles is non-deterministic input, rotated from existing witness polynomial
            // we will reduce it to zero check, and finally reduce
            let (mut selector, mut rotated_mles) = {
                let mut mles = rotation_exprs
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
            let rotation_alpha_pows = get_challenge_pows(rotation_exprs.len(), transcript)
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
                    .zip_eq(rotation_exprs)
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
                .take(rotation_exprs.len())
                .zip_eq(&rotation_alpha_pows)
                .map(|((rotate_wit_id, target_wit_id), alpha)| {
                    alpha * (Expression::WitIn(rotate_wit_id) - Expression::WitIn(target_wit_id))
                })
                .sum::<Expression<E>>();
            // last 2 is [selector, eq]
            let (selector_expr, eq_expr) = (
                Expression::<E>::WitIn((rotation_exprs.len() * 2) as u32),
                Expression::<E>::WitIn((rotation_exprs.len() * 2 + 1) as u32),
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
            evals.truncate(rotation_exprs.len() * 2);

            let span = entered_span!("rotation derived left/right eval", profiling_4 = true);
            // post process: giving opening of rotated polys (point, evals), derive original opening before rotate
            // final format: [
            //    left_eval_0th,
            //    right_eval_0th,
            //    target_eval_0th,
            //    left_eval_1st,
            //    right_eval_1st,
            //    target_eval_1st,
            //    ...
            // ]
            let evals = evals
                .par_chunks_exact(2)
                .zip_eq(rotation_exprs.par_iter())
                .flat_map(|(evals, (rotated_expr, _))| {
                    let [rotated_eval, target_eval] = evals else {
                        unreachable!()
                    };
                    let left_eval = match rotated_expr {
                        Expression::WitIn(source_wit_id) => wit.bases[*source_wit_id as usize]
                            .evaluate(
                                // (0, r0, r1, r2, r3, r5, r6, ....)
                                // skip r4
                                &std::iter::once(E::ZERO)
                                    .chain(point[..4].iter().copied())
                                    .chain(point[5..].iter().copied())
                                    .take(point.len())
                                    .collect_vec(),
                            ),
                        _ => unreachable!(),
                    };

                    let right_eval = (left_eval * (E::ONE - point[4]) - *rotated_eval) / point[4];
                    [left_eval, right_eval, *target_eval]
                })
                .collect::<Vec<E>>();
            exit_span!(span);
            // add evaluation of state in left
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

        // 2th sumcheck: batch rotation with other constrains
        let mut expr_iter = self.exprs.iter();
        let mut zero_check_exprs = Vec::with_capacity(self.outs.len());

        let alpha_pows = get_challenge_pows(
            self.exprs.len() + rotation_exprs.len() * ROTATION_OPENING_COUNT,
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
        let (mut left_rotation_expr, mut right_rotation_expr, mut rotation_expr) = (
            Vec::with_capacity(rotation_exprs.len()),
            Vec::with_capacity(rotation_exprs.len()),
            Vec::with_capacity(rotation_exprs.len()),
        );
        for ((rotate_expr, expr), (alpha1, alpha2, alpha3)) in rotation_exprs.iter().zip_eq(
            alpha_pows_iter
                .by_ref()
                .take(rotation_exprs.len() * ROTATION_OPENING_COUNT)
                .tuples(),
        ) {
            assert!(
                matches!(rotate_expr, Expression::WitIn(_)) && matches!(expr, Expression::WitIn(_))
            );

            left_rotation_expr.push(alpha1 * rotate_expr.clone());
            right_rotation_expr.push(alpha2 * rotate_expr.clone());
            rotation_expr.push(alpha3 * expr.clone());
        }

        // push rotation expr to zerocheck expr
        if let Some(
            [
                rotation_left_eq_expr,
                rotation_right_eq_expr,
                rotation_eq_expr,
            ],
        ) = rotation_eq.as_ref()
        {
            zero_check_exprs.push(
                rotation_left_eq_expr.clone()
                    * left_rotation_expr.into_iter().sum::<Expression<E>>(),
            );
            zero_check_exprs.push(
                rotation_right_eq_expr.clone()
                    * right_rotation_expr.into_iter().sum::<Expression<E>>(),
            );
            zero_check_exprs
                .push(rotation_eq_expr.clone() * rotation_expr.into_iter().sum::<Expression<E>>());
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
            // for rotation left point
            .chain(rotation_point.par_iter().map(|rotation_point| {
                // (0, r0, r1, r2, r3, r5, r6, ....)
                // skip r4
                let rotation_left = std::iter::once(E::ZERO)
                    .chain(rotation_point[..4].iter().copied())
                    .chain(rotation_point[5..].iter().copied())
                    .take(rotation_point.len())
                    .collect_vec();
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_left.len(),
                    build_eq_x_r_vec(&rotation_left),
                )
            }))
            // for rotation right point
            .chain(rotation_point.par_iter().map(|rotation_point| {
                // (1, r0, 1-r1, r2, r3, r5, r6, ....)
                // skip r4
                let rotation_left = std::iter::once(E::ONE)
                    .chain(std::iter::once(rotation_point[0]))
                    .chain(std::iter::once(E::ONE - rotation_point[1]))
                    .chain(rotation_point[2..4].iter().copied())
                    .chain(rotation_point[5..].iter().copied())
                    .take(rotation_point.len())
                    .collect_vec();
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_left.len(),
                    build_eq_x_r_vec(&rotation_left),
                )
            }))
            // for rotation point
            .chain(rotation_point.par_iter().map(|rotation_point| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_point.len(),
                    build_eq_x_r_vec(rotation_point),
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
