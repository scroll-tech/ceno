use std::marker::PhantomData;

use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    Expression, WitnessId,
    mle::{MultilinearExtension, Point},
    utils::eval_by_expr,
    virtual_poly::{VPAuxInfo, build_eq_x_r_vec, eq_eval},
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3_field::dot_product;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{ROTATION_OPENING_COUNT, sumcheck_layer::SumcheckLayerProof},
    },
    utils::{
        extend_exprs_with_rotation, rotation_next_base_mle, rotation_selector,
        rotation_selector_eval,
    },
};

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::LayerProof};

struct RotationPoints<E: ExtensionField> {
    left: Point<E>,
    right: Point<E>,
    origin: Point<E>,
}

struct RotationClaims<E: ExtensionField> {
    left_evals: Vec<E>,
    right_evals: Vec<E>,
    target_evals: Vec<E>,
    rotation_points: RotationPoints<E>,
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
    ) -> (LayerProof<E>, Point<E>);

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
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
    ) -> (LayerProof<E>, Point<E>) {
        assert_eq!(
            self.out_eq_and_eval_exprs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            self.out_eq_and_eval_exprs.len(),
            out_points.len(),
        );

        let (_, rotation_exprs) = &self.rotation_exprs;
        let (rotation_proof, rotation_left, rotation_right, rotation_point) =
            if !rotation_exprs.is_empty() {
                // 1st sumcheck: process rotation_exprs
                let rt = out_points.first().unwrap();
                let (
                    proof,
                    RotationPoints {
                        left,
                        right,
                        origin,
                    },
                ) = prove_rotation(
                    num_threads,
                    max_num_variables,
                    self.rotation_cyclic_subgroup_size,
                    self.rotation_cyclic_group_log2,
                    &wit,
                    rotation_exprs,
                    rt,
                    transcript,
                );
                (Some(proof), Some(left), Some(right), Some(origin))
            } else {
                (None, None, None, None)
            };

        // 2th sumcheck: batch rotation with other constrains
        let alpha_pows = get_challenge_pows(
            self.exprs.len() + rotation_exprs.len() * ROTATION_OPENING_COUNT,
            transcript,
        )
        .into_iter()
        .map(|r| Expression::Constant(Either::Right(r)))
        .collect_vec();

        let span = entered_span!("gen_expr", profiling_4 = true);
        let zero_check_exprs = extend_exprs_with_rotation(self, &alpha_pows);
        exit_span!(span);

        let span = entered_span!("build_out_points_eq", profiling_4 = true);
        // zero check eq || rotation eq
        let mut eqs = out_points
            .par_iter()
            .map(|point| {
                MultilinearExtension::from_evaluations_ext_vec(point.len(), build_eq_x_r_vec(point))
            })
            // for rotation left point
            .chain(rotation_left.par_iter().map(|rotation_left| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_left.len(),
                    build_eq_x_r_vec(rotation_left),
                )
            }))
            // for rotation right point
            .chain(rotation_right.par_iter().map(|rotation_right| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_right.len(),
                    build_eq_x_r_vec(rotation_right),
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
            wit.iter()
                .map(|mle| Either::Left(mle.as_ref()))
                .chain(eqs.iter_mut().map(Either::Right))
                .collect_vec(),
        );

        let span = entered_span!("IOPProverState::prove", profiling_4 = true);
        let zero_check_expr: Expression<E> = zero_check_exprs.into_iter().sum();
        let (proof, prover_state) = IOPProverState::prove(
            builder.to_virtual_polys(&[zero_check_expr], challenges),
            transcript,
        );

        let evals = prover_state.get_mle_flatten_final_evaluations();
        exit_span!(span);
        (
            LayerProof {
                main: SumcheckLayerProof { proof, evals },
                rotation: rotation_proof,
            },
            prover_state.collect_raw_challenges(),
        )
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        mut eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        assert_eq!(
            self.out_eq_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
            "out eval length {} != with eval_and_dedup_points {}",
            self.out_eq_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
        );
        let LayerProof {
            main:
                SumcheckLayerProof {
                    proof: IOPProof { proofs },
                    evals: mut main_evals,
                },
            rotation: rotation_proof,
        } = proof;

        if let Some(rotation_proof) = rotation_proof {
            // verify rotation proof
            let rt = eval_and_dedup_points
                .first()
                .and_then(|(_, rt)| rt.as_ref())
                .expect("rotation proof should have at least one point");
            let RotationClaims {
                left_evals,
                right_evals,
                target_evals,
                rotation_points:
                    RotationPoints {
                        left: left_point,
                        right: right_point,
                        origin: origin_point,
                    },
            } = verify_rotation(
                max_num_variables,
                rotation_proof,
                self.rotation_cyclic_subgroup_size,
                self.rotation_cyclic_group_log2,
                rt,
                transcript,
            )?;
            eval_and_dedup_points.push((left_evals, Some(left_point)));
            eval_and_dedup_points.push((right_evals, Some(right_point)));
            eval_and_dedup_points.push((target_evals, Some(origin_point)));
        }

        let rotation_exprs_len = self.rotation_exprs.1.len();
        let alpha_pows = get_challenge_pows(
            self.exprs.len() + rotation_exprs_len * ROTATION_OPENING_COUNT,
            transcript,
        );

        let sigma = dot_product(
            alpha_pows.iter().copied(),
            eval_and_dedup_points
                .iter()
                .flat_map(|(sigmas, _)| sigmas)
                .copied(),
        );

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            sigma,
            &IOPProof { proofs },
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
            .zip(&self.out_eq_and_eval_exprs)
            .for_each(|(eval, (eq_expr, _))| match eq_expr {
                Some(Expression::WitIn(id)) => {
                    #[cfg(debug_assertions)]
                    assert_eq!(main_evals[*id as usize], eval, "eq compute wrong");
                    main_evals[*id as usize] = eval;
                }
                _ => unreachable!(),
            });

        let zero_check_exprs = extend_exprs_with_rotation(
            self,
            &alpha_pows
                .iter()
                .cloned()
                .map(|r| Expression::Constant(Either::Right(r)))
                .collect_vec(),
        );

        let zero_check_expr = zero_check_exprs.into_iter().sum::<Expression<E>>();
        let got_claim = eval_by_expr(&main_evals, &[], challenges, &zero_check_expr);

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                self.name.clone(),
                VerifierError::ClaimNotMatch(expected_evaluation, got_claim),
            ));
        }

        Ok(LayerClaims {
            in_point,
            evals: main_evals,
        })
    }
}

/// This is to prove the following n rotation arguments:
/// For the i-th argument, we check rotated(rotation_expr[i].0) == rotation_expr[i].1
/// This is proved through the following arguments:
///     0 = \sum_{b = 0}^{N - 1} sel(b) * \sum_i alpha^i * (rotated_rotation_expr[i].0(b) - rotation_expr[i].1(b))
/// With the randomness rx, we check: (currently we only support cycle with length 32)
///     rotated_rotation_expr[i].0(rx) == (1 - rx_4) * rotation_expr[i].1(0, rx_0, rx_1, ..., rx_3, rx_5, ...)
///                                     + rx_4 * rotation_expr[i].1(1, rx_0, 1 - rx_1, ..., rx_3, rx_5, ...)
#[allow(clippy::too_many_arguments)]
fn prove_rotation<E: ExtensionField>(
    num_threads: usize,
    max_num_variables: usize,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    wit: &LayerWitness<E>,
    rotation_exprs: &[(Expression<E>, Expression<E>)],
    rt: &Point<E>,
    transcript: &mut impl Transcript<E>,
) -> (SumcheckLayerProof<E>, RotationPoints<E>) {
    let span = entered_span!("rotate_witin_selector", profiling_4 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    // rotated_mles is non-deterministic input, rotated from existing witness polynomial
    // we will reduce it to zero check, and finally reduce to commmitted polynomial opening
    let (mut selector, mut rotated_mles) = {
        let eq = build_eq_x_r_vec(rt);
        let mut mles = rotation_exprs
            .par_iter()
            .map(|rotation_expr| match rotation_expr {
                (Expression::WitIn(source_wit_id), _) => rotation_next_base_mle(
                    &bh,
                    &wit.0[*source_wit_id as usize],
                    rotation_cyclic_group_log2,
                ),
                _ => unimplemented!("unimplemented rotation"),
            })
            .chain(rayon::iter::once(rotation_selector(
                &bh,
                &eq,
                rotation_cyclic_subgroup_size,
                rotation_cyclic_group_log2,
                wit.0[0].evaluations().len(), // Take first mle just to retrieve total length
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
    // TODO FIXME: we pick a random point from output point, does it sound?
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
                        Either::Left(wit.0[*wit_id as usize].as_ref()),
                    ]
                }
                _ => panic!(""),
            })
            .chain(std::iter::once(Either::Right(&mut selector)))
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
    let selector_expr = Expression::<E>::WitIn((rotation_exprs.len() * 2) as WitnessId);
    let span = entered_span!("rotation IOPProverState::prove", profiling_4 = true);
    let (rotation_proof, prover_state) = IOPProverState::prove(
        builder.to_virtual_polys(&[selector_expr * rotation_expr], &[]),
        transcript,
    );
    exit_span!(span);
    let mut evals = prover_state.get_mle_flatten_final_evaluations();
    let origin_point = prover_state.collect_raw_challenges();
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
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let (left_point, right_point) = bh.get_rotation_points(&origin_point);
    let evals = evals
        .par_chunks_exact(2)
        .zip_eq(rotation_exprs.par_iter())
        .flat_map(|(evals, (rotated_expr, _))| {
            let [rotated_eval, target_eval] = evals else {
                unreachable!()
            };
            let left_eval = match rotated_expr {
                Expression::WitIn(source_wit_id) => {
                    wit.0[*source_wit_id as usize].evaluate(&left_point)
                }
                _ => unreachable!(),
            };
            let right_eval =
                bh.get_rotation_right_eval_from_left(*rotated_eval, left_eval, &origin_point);
            #[cfg(debug_assertions)]
            {
                let expected_right_eval = match rotated_expr {
                    Expression::WitIn(source_wit_id) => {
                        wit.0[*source_wit_id as usize].evaluate(&right_point)
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    expected_right_eval, right_eval,
                    "rotation right eval mismatch: expected {expected_right_eval}, got {right_eval}"
                );
            }
            [left_eval, right_eval, *target_eval]
        })
        .collect::<Vec<E>>();
    exit_span!(span);
    (
        SumcheckLayerProof {
            proof: rotation_proof,
            evals,
        },
        RotationPoints {
            left: left_point,
            right: right_point,
            origin: origin_point,
        },
    )
}

fn verify_rotation<E: ExtensionField>(
    max_num_variables: usize,
    rotation_proof: SumcheckLayerProof<E>,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    rt: &Point<E>,
    transcript: &mut impl Transcript<E>,
) -> Result<RotationClaims<E>, BackendError<E>> {
    let SumcheckLayerProof { proof, evals } = rotation_proof;
    let rotation_expr_len = evals.len() / 3;
    let rotation_alpha_pows = get_challenge_pows(rotation_expr_len, transcript)
        .into_iter()
        .collect_vec();

    let sigma = E::ZERO;

    let SumCheckSubClaim {
        point: in_point,
        expected_evaluation,
    } = IOPVerifierState::verify(
        sigma,
        &proof,
        &VPAuxInfo {
            max_degree: 2, // selector * (rotated - target)
            max_num_variables,
            phantom: PhantomData,
        },
        transcript,
    );
    let origin_point = in_point.into_iter().map(|c| c.elements).collect_vec();

    // compute the selector evaluation
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let selector_eval = rotation_selector_eval(
        &bh,
        rt,
        &origin_point,
        rotation_cyclic_subgroup_size,
        rotation_cyclic_group_log2,
    );

    // check the final evaluations.
    let mut left_evals = Vec::with_capacity(evals.len() / 3);
    let mut right_evals = Vec::with_capacity(evals.len() / 3);
    let mut target_evals = Vec::with_capacity(evals.len() / 3);
    let got_claim = selector_eval
        * evals
            .chunks_exact(3)
            .zip_eq(rotation_alpha_pows.iter())
            .map(|(evals, alpha)| {
                let [left_eval, right_eval, target_eval] = evals else {
                    unreachable!()
                };
                left_evals.push(*left_eval);
                right_evals.push(*right_eval);
                target_evals.push(*target_eval);
                *alpha
                    * ((E::ONE - origin_point[rotation_cyclic_group_log2 - 1]) * *left_eval
                        + origin_point[rotation_cyclic_group_log2 - 1] * *right_eval
                        - *target_eval)
            })
            .sum::<E>();

    if got_claim != expected_evaluation {
        return Err(BackendError::LayerVerificationFailed(
            "rotation verify failed".to_string(),
            VerifierError::ClaimNotMatch(expected_evaluation, got_claim),
        ));
    }

    let (left_point, right_point) =
        BooleanHypercube::new(rotation_cyclic_group_log2).get_rotation_points(&origin_point);

    Ok(RotationClaims {
        left_evals,
        right_evals,
        target_evals,
        rotation_points: RotationPoints {
            left: left_point,
            right: right_point,
            origin: origin_point,
        },
    })
}
