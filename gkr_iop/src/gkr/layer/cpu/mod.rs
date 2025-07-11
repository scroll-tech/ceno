use crate::{
    cpu::{CpuBackend, CpuProver},
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{
            Layer, LayerWitness, ROTATION_OPENING_COUNT,
            hal::{SumcheckLayerProver, ZerocheckLayerProver},
            zerocheck_layer::RotationPoints,
        },
    },
    utils::{extend_exprs_with_rotation, rotation_next_base_mle, rotation_selector},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, WitnessId, mle::MultilinearExtension, virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
    },
    slice::ParallelSlice,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::{
    gkr::layer::{
        hal::LinearLayerProver,
        sumcheck_layer::{LayerProof, SumcheckLayerProof},
    },
    hal::ProverBackend,
};

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn prove(
        _layer: &Layer<E>,
        wit: LayerWitness<CpuBackend<E, PCS>>,
        out_point: &multilinear_extensions::mle::Point<E>,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        let evals: Vec<_> = wit
            .into_par_iter()
            .map(|base| base.evaluate(out_point))
            .collect();

        transcript.append_field_element_exts(&evals);

        LayerProof {
            main: SumcheckLayerProof {
                proof: IOPProof { proofs: vec![] },
                evals,
            },
            rotation: None,
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> SumcheckLayerProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<'_, CpuBackend<E, PCS>>,
        challenges: &[<CpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> LayerProof<<CpuBackend<E, PCS> as ProverBackend>::E> {
        let builder = VirtualPolynomialsBuilder::new_with_mles(
            num_threads,
            max_num_variables,
            wit.iter()
                .map(|mle| Either::Left(mle.as_ref()))
                .collect_vec(),
        );
        let (proof, prover_state) = IOPProverState::prove(
            builder.to_virtual_polys(&[layer.exprs[0].clone()], challenges),
            transcript,
        );
        LayerProof {
            main: SumcheckLayerProof {
                proof,
                evals: prover_state.get_mle_flatten_final_evaluations(),
            },
            rotation: None,
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZerocheckLayerProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<<CpuBackend<E, PCS> as ProverBackend>::E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<CpuBackend<E, PCS>>,
        out_points: &[Point<<CpuBackend<E, PCS> as ProverBackend>::E>],
        challenges: &[<CpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> (
        LayerProof<<CpuBackend<E, PCS> as ProverBackend>::E>,
        Point<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) {
        assert_eq!(
            layer.out_eq_and_eval_exprs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            layer.out_eq_and_eval_exprs.len(),
            out_points.len(),
        );

        let (_, rotation_exprs) = &layer.rotation_exprs;
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
                    layer.rotation_cyclic_subgroup_size,
                    layer.rotation_cyclic_group_log2,
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
            layer.exprs.len() + rotation_exprs.len() * ROTATION_OPENING_COUNT,
            transcript,
        )
        .into_iter()
        .map(|r| Expression::Constant(Either::Right(r)))
        .collect_vec();

        let span = entered_span!("gen_expr", profiling_4 = true);
        let zero_check_exprs =
            extend_exprs_with_rotation(layer, &alpha_pows, layer.n_witin as WitnessId);
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

        let all_witins = wit
            .iter()
            .map(|mle| Either::Left(mle.as_ref()))
            .chain(eqs.iter_mut().map(Either::Right))
            .collect_vec();
        assert_eq!(
            all_witins.len(),
            layer.n_witin + layer.n_structural_witin + layer.n_fixed
        );
        let builder =
            VirtualPolynomialsBuilder::new_with_mles(num_threads, max_num_variables, all_witins);

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
}

/// This is to prove the following n rotation arguments:
/// For the i-th argument, we check rotated(rotation_expr[i].0) == rotation_expr[i].1
/// This is proved through the following arguments:
///     0 = \sum_{b = 0}^{N - 1} sel(b) * \sum_i alpha^i * (rotated_rotation_expr[i].0(b) - rotation_expr[i].1(b))
/// With the randomness rx, we check: (currently we only support cycle with length 32)
///     rotated_rotation_expr[i].0(rx) == (1 - rx_4) * rotation_expr[i].1(0, rx_0, rx_1, ..., rx_3, rx_5, ...)
///                                     + rx_4 * rotation_expr[i].1(1, rx_0, 1 - rx_1, ..., rx_3, rx_5, ...)
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_rotation<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    num_threads: usize,
    max_num_variables: usize,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    wit: &LayerWitness<CpuBackend<E, PCS>>,
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
                    &wit[*source_wit_id as usize],
                    rotation_cyclic_group_log2,
                ),
                _ => unimplemented!("unimplemented rotation"),
            })
            .chain(rayon::iter::once(rotation_selector(
                &bh,
                &eq,
                rotation_cyclic_subgroup_size,
                rotation_cyclic_group_log2,
                wit[0].evaluations().len(), // Take first mle just to retrieve total length
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
                        Either::Left(wit[*wit_id as usize].as_ref()),
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
                    wit[*source_wit_id as usize].evaluate(&left_point)
                }
                _ => unreachable!(),
            };
            let right_eval =
                bh.get_rotation_right_eval_from_left(*rotated_eval, left_eval, &origin_point);
            #[cfg(debug_assertions)]
            {
                use multilinear_extensions::Expression;

                let expected_right_eval = match rotated_expr {
                    Expression::WitIn(source_wit_id) => {
                        wit[*source_wit_id as usize].evaluate(&right_point)
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
