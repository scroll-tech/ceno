use crate::{
    cpu::{CpuBackend, CpuProver},
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{
            Layer, LayerWitness,
            hal::{SumcheckLayerProver, ZerocheckLayerProver},
            zerocheck_layer::RotationPoints,
        },
    },
    selector::SelectorContext,
    utils::{rotation_next_base_mle, rotation_selector},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point},
    monomial::Term,
    virtual_poly::build_eq_x_r_vec,
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
        ROTATION_OPENING_COUNT,
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
        pub_io_evals: &[<CpuBackend<E, PCS> as ProverBackend>::E],
        challenges: &[<CpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
        selector_ctxs: &[SelectorContext],
    ) -> (
        LayerProof<<CpuBackend<E, PCS> as ProverBackend>::E>,
        Point<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) {
        assert_eq!(challenges.len(), 2);
        assert_eq!(
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
        );
        assert_eq!(
            layer.out_sel_and_eval_exprs.len(),
            selector_ctxs.len(),
            "selector_ctxs length {}",
            selector_ctxs.len()
        );

        let (_, raw_rotation_exprs) = &layer.rotation_exprs;
        let (rotation_proof, rotation_left, rotation_right, rotation_point) =
            if let Some(rotation_sumcheck_expression) =
                layer.rotation_sumcheck_expression_monomial_terms.as_ref()
            {
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
                    raw_rotation_exprs,
                    rotation_sumcheck_expression.clone(),
                    rt,
                    challenges,
                    transcript,
                );
                (Some(proof), Some(left), Some(right), Some(origin))
            } else {
                (None, None, None, None)
            };

        // 2th sumcheck: batch rotation with other constrains
        let span = entered_span!("build_out_points_eq", profiling_4 = true);
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(
                layer.exprs.len() + raw_rotation_exprs.len() * ROTATION_OPENING_COUNT,
                transcript,
            )
        )
        .collect_vec();

        // zero check eq || rotation eq
        let mut eqs = layer
            .out_sel_and_eval_exprs
            .par_iter()
            .zip(out_points.par_iter())
            .zip(selector_ctxs.par_iter())
            .filter_map(|(((sel_type, _), point), selector_ctx)| {
                sel_type.compute(point, selector_ctx)
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

        // `wit` := witin ++ fixed
        // we concat eq in between `wit` := witin ++ eqs ++ fixed
        let all_witins = wit
            .iter()
            .take(layer.n_witin)
            .map(|mle| Either::Left(mle.as_ref()))
            .chain(eqs.iter_mut().map(Either::Right))
            .chain(
                // fixed, start after `n_witin`
                wit.iter()
                    .skip(layer.n_witin + layer.n_structural_witin)
                    .map(|mle| Either::Left(mle.as_ref())),
            )
            .collect_vec();
        assert_eq!(
            all_witins.len(),
            layer.n_witin + layer.n_structural_witin + layer.n_fixed,
            "all_witins.len() {} != layer.n_witin {} + layer.n_structural_witin {} + layer.n_fixed {}",
            all_witins.len(),
            layer.n_witin,
            layer.n_structural_witin,
            layer.n_fixed,
        );

        let builder =
            VirtualPolynomialsBuilder::new_with_mles(num_threads, max_num_variables, all_witins);

        let span = entered_span!("IOPProverState::prove", profiling_4 = true);
        let (proof, prover_state) = IOPProverState::prove(
            builder.to_virtual_polys_with_monomial_terms(
                layer
                    .main_sumcheck_expression_monomial_terms
                    .as_ref()
                    .unwrap(),
                pub_io_evals,
                &main_sumcheck_challenges,
            ),
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
    raw_rotation_exprs: &[(Expression<E>, Expression<E>)],
    rotation_sumcheck_expression: Vec<Term<Expression<E>, Expression<E>>>,
    rt: &Point<E>,
    global_challenges: &[E],
    transcript: &mut impl Transcript<E>,
) -> (SumcheckLayerProof<E>, RotationPoints<E>) {
    let span = entered_span!("rotate_witin_selector", profiling_4 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    // rotated_mles is non-deterministic input, rotated from existing witness polynomial
    // we will reduce it to zero check, and finally reduce to committed polynomial opening
    let (mut selector, mut rotated_mles) = {
        let eq = build_eq_x_r_vec(rt);
        let mut mles = raw_rotation_exprs
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
    let rotation_challenges = chain!(
        global_challenges.iter().copied(),
        get_challenge_pows(raw_rotation_exprs.len(), transcript)
    )
    .collect_vec();
    exit_span!(span);
    // TODO FIXME: we pick a random point from output point, does it sound?
    let builder = VirtualPolynomialsBuilder::new_with_mles(
        num_threads,
        max_num_variables,
        // mles format [rotation_mle1, target_mle1, rotation_mle2, target_mle2, ....., selector, eq]
        rotated_mles
            .iter_mut()
            .zip_eq(raw_rotation_exprs)
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

    let span = entered_span!("rotation IOPProverState::prove", profiling_4 = true);
    let (rotation_proof, prover_state) = IOPProverState::prove(
        builder.to_virtual_polys_with_monomial_terms(
            &rotation_sumcheck_expression,
            &[],
            &rotation_challenges,
        ),
        transcript,
    );
    exit_span!(span);
    let mut evals = prover_state.get_mle_flatten_final_evaluations();
    let origin_point = prover_state.collect_raw_challenges();
    // skip selector/eq as verifier can derive itself
    evals.truncate(raw_rotation_exprs.len() * 2);

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
        .zip_eq(raw_rotation_exprs.par_iter())
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
