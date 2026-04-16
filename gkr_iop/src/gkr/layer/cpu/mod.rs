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
    Expression, mle::Point, monomial::Term, virtual_poly::build_eq_x_r_vec,
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
    selector::SelectorType,
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

        // Main sumcheck polynomial shape:
        //   Σ_g sel_g(x) * (Σ_j α_{2+offset(g,j)} * expr_{g,j}(x))
        // where selector groups `(sel_g, expr_{g,*})` come from `out_sel_and_eval_exprs`.
        let span = entered_span!("build_out_points_eq", profiling_4 = true);
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(layer.exprs.len(), transcript)
        )
        .collect_vec();

        // Build selector eq MLEs in parallel, then merge deterministically by structural wit id.
        let selector_eq_pairs = layer
            .out_sel_and_eval_exprs
            .par_iter()
            .zip(out_points.par_iter())
            .zip(selector_ctxs.par_iter())
            .filter_map(|(((sel_type, _), point), selector_ctx)| {
                let eq = sel_type.compute(point, selector_ctx)?;
                let selector_expr = match sel_type {
                    SelectorType::Whole(expr)
                    | SelectorType::Prefix(expr)
                    | SelectorType::OrderedSparse {
                        expression: expr, ..
                    }
                    | SelectorType::QuarkBinaryTreeLessThan(expr) => expr,
                    SelectorType::None => return None,
                };
                let Expression::StructuralWitIn(wit_id, _) = selector_expr else {
                    panic!("selector expression must be StructuralWitIn");
                };
                let wit_id = *wit_id as usize;
                assert!(
                    wit_id < layer.n_structural_witin,
                    "selector wit id out of range"
                );
                Some((wit_id, eq))
            })
            .collect::<Vec<_>>();

        let mut selector_eq_by_wit_id = vec![None; layer.n_structural_witin];
        for (wit_id, eq) in selector_eq_pairs {
            if selector_eq_by_wit_id[wit_id].is_none() {
                selector_eq_by_wit_id[wit_id] = Some(eq);
            }
        }
        exit_span!(span);

        // `wit` := witin ++ fixed ++ structural
        // selector structural witins are replaced by computed eq MLEs in-place by witness id.
        let base_wit_count = layer.n_witin + layer.n_fixed;
        let mut all_witins =
            Vec::with_capacity(layer.n_witin + layer.n_structural_witin + layer.n_fixed);
        all_witins.extend(
            wit.iter()
                .take(base_wit_count)
                .map(|mle| Either::Left(mle.as_ref())),
        );
        for (selector_eq, mle) in selector_eq_by_wit_id.iter_mut().zip(
            wit.iter()
                .skip(base_wit_count)
                .take(layer.n_structural_witin),
        ) {
            if let Some(eq) = selector_eq.as_mut() {
                all_witins.push(Either::Right(eq));
            } else {
                all_witins.push(Either::Left(mle.as_ref()));
            }
        }

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
pub fn prove_rotation<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
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
    // TODO: we pick a random point from output point, does it sound?
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
