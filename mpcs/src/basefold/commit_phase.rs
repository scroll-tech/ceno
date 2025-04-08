use std::{borrow::Cow, sync::Arc};

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec, MerkleTree, MerkleTreeExt},
};
use crate::{
    Point,
    util::{
        hash::write_digest_to_transcript,
        merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
        split_by_sizes,
    },
};
use ff_ext::{ExtensionField, PoseidonField};
use itertools::{Itertools, izip};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    field::{Field, PrimeCharacteristicRing, dot_product},
    matrix::{
        Matrix,
        dense::{DenseMatrix, RowMajorMatrix},
    },
    util::log2_strict_usize,
};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverState,
    util::{AdditiveVec, merge_sumcheck_prover_state, optimal_sumcheck_threads},
};
use transcript::{Challenge, Transcript};

use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{DenseMultilinearExtension, IntoMLE},
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
    virtual_polys::VirtualPolynomials,
};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice},
};

use super::structure::BasefoldCommitmentWithWitness;

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
pub fn batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    fixed_comms: &BasefoldCommitmentWithWitness<E>,
    witin_commitment_with_witness: &MerkleTree<E::BaseField>,
    witin_polys_and_meta: Vec<(
        &Point<E>,
        (usize, &Vec<ArcMultilinearExtension<'static, E>>),
    )>,
    transcript: &mut impl Transcript<E>,
    max_num_vars: usize,
    num_rounds: usize,
) -> (Vec<MerkleTreeExt<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    let prepare_span = entered_span!("Prepare");

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();
    let mut trees: Vec<MerkleTreeExt<E>> = Vec::with_capacity(max_num_vars);

    // TODO filter too small witness (and fixed, both with same size)
    // giving witin_polys: Vec<Vec<ArcMle>>
    //        witin_index_mapping: Vec<Option<usize>>
    //        fixed_polys: Vec<Vec<ArcMle>>
    // here generate the concat fixed_polys along with witin_polys
    // such that we take `fixed_polys` respective index from `witin_index_mapping`
    // here we need `witin_index_mapping` because not all witin mapping with respective fixed_polys
    let witin_concat_with_fixed_polys: Vec<Vec<ArcMultilinearExtension<E>>> = witin_polys_and_meta
        .iter()
        .map(|(_, (circuit_index, witin_polys))| {
            let fixed_iter = fixed_comms
                .polys
                .get(circuit_index)
                .into_iter()
                .flatten()
                .cloned();
            witin_polys.iter().cloned().chain(fixed_iter).collect()
        })
        .collect::<Vec<Vec<_>>>();
    let batch_group_size = witin_concat_with_fixed_polys
        .iter()
        .map(|v| v.len())
        .collect_vec();
    let total_num_polys = batch_group_size.iter().sum();

    let batch_coeffs =
        &transcript.sample_and_append_challenge_pows(total_num_polys, b"batch coeffs");
    // split batch coeffs to match with batch group for easier handling
    let batch_coeffs_splitted = split_by_sizes(batch_coeffs, &batch_group_size);

    // prepare
    // - codeword oracle => for FRI
    // - evals => for sumcheck
    let witins_codeword = mmcs.get_matrices(witin_commitment_with_witness);
    let fixed_codeword = mmcs.get_matrices(&fixed_comms.codeword);

    let batch_oracle = entered_span!("batch_oracle");
    let initial_rlc_oracle = witins_codeword
        .iter()
        .zip_eq(&batch_coeffs_splitted)
        .zip_eq(&witin_polys_and_meta)
        .map(
            |((witin_codewords, batch_coeffs), (_, (circuit_index, group)))| {
                let num_polys = group.len();
                // batch_coeffs concat witin follow by fixed, where fixed is optional
                let witin_and_fixed_codeword: Vec<&&DenseMatrix<E::BaseField, Vec<E::BaseField>>> =
                    std::iter::once(witin_codewords)
                        .chain(
                            fixed_comms
                                .circuit_codeword_index
                                .get(circuit_index)
                                .and_then(|idx| fixed_codeword.get(*idx)),
                        )
                        .collect_vec();
                // final poly size is 2 * height because we commit left: poly[j] and right: poly[j + ni] under same mk path (due to bit-reverse)
                let size = witin_and_fixed_codeword[0].height() * 2;
                (0..size)
                    .into_par_iter()
                    .map(|j| {
                        witin_and_fixed_codeword
                            .iter()
                            .scan(0, |start_index, rmm| {
                                let batch_coeffs = batch_coeffs
                                    [*start_index..*start_index + num_polys]
                                    .iter()
                                    .copied();
                                *start_index += num_polys;
                                Some(dot_product(
                                    batch_coeffs,
                                    rmm.values[j * num_polys..(j + 1) * num_polys]
                                        .iter()
                                        .copied(),
                                ))
                            })
                            .sum::<E>()
                    })
                    .collect::<Vec<_>>()
            },
        )
        .collect_vec();
    assert!(
        [witin_polys_and_meta.len(), initial_rlc_oracle.len(),]
            .iter()
            .all_equal()
    );
    let mut running_oracle = initial_rlc_oracle.iter().map(Cow::Borrowed).collect_vec();
    exit_span!(batch_oracle);

    let batched_bh_evals = entered_span!("batched_bh_evals");
    let initial_rlc_bh_evals: Vec<ArcMultilinearExtension<E>> = witin_concat_with_fixed_polys
        .par_iter()
        .zip_eq(batch_coeffs_splitted.par_iter())
        .map(|(witin_fixed_mle, batch_coeffs)| {
            let num_vars = witin_fixed_mle[0].num_vars();
            let Some((running_evals, _)): Option<(ArcMultilinearExtension<E>, E)> = izip!(
                witin_fixed_mle.iter().cloned(),
                batch_coeffs.iter().copied()
            )
            .reduce(|(poly_a, coeff_a), (poly_b, coeff_b)| {
                let next_poly = commutative_op_mle_pair!(|poly_a, poly_b| {
                    // TODO we can save a bit cost if first batch_coeffs is E::ONE so we can skip the first base * ext operation
                    Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
                        num_vars,
                        poly_a
                            .par_iter()
                            .zip(poly_b.par_iter())
                            .map(|(a, b)| coeff_a * *a + coeff_b * *b)
                            .collect(),
                    ))
                });
                (next_poly, E::ONE)
            }) else {
                unimplemented!()
            };
            running_evals
        })
        .collect::<Vec<_>>();
    exit_span!(batched_bh_evals);
    exit_span!(prepare_span);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_span = entered_span!("Basefold::build eq");
    let eq: Vec<ArcMultilinearExtension<E>> = witin_polys_and_meta
        .par_iter()
        .map(|(point, _)| build_eq_x_r_vec(point).into_mle().into())
        .collect::<Vec<_>>();
    exit_span!(build_eq_span);

    // FIXME: make num_thread dominated by thread
    let num_threads = optimal_sumcheck_threads(max_num_vars);
    let log2_num_threads = log2_strict_usize(num_threads);

    // sumcheck formula: \sum_i \sum_b eq[point_i; b_i] * running_eval_i[b_i], |b_i| <= b and aligned on suffix
    let mut polys = VirtualPolynomials::new(num_threads, max_num_vars);

    izip!(&eq, &initial_rlc_bh_evals)
        .for_each(|(eq, running_evals)| polys.add_mle_list(vec![&eq, &running_evals], E::ONE));

    let (batched_polys, poly_meta) = polys.get_batched_polys();

    let mut prover_states = batched_polys
        .into_iter()
        .enumerate()
        .map(|(thread_id, poly)| {
            IOPProverState::prover_init_with_extrapolation_aux(
                thread_id == 0, // set thread_id 0 to be main worker
                poly,
                vec![(vec![], vec![])],
                Some(log2_num_threads),
                Some(poly_meta.clone()),
            )
        })
        .collect::<Vec<_>>();

    let mut challenge = None;

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut commits = Vec::with_capacity(num_rounds - 1);

    let sumcheck_phase1 = entered_span!("sumcheck_phase1");
    let phase1_rounds = num_rounds.min(max_num_vars - log2_num_threads);
    for i in 0..phase1_rounds {
        challenge = basefold_one_round::<E, Spec>(
            pp,
            &mut prover_states,
            challenge,
            &mut sumcheck_messages,
            &mut running_oracle,
            transcript,
            &mut trees,
            &mut commits,
            &mmcs_ext,
            i == num_rounds - 1,
        );
    }
    exit_span!(sumcheck_phase1);

    if let Some(p) = challenge {
        prover_states
            .iter_mut()
            .for_each(|prover_state| prover_state.fix_var(p.elements));
    }

    // deal with log(#thread) basefold rounds
    let merge_sumcheck_prover_state_span = entered_span!("merge_sumcheck_prover_state");
    let poly = merge_sumcheck_prover_state(&prover_states);
    let mut prover_states = vec![IOPProverState::prover_init_with_extrapolation_aux(
        true,
        poly,
        vec![(vec![], vec![])],
        None,
        None,
    )];
    exit_span!(merge_sumcheck_prover_state_span);

    let mut challenge = None;

    let sumcheck_phase2 = entered_span!("sumcheck_phase2");
    let remaining_rounds = num_rounds.saturating_sub(max_num_vars - log2_num_threads);
    for i in 0..remaining_rounds {
        challenge = basefold_one_round::<E, Spec>(
            pp,
            &mut prover_states,
            challenge,
            &mut sumcheck_messages,
            &mut running_oracle,
            transcript,
            &mut trees,
            &mut commits,
            &mmcs_ext,
            i == remaining_rounds - 1,
        );
    }
    exit_span!(sumcheck_phase2);

    if let Some(p) = challenge {
        prover_states[0].fix_var(p.elements);
    }

    let final_message = prover_states[0].get_mle_final_evaluations();
    // skip first half which is eq evaluations
    let final_message = final_message
        .into_iter()
        .map(|mut msg| msg.split_off(msg.len() / 2))
        .collect_vec();

    if cfg!(feature = "sanity-check") {
        assert_eq!(final_message.len(), 1, "batching different num var");
        // If the prover is honest, in the last round, the running oracle
        // on the prover side should be exactly the encoding of the folded polynomial.
        let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode_slow_ext(
            p3::matrix::dense::DenseMatrix::new(final_message[0].clone(), 1),
        );
        assert_eq!(
            basecode.values,
            mmcs_ext.get_matrices(trees.last().unwrap())[0].values
        );
        // remove last tree/commmitment which is only for debug purpose
        let _ = (trees.pop(), commits.pop());
    }
    transcript.append_field_element_exts_iter(final_message.iter().flatten());
    (trees, BasefoldCommitPhaseProof {
        sumcheck_messages,
        commits,
        final_message,
    })
}

// // outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
// #[allow(clippy::too_many_arguments)]
// pub fn simple_batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
//     pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
//     point: &[Point<E>],
//     batch_coeffs: &[E],
//     comm: &BasefoldCommitmentWithWitness<E>,
//     transcript: &mut impl Transcript<E>,
//     num_vars: usize,
//     num_rounds: usize,
// ) -> (Vec<MerkleTreeExt<E>>, BasefoldCommitPhaseProof<E>)
// where
//     E::BaseField: Serialize + DeserializeOwned,
//     <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
//         IntoIterator<Item = E::BaseField> + PartialEq,
// {
//     assert_eq!(point.len(), num_vars);
//     assert_eq!(comm.num_polys, batch_coeffs.len());
//     let prepare_timer = start_timer!(|| "Prepare");

//     let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
//     let mmcs = poseidon2_merkle_tree::<E>();
//     let mut trees: Vec<MerkleTreeExt<E>> = Vec::with_capacity(num_vars);

//     let batch_codewords_timer = start_timer!(|| "Batch codewords");
//     let initial_oracle = mmcs.get_matrices(&comm.codeword)[0]
//         .values
//         .par_chunks(comm.num_polys)
//         .map(|row| dot_product(batch_coeffs.iter().copied(), row.iter().copied()))
//         .collect::<Vec<_>>();
//     exit_span!(batch_codewords_timer);

//     let Some((running_evals, _)): Option<(ArcMultilinearExtension<E>, E)> = izip!(
//         comm.polynomials_bh_evals.iter().cloned(),
//         batch_coeffs.iter().cloned()
//     )
//     .reduce(|(poly_a, coeff_a), (poly_b, coeff_b)| {
//         let next_poly = commutative_op_mle_pair!(|poly_a, poly_b| {
//             // TODO we can save a bit cost if first batch_coeffs is E::ONE so we can skip the first base * ext operation
//             Arc::new(DenseMultilinearExtension::from_evaluation_vec_smart(
//                 num_vars,
//                 poly_a
//                     .par_iter()
//                     .zip(poly_b.par_iter())
//                     .map(|(a, b)| coeff_a * *a + coeff_b * *b)
//                     .collect(),
//             ))
//         });
//         (next_poly, E::ONE)
//     }) else {
//         unimplemented!()
//     };
//     exit_span!(prepare_timer);

//     // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
//     let build_eq_timer = start_timer!(|| "Basefold::build eq");
//     let eq = build_eq_x_r_vec(point).into_mle().into();
//     exit_span!(build_eq_timer);

//     let num_threads = optimal_sumcheck_threads(num_vars);

//     let mut polys = VirtualPolynomials::new(num_threads, num_vars);
//     polys.add_mle_list(vec![&eq, &running_evals], E::ONE);
//     let batched_polys = polys.get_batched_polys();

//     let mut prover_states = batched_polys
//         .into_par_iter()
//         .map(|poly| {
//             IOPProverState::prover_init_with_extrapolation_aux(poly, vec![(vec![], vec![])])
//         })
//         .collect::<Vec<_>>();

//     let mut challenge = None;

//     let mut sumcheck_messages = Vec::with_capacity(num_rounds);
//     let mut roots = Vec::with_capacity(num_rounds - 1);

//     let sumcheck_phase1 = entered_span!("sumcheck_phase1");
//     for i in 0..num_rounds.min(num_vars - log2_strict_usize(num_threads)) {
//         challenge = basefold_one_round::<E, Spec>(
//             pp,
//             &mut prover_states,
//             challenge,
//             &mut sumcheck_messages,
//             &initial_oracle,
//             transcript,
//             &mut trees,
//             &mut roots,
//             &mmcs_ext,
//             i == num_rounds - 1,
//         );
//     }
//     exit_span!(sumcheck_phase1);

//     if let Some(p) = challenge {
//         prover_states
//             .iter_mut()
//             .for_each(|prover_state| prover_state.fix_var(p.elements));
//     }

//     // deal with log(#thread) basefold rounds
//     let merge_sumcheck_polys_span = entered_span!("merge_sumcheck_polys");
//     let poly = merge_sumcheck_polys(&prover_states);
//     let mut prover_states = vec![IOPProverState::prover_init_with_extrapolation_aux(
//         poly,
//         vec![(vec![], vec![])],
//     )];
//     exit_span!(merge_sumcheck_polys_span);

//     let mut challenge = None;

//     let sumcheck_phase2 = entered_span!("sumcheck_phase2");
//     for i in 0..num_rounds.saturating_sub(num_vars - log2_strict_usize(num_threads)) {
//         challenge = basefold_one_round::<E, Spec>(
//             pp,
//             &mut prover_states,
//             challenge,
//             &mut sumcheck_messages,
//             &initial_oracle,
//             transcript,
//             &mut trees,
//             &mut roots,
//             &mmcs_ext,
//             i == num_rounds.saturating_sub(num_vars - log2_strict_usize(num_threads)) - 1,
//         );
//     }
//     exit_span!(sumcheck_phase2);

//     if let Some(p) = challenge {
//         prover_states[0].fix_var(p.elements);
//     }

//     let mut final_message = prover_states[0].get_mle_final_evaluations();
//     // skip first half which is eq evaluations
//     let final_message = final_message.split_off(final_message.len() / 2);

//     if cfg!(feature = "sanity-check") {
//         // If the prover is honest, in the last round, the running oracle
//         // on the prover side should be exactly the encoding of the folded polynomial.
//         let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode_slow_ext(
//             p3::matrix::dense::DenseMatrix::new(final_message.clone(), 1),
//         );
//         assert_eq!(
//             basecode.values,
//             mmcs_ext.get_matrices(trees.last().unwrap())[0].values
//         );
//         // remove last tree/commmitment which is only for debug purpose
//         let _ = (trees.pop(), roots.pop());
//     }
//     transcript.append_field_element_exts(&final_message);
//     (trees, BasefoldCommitPhaseProof {
//         sumcheck_messages,
//         roots,
//         final_message,
//     })
// }

// TODO define it within codeword
pub(crate) fn basefold_one_round_by_interpolation_weights<
    E: ExtensionField,
    Spec: BasefoldSpec<E>,
>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    values: &mut [Cow<Vec<E>>],
    challenge: E,
) -> RowMajorMatrix<E> {
    let target_len = values.iter().map(|v| v.len()).max().unwrap();
    let level = log2_strict_usize(target_len) - 1;
    let folding_coeffs =
        <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs_level(pp, level);
    let inv_2 = E::BaseField::from_u64(2).inverse();

    debug_assert_eq!(folding_coeffs.len(), 1 << level);

    let next_level_target_len = target_len << 1;
    let res = values
        .iter_mut()
        .filter_map(|value| {
            // the target codeword need to be folded
            if value.len() == target_len {
                // assume values in bit_reverse_format
                // thus chunks(2) is equivalent to left, right traverse
                *value = Cow::Owned(
                    value
                        .par_chunks_exact(2)
                        .zip(folding_coeffs)
                        .map(|(ys, coeff)| {
                            let (left, right) = (ys[0], ys[1]);
                            // original (left, right) = (lo + hi*x, lo - hi*x), lo, hi are codeword, but after times x it's not codeword
                            // recover left & right codeword via (lo, hi) = ((left + right) / 2, (left - right) / 2x)
                            let (lo, hi) = ((left + right) * inv_2, (left - right) * *coeff); // e.g. coeff = (2 * dit_butterfly)^(-1) in rs code
                            // we do fold on folded = (1-r) * left_codeword + r * right_codeword, as it match perfectly with raw message in lagrange domain fixed variable
                            lo + (hi - lo) * challenge
                        })
                        .collect::<Vec<_>>(),
                );
                Some(value)
            // this is new codeword involve into commitment
            } else if value.len() == next_level_target_len {
                Some(value)
            } else {
                None
            }
        })
        .collect_vec();

    RowMajorMatrix::new(
        (0..res[0].len())
            .into_par_iter()
            .map(|j| res.iter().map(|row| row[j]).sum())
            .collect(),
        2,
    )
}

#[allow(clippy::too_many_arguments)]
fn basefold_one_round<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    prover_states: &mut Vec<IOPProverState<'_, E>>,
    challenge: Option<Challenge<E>>,
    sumcheck_messages: &mut Vec<Vec<E>>,
    running_oracle: &mut [Cow<Vec<E>>],
    transcript: &mut impl Transcript<E>,
    trees: &mut Vec<MerkleTreeExt<E>>,
    commits: &mut Vec<<Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment>,
    mmcs_ext: &ExtensionMmcs<
        E::BaseField,
        E,
        <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
    >,
    is_last_round: bool,
) -> Option<Challenge<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    let prove_round_and_update_state_span = entered_span!("prove_round_and_update_state");
    let prover_msgs = prover_states
        .par_iter_mut()
        .map(|prover_state| IOPProverState::prove_round_and_update_state(prover_state, &challenge))
        .collect::<Vec<_>>();
    exit_span!(prove_round_and_update_state_span);

    // for each round, we must collect #SIZE prover message
    let evaluations: AdditiveVec<E> =
        prover_msgs
            .into_iter()
            .fold(AdditiveVec::new(3), |mut acc, prover_msg| {
                acc += AdditiveVec(prover_msg.evaluations);
                acc
            });

    transcript.append_field_element_exts(&evaluations.0);
    sumcheck_messages.push(evaluations.0);

    let next_challenge = transcript.sample_and_append_challenge(b"commit round");

    let new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
        pp,
        running_oracle,
        next_challenge.elements,
    );

    if cfg!(feature = "sanity-check") && is_last_round {
        let (commitment, merkle_tree) = mmcs_ext.commit_matrix(new_running_oracle.clone());
        commits.push(commitment);
        trees.push(merkle_tree);
    }

    if !is_last_round {
        let (commitment, merkle_tree) = mmcs_ext.commit_matrix(new_running_oracle);
        write_digest_to_transcript(&commitment, transcript);
        commits.push(commitment);
        trees.push(merkle_tree);
    }

    Some(next_challenge)
}
