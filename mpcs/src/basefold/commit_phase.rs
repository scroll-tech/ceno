use std::collections::HashSet;

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitPhaseProof, BasefoldSpec, MerkleTree, MerkleTreeExt},
};
use crate::{
    Point,
    util::{
        codeword_fold_with_challenge,
        hash::write_digest_to_transcript,
        merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
        pop_front_while, split_by_sizes,
    },
};
use ff_ext::{ExtensionField, PoseidonField};
use itertools::{Either, Itertools};
use multilinear_extensions::{
    Expression, mle::ArcMultilinearExtension, virtual_polys::VirtualPolynomialsBuilder,
};
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
use std::collections::VecDeque;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::{AdditiveVec, merge_sumcheck_prover_state, optimal_sumcheck_threads},
};
use transcript::{Challenge, Transcript};

use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator},
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use super::structure::BasefoldCommitmentWithWitness;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    fixed_comms: Option<&BasefoldCommitmentWithWitness<E>>,
    witin_commitment_with_witness: &MerkleTree<E::BaseField>,
    witin_polys_and_meta: Vec<(
        &Point<E>,
        (usize, &Vec<ArcMultilinearExtension<'static, E>>),
    )>,
    transcript: &mut impl Transcript<E>,
    max_num_vars: usize,
    num_rounds: usize,
    circuit_num_polys: &[(usize, usize)],
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

    // concat witin mle with fixed mle under same circuit index
    let witin_concat_with_fixed_polys: Vec<Vec<ArcMultilinearExtension<E>>> = witin_polys_and_meta
        .iter()
        .map(|(_, (circuit_index, witin_polys))| {
            let fixed_iter = fixed_comms
                .and_then(|fixed_comms| fixed_comms.polys.get(circuit_index))
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
    let fixed_codeword = fixed_comms
        .map(|fixed_comms| mmcs.get_matrices(&fixed_comms.codeword))
        .unwrap_or_default();

    let batch_codeword_span = entered_span!("batch_codeword");
    // we random linear combination of rmm under same circuit into single codeword, as they shared same height
    let batched_codewords: Vec<DenseMatrix<E>> = witins_codeword
        .iter()
        .zip_eq(&batch_coeffs_splitted)
        .zip_eq(&witin_polys_and_meta)
        .map(
            |((witin_codewords, batch_coeffs), (_, (circuit_index, _)))| {
                let (expected_witins_num_poly, expected_fixed_num_poly) =
                    circuit_num_polys[*circuit_index];
                // batch_coeffs concat witin follow by fixed, where fixed is optional
                let witin_fixed_concated_codeword: Vec<(_, usize)> =
                    std::iter::once((witin_codewords, expected_witins_num_poly))
                        .chain(
                            fixed_comms
                                .and_then(|fixed_comms| {
                                    fixed_comms.circuit_codeword_index.get(circuit_index)
                                })
                                .and_then(|idx| {
                                    fixed_codeword
                                        .get(*idx)
                                        .map(|rmm| (rmm, expected_fixed_num_poly))
                                }),
                        )
                        .collect_vec();
                // final poly size is 2 * height because we commit left: poly[j] and right: poly[j + ni] under same mk path (due to bit-reverse)
                let size = witin_fixed_concated_codeword[0].0.height() * 2;
                RowMajorMatrix::new(
                    (0..size)
                        .into_par_iter()
                        .map(|j| {
                            witin_fixed_concated_codeword
                                .iter()
                                .scan(0, |start_index, (rmm, num_polys)| {
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
                        .collect::<Vec<_>>(),
                    2,
                )
            },
        )
        .collect_vec();
    assert!(
        [witin_polys_and_meta.len(), batched_codewords.len(),]
            .iter()
            .all_equal()
    );
    // sorted batch codewords by height in descending order
    let mut batched_codewords = VecDeque::from(
        batched_codewords
            .into_iter()
            .sorted_by_key(|codeword| std::cmp::Reverse(codeword.height()))
            .collect_vec(),
    );
    exit_span!(batch_codeword_span);

    let batched_evals = entered_span!("batched_evals");
    let mut initial_rlc_evals: Vec<MultilinearExtension<E>> = witin_concat_with_fixed_polys
        .par_iter()
        .zip_eq(batch_coeffs_splitted.par_iter())
        .map(|(witin_fixed_mle, batch_coeffs)| {
            assert_eq!(witin_fixed_mle.len(), batch_coeffs.len());
            let num_vars = witin_fixed_mle[0].num_vars();
            let mle_base_vec = witin_fixed_mle
                .iter()
                .map(|mle| mle.get_base_field_vec())
                .collect_vec();
            let running_evals: MultilinearExtension<_> =
                MultilinearExtension::from_evaluation_vec_smart(
                    num_vars,
                    (0..witin_fixed_mle[0].evaluations().len())
                        .into_par_iter()
                        .map(|j| {
                            dot_product(
                                batch_coeffs.iter().copied(),
                                mle_base_vec.iter().map(|mle| mle[j]),
                            )
                        })
                        .collect::<Vec<E>>(),
                );
            running_evals
        })
        .collect::<Vec<_>>();
    exit_span!(batched_evals);
    exit_span!(prepare_span);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_span = entered_span!("Basefold::build eq");
    let mut eq: Vec<MultilinearExtension<E>> = witin_polys_and_meta
        .par_iter()
        .map(|(point, _)| build_eq_x_r_vec(point).into_mle())
        .collect::<Vec<_>>();
    exit_span!(build_eq_span);

    let num_threads = optimal_sumcheck_threads(max_num_vars);
    let log2_num_threads = log2_strict_usize(num_threads);

    let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, max_num_vars);
    let eq_expr = eq
        .iter_mut()
        .map(|eq| expr_builder.lift(Either::Right(eq)))
        .collect_vec();
    let initial_rlc_evals_expr = initial_rlc_evals
        .iter_mut()
        .map(|initial_rlc_evals| expr_builder.lift(Either::Right(initial_rlc_evals)))
        .collect_vec();
    let polys = expr_builder.to_virtual_polys(
        // sumcheck formula: \sum_i \sum_b eq[point_i; b_i] * running_eval_i[b_i], |b_i| <= b and aligned on suffix
        &[eq_expr
            .into_iter()
            .zip(initial_rlc_evals_expr.clone())
            .map(|(eq, initial_rlc_evals)| eq * initial_rlc_evals)
            .sum::<Expression<E>>()],
        &[],
    );

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
    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut commits = Vec::with_capacity(num_rounds - 1);

    let mut challenge = None;
    let sumcheck_phase1 = entered_span!("sumcheck_phase1");
    let phase1_rounds = num_rounds.min(max_num_vars - log2_num_threads);
    println!("[ceno] phase1_rounds: {}", phase1_rounds);

    for i in 0..phase1_rounds {
        challenge = basefold_one_round::<E, Spec>(
            pp,
            &mut prover_states,
            challenge,
            &mut sumcheck_messages,
            &mut batched_codewords,
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
            &mut batched_codewords,
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
    // skip even index which is eq evaluations
    let final_message_indexes = initial_rlc_evals_expr
        .iter()
        .map(|expr| match expr {
            Expression::WitIn(index) => *index as usize,
            _ => unreachable!(),
        })
        .collect::<HashSet<usize>>();
    let final_message = final_message
        .into_iter()
        .enumerate()
        .filter(|(i, _)| final_message_indexes.contains(i))
        .map(|(_, m)| m)
        .collect_vec();

    if cfg!(feature = "sanity-check") {
        assert!(final_message.iter().map(|m| m.len()).all_equal());
        let final_message_agg: Vec<E> = (0..final_message[0].len())
            .map(|j| final_message.iter().map(|row| row[j]).sum())
            .collect_vec();
        // last round running oracle should be exactly the encoding of the folded polynomial.
        let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode_slow_ext(
            p3::matrix::dense::DenseMatrix::new(final_message_agg, 1),
        );
        assert_eq!(
            basecode.values,
            mmcs_ext.get_matrices(trees.last().unwrap())[0].values
        );
        // remove last tree/commmitment which is only for debug purpose
        let _ = (trees.pop(), commits.pop());
    }
    transcript.append_field_element_exts_iter(final_message.iter().flatten());
    (
        trees,
        BasefoldCommitPhaseProof {
            sumcheck_messages,
            commits,
            final_message,
        },
    )
}



#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn batch_commit_phase_prepare<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    fixed_comms: Option<&BasefoldCommitmentWithWitness<E>>,
    witin_commitment_with_witness: &MerkleTree<E::BaseField>,
    witin_polys_and_meta: Vec<(
        &Point<E>,
        (usize, &Vec<ArcMultilinearExtension<'static, E>>),
    )>,
    transcript: &mut impl Transcript<E>,
    max_num_vars: usize,
    num_rounds: usize,
    circuit_num_polys: &[(usize, usize)],
) -> (Vec<usize>, Vec<E>, VecDeque<DenseMatrix<E>>)
where
    E::BaseField: Serialize + DeserializeOwned,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    let prepare_span = entered_span!("Prepare");

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();
    let mut trees: Vec<MerkleTreeExt<E>> = Vec::with_capacity(max_num_vars);

    // concat witin mle with fixed mle under same circuit index
    let witin_concat_with_fixed_polys: Vec<Vec<ArcMultilinearExtension<E>>> = witin_polys_and_meta
        .iter()
        .map(|(_, (circuit_index, witin_polys))| {
            let fixed_iter = fixed_comms
                .and_then(|fixed_comms| fixed_comms.polys.get(circuit_index))
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
    let fixed_codeword = fixed_comms
        .map(|fixed_comms| mmcs.get_matrices(&fixed_comms.codeword))
        .unwrap_or_default();

    let batch_codeword_span = entered_span!("batch_codeword");
    // we random linear combination of rmm under same circuit into single codeword, as they shared same height
    let batched_codewords: Vec<DenseMatrix<E>> = witins_codeword
        .iter()
        .zip_eq(&batch_coeffs_splitted)
        .zip_eq(&witin_polys_and_meta)
        .map(
            |((witin_codewords, batch_coeffs), (_, (circuit_index, _)))| {
                let (expected_witins_num_poly, expected_fixed_num_poly) =
                    circuit_num_polys[*circuit_index];
                // batch_coeffs concat witin follow by fixed, where fixed is optional
                let witin_fixed_concated_codeword: Vec<(_, usize)> =
                    std::iter::once((witin_codewords, expected_witins_num_poly))
                        .chain(
                            fixed_comms
                                .and_then(|fixed_comms| {
                                    fixed_comms.circuit_codeword_index.get(circuit_index)
                                })
                                .and_then(|idx| {
                                    fixed_codeword
                                        .get(*idx)
                                        .map(|rmm| (rmm, expected_fixed_num_poly))
                                }),
                        )
                        .collect_vec();
                // final poly size is 2 * height because we commit left: poly[j] and right: poly[j + ni] under same mk path (due to bit-reverse)
                let size = witin_fixed_concated_codeword[0].0.height() * 2;
                RowMajorMatrix::new(
                    (0..size)
                        .into_par_iter()
                        .map(|j| {
                            witin_fixed_concated_codeword
                                .iter()
                                .scan(0, |start_index, (rmm, num_polys)| {
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
                        .collect::<Vec<_>>(),
                    2,
                )
            },
        )
        .collect_vec();
    assert!(
        [witin_polys_and_meta.len(), batched_codewords.len(),]
            .iter()
            .all_equal()
    );

    // sorted batch codewords by height in descending order
    let batched_codewords = VecDeque::from(
        batched_codewords
            .into_iter()
            .sorted_by_key(|codeword| std::cmp::Reverse(codeword.height()))
            .collect_vec(),
    );
    exit_span!(batch_codeword_span);

    exit_span!(prepare_span);

    // witins_codeword, fixed_codeword, 
    (batch_group_size, batch_coeffs.clone(), batched_codewords)
}

/// basefold fri round to fold codewords
#[allow(clippy::too_many_arguments)]
pub(crate) fn basefold_fri_round<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    codewords: &mut VecDeque<RowMajorMatrix<E>>,
    trees: &mut Vec<MerkleTreeExt<E>>,
    commits: &mut Vec<<Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment>,
    mmcs_ext: &ExtensionMmcs<
        E::BaseField,
        E,
        <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
    >,
    challenge: E,
    is_last_round: bool,
    transcript: &mut impl Transcript<E>,
) where
    E::BaseField: Serialize + DeserializeOwned,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    let running_codeword_opt = trees
        .last()
        .and_then(|mktree| mmcs_ext.get_matrices(mktree).pop())
        .map(|m| m.as_view());
    let target_len = running_codeword_opt
        .map(|running_codeword| running_codeword.values.len())
        .unwrap_or_else(|| {
            codewords
                .iter()
                .map(|v| v.values.len())
                .max()
                .expect("empty codeword")
        });
    let next_level_target_len = target_len >> 1;
    let level = log2_strict_usize(target_len) - 1;
    let folding_coeffs =
        <Spec::EncodingScheme as EncodingScheme<E>>::prover_folding_coeffs_level(pp, level);
    let inv_2 = E::BaseField::from_u64(2).inverse();
    debug_assert_eq!(folding_coeffs.len(), 1 << level);

    // take codewords match with target length then fold
    let codewords_matched =
        pop_front_while(codewords, |codeword| codeword.values.len() == target_len);
    // take codewords match next target length in preparation of being committed together
    let codewords_next_level_matched = pop_front_while(codewords, |codeword| {
        codeword.values.len() == next_level_target_len
    });

    // optimize for single codeword match
    let folded_codeword = if (usize::from(running_codeword_opt.is_some()) + codewords_matched.len())
        == 1
        && codewords_next_level_matched.is_empty()
    {
        println!("[ceno] single codeword match");
        RowMajorMatrix::new(
            running_codeword_opt
                .or_else(|| codewords_matched.first().map(|m| m.as_view()))
                .unwrap()
                .values
                .par_chunks_exact(2)
                .zip(folding_coeffs)
                .map(|(ys, coeff)| codeword_fold_with_challenge(ys, challenge, *coeff, inv_2))
                .collect::<Vec<_>>(),
            2,
        )
    } else {
        println!("[ceno] multiple codewords match");
        // aggregate codeword with same length
        let codeword_to_fold = (0..target_len)
            .into_par_iter()
            .map(|index| {
                running_codeword_opt
                    .into_iter()
                    .chain(codewords_matched.iter().map(|m| m.as_view()))
                    .map(|codeword| codeword.values[index])
                    .sum::<E>()
            })
            .collect::<Vec<E>>();

        RowMajorMatrix::new(
            (0..target_len)
                .into_par_iter()
                .step_by(2)
                .map(|index| {
                    let coeff = &folding_coeffs[index >> 1];

                    // 1st part folded with challenge then sum
                    let cur_same_pos_sum = codeword_fold_with_challenge(
                        &codeword_to_fold[index..index + 2],
                        challenge,
                        *coeff,
                        inv_2,
                    );
                    // 2nd part: retrieve respective index then sum
                    let next_same_pos_sum = codewords_next_level_matched
                        .iter()
                        .map(|codeword| codeword.values[index >> 1])
                        .sum::<E>();
                    cur_same_pos_sum + next_same_pos_sum
                })
                .collect::<Vec<_>>(),
            2,
        )
    };

    if cfg!(feature = "sanity-check") && is_last_round {
        let (commitment, merkle_tree) = mmcs_ext.commit_matrix(folded_codeword.clone());
        commits.push(commitment);
        trees.push(merkle_tree);
    }

    // skip last round commitment as verifer need to derive encode(final_message) = final_codeword itself
    if !is_last_round {
        let (commitment, merkle_tree) = mmcs_ext.commit_matrix(folded_codeword);
        write_digest_to_transcript(&commitment, transcript);
        commits.push(commitment);
        trees.push(merkle_tree);
    }
}

// do sumcheck interleaving with FRI step
#[allow(clippy::too_many_arguments)]
fn basefold_one_round<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    prover_states: &mut Vec<IOPProverState<'_, E>>,
    challenge: Option<Challenge<E>>,
    sumcheck_messages: &mut Vec<IOPProverMessage<E>>,
    codewords: &mut VecDeque<RowMajorMatrix<E>>,
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
    // 1. sumcheck part
    let sumcheck_round_span = entered_span!("basefold::sumcheck_one_round");
    let prover_msgs = prover_states
        .par_iter_mut()
        .map(|prover_state| IOPProverState::prove_round_and_update_state(prover_state, &challenge))
        .collect::<Vec<_>>();

    // for each round, we must collect #SIZE prover message
    let evaluations: AdditiveVec<E> =
        prover_msgs
            .into_iter()
            .fold(AdditiveVec::new(3), |mut acc, prover_msg| {
                acc += AdditiveVec(prover_msg.evaluations);
                acc
            });
    transcript.append_field_element_exts(&evaluations.0);
    sumcheck_messages.push(IOPProverMessage {
        evaluations: evaluations.0,
    });
    exit_span!(sumcheck_round_span);

    let next_challenge = transcript.sample_and_append_challenge(b"commit round");

    // 2. fri part
    let fri_round_span = entered_span!("basefold::fri_one_round");
    basefold_fri_round::<E, Spec>(
        pp,
        codewords,
        trees,
        commits,
        mmcs_ext,
        next_challenge.elements,
        is_last_round,
        transcript,
    );
    exit_span!(fri_round_span);

    Some(next_challenge)
}

// do sumcheck interleaving with FRI step
#[allow(clippy::too_many_arguments)]
fn basefold_one_round_fri_only<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    codewords: &mut VecDeque<RowMajorMatrix<E>>,
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
    let next_challenge = transcript.sample_and_append_challenge(b"commit round");

    // 2. fri part
    let fri_round_span = entered_span!("basefold::fri_one_round");
    basefold_fri_round::<E, Spec>(
        pp,
        codewords,
        trees,
        commits,
        mmcs_ext,
        next_challenge.elements,
        is_last_round,
        transcript,
    );
    exit_span!(fri_round_span);

    Some(next_challenge)
}
